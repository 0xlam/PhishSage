import re
import asyncio
from datetime import timedelta, timezone, datetime
from dateutil import parser

import aiodns
from phishsage.config.schemas import HeaderHeuristicConfig
from phishsage.models.results import HeaderHeuristicResult
from phishsage.utils import is_domain_match, earliest_received_date
from phishsage.config.loader import CACHE_TTL_MX, CACHE_TTL_SPAMHAUS


class HeaderHeuristics:

    def __init__(
        self,
        config: HeaderHeuristicConfig,
        whois_lookup=None,
        dns_resolver=None,
        cache=None,
    ):
        self.config = config
        self.whois_lookup = whois_lookup
        self.dns_resolver = dns_resolver
        self.cache = cache

    def auth_check(self, headers) -> HeaderHeuristicResult:
        auth_results = headers.auth_results
        if isinstance(auth_results, list):
            auth_results_text = "\n".join(str(x).strip() for x in auth_results if x)
        elif isinstance(auth_results, str):
            auth_results_text = auth_results.strip()
        else:
            auth_results_text = str(auth_results or "").strip()

        auth_results_text_lower = auth_results_text.lower()

        def extract_result(field):
            match = re.search(
                rf"{field}\s*=\s*([\w-]+)",
                auth_results_text_lower,
                re.IGNORECASE,
            )
            return match.group(1).lower() if match else None

        spf = extract_result("spf")
        dkim = extract_result("dkim")
        dmarc = extract_result("dmarc")

        result = {
            "spf": {"value": spf, "passed": spf == "pass" if spf is not None else None},
            "dkim": {
                "value": dkim,
                "passed": dkim == "pass" if dkim is not None else None,
            },
            "dmarc": {
                "value": dmarc,
                "passed": dmarc == "pass" if dmarc is not None else None,
            },
        }

        alerts = []

        if spf is None:
            alerts.append(
                {
                    "type": "SPF_MISSING",
                    "message": "SPF result missing from Authentication-Results header",
                }
            )
        elif spf != "pass":
            alerts.append(
                {"type": "SPF_FAIL", "message": f"SPF check failed (spf={spf})"}
            )

        if dkim is None:
            alerts.append(
                {
                    "type": "DKIM_MISSING",
                    "message": "DKIM result missing from Authentication-Results header",
                }
            )
        elif dkim != "pass":
            alerts.append(
                {"type": "DKIM_FAIL", "message": f"DKIM check failed (dkim={dkim})"}
            )

        if dmarc is None:
            alerts.append(
                {
                    "type": "DMARC_MISSING",
                    "message": "DMARC result missing from Authentication-Results header",
                }
            )
        elif dmarc != "pass":
            alerts.append(
                {"type": "DMARC_FAIL", "message": f"DMARC check failed (dmarc={dmarc})"}
            )

        return HeaderHeuristicResult(
            flags=bool(alerts),
            result=result,
            alerts=alerts,
            meta={"raw_header_present": bool(auth_results_text)},
        )

    def check_address_alignment(self, headers) -> HeaderHeuristicResult:
        alerts = []
        from_email = headers.from_email
        reply_to_email = headers.reply_to_email
        return_path_email = headers.return_path_email

        meta = {
            "from_email": from_email,
            "reply_to_email": reply_to_email,
            "return_path_email": return_path_email,
        }
        result = {"from_vs_reply": None, "from_vs_return": None}

        from_norm = from_email.lower() if from_email else None
        reply_norm = reply_to_email.lower() if reply_to_email else None
        return_norm = return_path_email.lower() if return_path_email else None

        if from_norm and reply_norm:
            aligned = from_norm == reply_norm
            result["from_vs_reply"] = aligned
            if not aligned:
                alerts.append(
                    {
                        "type": "FROM_REPLY_MISMATCH",
                        "message": f"From address ({from_email}) does not match Reply-To address ({reply_to_email})",
                    }
                )

        if from_norm and return_norm:
            aligned = from_norm == return_norm
            result["from_vs_return"] = aligned
            if not aligned:
                alerts.append(
                    {
                        "type": "FROM_RETURN_PATH_MISMATCH",
                        "message": f"From address ({from_email}) does not match Return-Path address ({return_path_email})",
                    }
                )

        return HeaderHeuristicResult(
            flags=bool(alerts), result=result, alerts=alerts, meta=meta
        )

    def check_message_id_domain(self, headers) -> HeaderHeuristicResult:
        alerts = []
        from_domain = headers.from_domain
        msgid_domain = headers.message_id_domain

        meta = {"from_domain": from_domain, "msgid_domain": msgid_domain}
        result = {"msgid_vs_from": None}

        if not from_domain or not msgid_domain:
            alerts.append(
                {
                    "type": "MISSING_MSGID_OR_FROM",
                    "message": "Missing From or Message-ID domain",
                }
            )
            return HeaderHeuristicResult(
                flags=True, result=result, alerts=alerts, meta=meta
            )

        match = from_domain.lower() == msgid_domain.lower()
        result["msgid_vs_from"] = match
        if not match:
            alerts.append(
                {
                    "type": "MSGID_DOMAIN_MISMATCH",
                    "message": f"Message-ID domain ({msgid_domain}) does not match From domain ({from_domain})",
                }
            )

        return HeaderHeuristicResult(
            flags=bool(alerts), result=result, alerts=alerts, meta=meta
        )

    def check_domain_mismatch(self, headers) -> HeaderHeuristicResult:
        alerts = []
        from_domain = headers.from_domain
        return_path_domain = headers.return_path_domain
        reply_to_domain = headers.reply_to_domain

        meta = {
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "reply_to_domain": reply_to_domain,
        }
        result = {"from_vs_return": None, "from_vs_reply": None}

        if from_domain and return_path_domain:
            match = is_domain_match(from_domain, return_path_domain)
            result["from_vs_return"] = match
            if not match:
                alerts.append(
                    {
                        "type": "FROM_RETURN_MISMATCH",
                        "message": f"From domain ({from_domain}) does not match Return-Path domain ({return_path_domain})",
                    }
                )

        if from_domain and reply_to_domain:
            match = is_domain_match(from_domain, reply_to_domain)
            result["from_vs_reply"] = match
            if not match:
                alerts.append(
                    {
                        "type": "FROM_REPLY_MISMATCH",
                        "message": f"From domain ({from_domain}) does not match Reply-To domain ({reply_to_domain})",
                    }
                )

        return HeaderHeuristicResult(
            flags=bool(alerts), result=result, alerts=alerts, meta=meta
        )

    def check_free_reply_to(self, headers) -> HeaderHeuristicResult:
        alerts = []
        from_domain = headers.from_domain
        reply_to_domain = headers.reply_to_domain
        return_path_domain = headers.return_path_domain

        meta = {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
        }
        result = {
            "from_is_free": False,
            "reply_to_is_free": False,
            "return_path_is_free": False,
        }

        free = self.config.FREE_EMAIL_DOMAINS

        if from_domain:
            result["from_is_free"] = from_domain.lower() in free
        if reply_to_domain:
            result["reply_to_is_free"] = reply_to_domain.lower() in free
        if return_path_domain:
            result["return_path_is_free"] = return_path_domain.lower() in free

        if not reply_to_domain and not return_path_domain:
            alerts.append(
                {
                    "type": "MISSING_REPLY_AND_RETURN_PATH",
                    "message": "Both Reply-To and Return-Path headers are missing",
                }
            )

        if (
            reply_to_domain
            and result["reply_to_is_free"]
            and not result["from_is_free"]
            and not result["return_path_is_free"]
        ):
            alerts.append(
                {
                    "type": "FREE_REPLY_TO_DOMAIN",
                    "message": f"Reply-To domain ({reply_to_domain}) is a free email provider while From and Return-Path are not",
                }
            )

        if (
            return_path_domain
            and result["return_path_is_free"]
            and not result["from_is_free"]
        ):
            alerts.append(
                {
                    "type": "FREE_RETURN_PATH_DOMAIN",
                    "message": f"Return-Path domain ({return_path_domain}) is a free email provider while From is not",
                }
            )

        return HeaderHeuristicResult(
            flags=bool(alerts), result=result, alerts=alerts, meta=meta
        )

    def check_date_vs_received(self, headers) -> HeaderHeuristicResult:
        alerts = []
        date_header = headers.date
        first_received_header = earliest_received_date(headers.received_chain)
        drift_minutes = self.config.DATE_RECEIVED_DRIFT_MINUTES

        meta = {
            "date_header": date_header,
            "first_received_header": first_received_header,
            "drift_minutes": drift_minutes,
        }
        result = {
            "email_date": None,
            "received_date": None,
            "drift_minutes": drift_minutes,
            "status": None,
        }

        try:
            email_date = parser.parse(date_header)
            result["email_date"] = email_date.isoformat()
        except Exception:
            alerts.append(
                {"type": "MALFORMED_DATE", "message": "Malformed Date header"}
            )
            result["status"] = "malformed"
            return HeaderHeuristicResult(
                flags=True, result=result, alerts=alerts, meta=meta
            )

        try:
            received_date = parser.parse(first_received_header)
            result["received_date"] = received_date.isoformat()
        except Exception:
            alerts.append(
                {
                    "type": "MALFORMED_RECEIVED",
                    "message": "Malformed first Received header",
                }
            )
            result["status"] = "malformed"
            return HeaderHeuristicResult(
                flags=True, result=result, alerts=alerts, meta=meta
            )

        email_date = (
            email_date.astimezone(timezone.utc)
            if email_date.tzinfo
            else email_date.replace(tzinfo=timezone.utc)
        )
        received_date = (
            received_date.astimezone(timezone.utc)
            if received_date.tzinfo
            else received_date.replace(tzinfo=timezone.utc)
        )

        drift = timedelta(minutes=drift_minutes)

        if email_date > received_date + drift:
            alerts.append(
                {
                    "type": "DATE_AFTER_RECEIVED",
                    "message": f"Date header ({email_date.isoformat()}) is after first Received ({received_date.isoformat()})",
                }
            )
            result["status"] = "after"
        elif email_date < received_date - drift:
            alerts.append(
                {
                    "type": "DATE_BEFORE_RECEIVED",
                    "message": f"Date header ({email_date.isoformat()}) is before first Received ({received_date.isoformat()})",
                }
            )
            result["status"] = "before"
        else:
            result["status"] = "ok"

        return HeaderHeuristicResult(
            flags=bool(alerts), result=result, alerts=alerts, meta=meta
        )

    async def _whois_domain(self, label: str, domain: str):
        entry = {"age_days": None, "expiry_days_left": None, "error": None}
        alerts = []
        meta = {"domain": domain}

        if not self.whois_lookup:
            entry["error"] = "whois_service_unavailable"
            return label, entry, alerts, meta

        try:
            w = await self.whois_lookup(domain)

            entry["age_days"] = w.age_days
            entry["expiry_days_left"] = w.expiry_days

            if w.age_days is not None and w.age_days < self.config.THRESHOLD_YOUNG:
                alerts.append(
                    {
                        "type": "YOUNG_DOMAIN",
                        "message": f"Domain {domain} appears newly registered — only {w.age_days} days old.",
                    }
                )

            if (
                w.expiry_days is not None
                and w.expiry_days <= self.config.THRESHOLD_EXPIRING
            ):
                alerts.append(
                    {
                        "type": "DOMAIN_EXPIRING_SOON",
                        "message": f"Domain {domain} is expiring soon — {w.expiry_days} days left.",
                    }
                )

        except Exception as e:
            err_msg = str(e).splitlines()[0] if str(e) else "Unknown WHOIS error"
            entry["error"] = err_msg
            alerts.append(
                {
                    "type": "WHOIS_ERROR",
                    "message": f"Unable to retrieve WHOIS data for {domain}: {err_msg}",
                }
            )

        return label, entry, alerts, meta

    async def domain_age_bulk(self, headers) -> dict:
        domains = {
            "from": headers.from_domain,
            "reply_to": headers.reply_to_domain,
            "return_path": headers.return_path_domain,
        }

        tasks = [
            self._whois_domain(label, domain)
            for label, domain in domains.items()
            if domain
        ]

        if not tasks:
            return {"flags": False, "result": {}, "alerts": [], "meta": {}}

        results = await asyncio.gather(*tasks)

        final_results = {}
        final_alerts = []
        final_meta = {}

        for label, entry, alerts, meta in results:
            final_results[label] = entry
            final_alerts.extend(alerts)
            final_meta[label] = meta

        return {
            "flags": bool(final_alerts),
            "result": final_results,
            "alerts": final_alerts,
            "meta": final_meta,
        }

    async def check_mx(self, headers) -> dict:
        domain = headers.from_domain
        meta = {"domain": domain}
        result = {"has_mx": False, "records": None, "error": None}
        alerts = []

        if not domain:
            result["error"] = "No domain provided"
            alerts.append(
                {"type": "MX_MISSING", "message": "No domain provided for MX check"}
            )
            return {"flags": True, "result": result, "alerts": alerts, "meta": meta}

        if not self.dns_resolver:
            result["error"] = "DNS resolver not available"
            alerts.append(
                {"type": "MX_MISSING", "message": "DNS resolver not injected"}
            )
            return {"flags": False, "result": result, "alerts": alerts, "meta": meta}

        key = f"mx:{domain}"
        if self.cache is not None:
            try:
                cached = self.cache.get(key)
                if cached is not None:
                    return cached
            except Exception:
                pass

        try:
            resp = await self.dns_resolver.query_dns(domain, "MX")
            mx_records = sorted(r.data.exchange.rstrip(".") for r in resp.answer)

            result["has_mx"] = bool(mx_records)
            result["records"] = mx_records

            if not mx_records:
                alerts.append(
                    {
                        "type": "MX_MISSING",
                        "message": f"Domain {domain} has no MX records.",
                    }
                )

        except aiodns.error.DNSError as e:
            code = e.args[0] if e.args else None
            message = e.args[1] if len(e.args) > 1 else str(e)
            result["error"] = message

            if code in ("ENOTFOUND", "ENODATA"):
                alerts.append(
                    {
                        "type": "MX_MISSING",
                        "message": f"Domain {domain} has no MX records or does not exist.",
                    }
                )
            else:
                alerts.append(
                    {
                        "type": "MX_ERROR",
                        "message": f"MX check error for {domain}: {message}",
                    }
                )

        except Exception as e:
            result["error"] = str(e)
            alerts.append(
                {
                    "type": "MX_ERROR",
                    "message": f"Unexpected MX check error for {domain}: {str(e)}",
                }
            )

        final = {
            "flags": bool(alerts),
            "result": result,
            "alerts": alerts,
            "meta": meta,
        }

        if self.cache is not None and not result.get("error"):
            try:
                self.cache.set(key, final, expire=CACHE_TTL_MX)
            except Exception:
                pass

        return final

    async def _check_spamhaus_dbl_lookup(self, label: str, domain: str) -> dict:
        entry = {"listed": False, "error": None}
        alerts = []
        meta = {"domain": domain, "query": f"{domain}.dbl.spamhaus.org"}

        query_domain = meta["query"]

        if not self.dns_resolver:
            entry["error"] = "DNS resolver not available"
            return label, entry, alerts, meta

        key = f"spamhaus:{domain}"

        if self.cache is not None:
            try:
                cached = self.cache.get(key)
                if cached is not None:
                    entry, alerts, meta = cached
                    return label, entry, alerts, meta
            except Exception:
                pass

        try:
            result = await self.dns_resolver.query_dns(query_domain, "A")
            if result.answer:
                for answer in result.answer:
                    if hasattr(answer, "host") and answer.host.startswith("127.0.1."):
                        entry["listed"] = True
                        alerts.append(
                            {
                                "type": "DOMAIN_BLACKLISTED",
                                "message": f"Domain {domain} is listed on Spamhaus DBL (IP: {answer.host})",
                            }
                        )
                        break
                    else:
                        entry["listed"] = False
            else:
                entry["listed"] = False

        except aiodns.error.DNSError as e:
            if e.args and e.args[0] == aiodns.error.ARES_ENOTFOUND:
                entry["listed"] = False
            else:
                entry["error"] = str(e)
                alerts.append(
                    {
                        "type": "SPAMHAUS_ERROR",
                        "message": f"Error checking Spamhaus for {domain}: {entry['error']}",
                    }
                )

        final = (entry, alerts, meta)

        if self.cache is not None and not entry.get("error"):
            try:
                self.cache.set(key, final, expire=CACHE_TTL_SPAMHAUS)
            except Exception:
                pass

        return label, entry, alerts, meta

    async def check_spamhaus(self, headers) -> dict:
        """
        Run Spamhaus DBL lookup for multiple domains.
        """

        domains = {
            "from": headers.from_domain,
            "reply_to": headers.reply_to_domain,
            "return_path": headers.return_path_domain,
        }

        tasks = [
            self._check_spamhaus_dbl_lookup(label, domain)
            for label, domain in domains.items()
            if domain
        ]

        if not tasks:
            return {"flags": False, "result": {}, "alerts": [], "meta": {}}

        results = await asyncio.gather(*tasks, return_exceptions=True)

        final_results = {}
        final_alerts = []
        final_meta = {}

        for label, entry, alerts, meta in results:
            final_results[label] = entry
            final_alerts.extend(alerts)
            final_meta[label] = meta

        return {
            "flags": bool(final_alerts),
            "result": final_results,
            "alerts": final_alerts,
            "meta": final_meta,
        }

    async def run_headers_heuristics(
        self, headers, enrich=None
    ) -> HeaderHeuristicResult:
        results = {}
        alerts = []

        auth_data = self.auth_check(headers)
        results["auth"] = auth_data.result
        alerts.extend(auth_data.alerts)

        alignment_data = self.check_address_alignment(headers)
        results["address_alignment"] = alignment_data.result
        alerts.extend(alignment_data.alerts)

        msgid_data = self.check_message_id_domain(headers)
        results["message_id"] = msgid_data.result
        alerts.extend(msgid_data.alerts)

        domain_data = self.check_domain_mismatch(headers)
        results["domain_consistency"] = domain_data.result
        alerts.extend(domain_data.alerts)

        free_data = self.check_free_reply_to(headers)
        alerts.extend(free_data.alerts)

        date_data = self.check_date_vs_received(headers)
        alerts.extend(date_data.alerts)

        enrich = enrich or []

        tasks = {}
        if "mx" in enrich:
            tasks["mx"] = self.check_mx(headers)
        if "spamhaus" in enrich:
            tasks["spamhaus"] = self.check_spamhaus(headers)
        if "domain_age" in enrich:
            tasks["domain_age"] = self.domain_age_bulk(headers)

        if tasks:
            results_data = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for name, data in zip(tasks.keys(), results_data):
                if isinstance(data, Exception):
                    alerts.append(
                        {"type": f"{name.upper()}_FAILED", "message": str(data)}
                    )
                    continue
                results[name] = data["result"]
                alerts.extend(data["alerts"])

        return HeaderHeuristicResult(
            flags=bool(alerts),
            result=results,
            alerts=alerts,
            meta={"mail_id": headers.mail_id},
        )
