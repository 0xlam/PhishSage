import re
import asyncio
from datetime import datetime, timedelta, timezone

import whois
import aiodns
from dateutil import parser
from phishsage.config.loader import (
    FREE_EMAIL_DOMAINS,
    DATE_RECEIVED_DRIFT_MINUTES,
    THRESHOLD_YOUNG,
    THRESHOLD_EXPIRING,
)
from phishsage.utils import is_domain_match, earliest_received_date


class HeaderHeuristics:

    def __init__(self):
        self._resolver = None

    async def _get_resolver(self):
        if self._resolver is None:
            self._resolver = aiodns.DNSResolver()
        return self._resolver


    def auth_check(self, headers) -> dict:
        """
        Parses SPF, DKIM, and DMARC results from Authentication-Results headers.
        """

        auth_results = headers.auth_results
        # Normalize input safely
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
            "spf": {
                "value": spf,
                "passed": spf == "pass" if spf is not None else None,
            },
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
                {
                    "type": "SPF_FAIL",
                    "message": f"SPF check failed (spf={spf})",
                }
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
                {
                    "type": "DKIM_FAIL",
                    "message": f"DKIM check failed (dkim={dkim})",
                }
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
                {
                    "type": "DMARC_FAIL",
                    "message": f"DMARC check failed (dmarc={dmarc})",
                }
            )

        flags = bool(alerts)

        meta = {
            "raw_header_present": bool(auth_results_text),
        }

        return {
            "flags": flags,
            "result": result,
            "alerts": alerts,
            "meta": meta,
        }

    def check_address_alignment(self, headers) -> dict:
        """
        Checks alignment between From, Reply-To, and Return-Path addresses.
        """

        alerts = []

        from_email = headers.from_email
        reply_to_email = headers.reply_to_email
        return_path_email = headers.reply_to_email

        meta = {
            "from_email": from_email,
            "reply_to_email": reply_to_email,
            "return_path_email": return_path_email,
        }

        result = {
            "from_vs_reply": None,
            "from_vs_return": None,
        }

        # Normalize
        from_norm = from_email.lower() if from_email else None
        reply_norm = reply_to_email.lower() if reply_to_email else None
        return_norm = return_path_email.lower() if return_path_email else None

        # From vs Reply-To
        if from_norm and reply_norm:
            aligned = from_norm == reply_norm
            result["from_vs_reply"] = aligned
            if not aligned:
                alerts.append(
                    {
                        "type": "FROM_REPLY_MISMATCH",
                        "message": (
                            f"From address ({from_email}) does not match "
                            f"Reply-To address ({reply_to_email})"
                        ),
                    }
                )

        # From vs Return-Path
        if from_norm and return_norm:
            aligned = from_norm == return_norm
            result["from_vs_return"] = aligned
            if not aligned:
                alerts.append(
                    {
                        "type": "FROM_RETURN_PATH_MISMATCH",
                        "message": (
                            f"From address ({from_email}) does not match "
                            f"Return-Path address ({return_path_email})"
                        ),
                    }
                )

        flags = bool(alerts)

        return {
            "flags": flags,
            "result": result,
            "alerts": alerts,
            "meta": meta,
        }

    def check_message_id_domain(self, headers) -> dict:
        """
        Checks if the Message-ID domain matches the From domain.
        """

        alerts = []

        from_domain = headers.from_domain
        msgid_domain = headers.message_id_domain

        meta = {
            "from_domain": from_domain,
            "msgid_domain": msgid_domain,
        }

        result = {
            "msgid_vs_from": None,  # True / False / None (if missing)
        }

        # Missing data
        if not from_domain or not msgid_domain:
            alerts.append(
                {
                    "type": "MISSING_MSGID_OR_FROM",
                    "message": "Missing From or Message-ID domain",
                }
            )
            flags = True
            return {
                "flags": flags,
                "result": result,
                "alerts": alerts,
                "meta": meta,
            }

        # Compare domains
        match = from_domain.lower() == msgid_domain.lower()
        result["msgid_vs_from"] = match

        if not match:
            alerts.append(
                {
                    "type": "MSGID_DOMAIN_MISMATCH",
                    "message": (
                        f"Message-ID domain ({msgid_domain}) does not match "
                        f"From domain ({from_domain})"
                    ),
                }
            )

        flags = bool(alerts)

        return {
            "flags": flags,
            "result": result,
            "alerts": alerts,
            "meta": meta,
        }

    def check_domain_mismatch(self, headers) -> dict:
        """
        Checks for mismatched domains between From, Return-Path, and optionally Reply-To.
        """

        alerts = []

        from_domain = headers.from_domain
        return_path_domain = headers.return_path_domain
        reply_to_domain = headers.reply_to_domain

        meta = {
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "reply_to_domain": reply_to_domain,
        }

        result = {
            "from_vs_return": None,
            "from_vs_reply": None,
        }

        # From vs Return-Path
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

        # From vs Reply-To
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

        flags = bool(alerts)

        return {
            "flags": flags,
            "result": result,
            "alerts": alerts,
            "meta": meta,
        }

    def check_free_reply_to(self, headers) -> dict:
        """
        Detects use of free email domains in From, Reply-To, and Return-Path.
        """

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

        if from_domain:
            result["from_is_free"] = from_domain.lower() in FREE_EMAIL_DOMAINS
        if reply_to_domain:
            result["reply_to_is_free"] = reply_to_domain.lower() in FREE_EMAIL_DOMAINS
        if return_path_domain:
            result["return_path_is_free"] = (
                return_path_domain.lower() in FREE_EMAIL_DOMAINS
            )

        # Missing routing headers
        if not reply_to_domain and not return_path_domain:
            alerts.append(
                {
                    "type": "MISSING_REPLY_AND_RETURN_PATH",
                    "message": "Both Reply-To and Return-Path headers are missing",
                }
            )

        # Reply-To analysis
        if reply_to_domain and result["reply_to_is_free"]:
            if not result["from_is_free"] and not result["return_path_is_free"]:
                alerts.append(
                    {
                        "type": "FREE_REPLY_TO_DOMAIN",
                        "message": (
                            f"Reply-To domain ({reply_to_domain}) is a free email provider "
                            f"while From and Return-Path are not"
                        ),
                    }
                )

        # Return-Path analysis
        if (
            return_path_domain
            and result["return_path_is_free"]
            and not result["from_is_free"]
        ):
            alerts.append(
                {
                    "type": "FREE_RETURN_PATH_DOMAIN",
                    "message": (
                        f"Return-Path domain ({return_path_domain}) is a free email provider "
                        f"while From is not"
                    ),
                }
            )

        flags = bool(alerts)

        return {
            "flags": flags,
            "result": result,
            "alerts": alerts,
            "meta": meta,
        }

    def check_date_vs_received(self, headers) -> dict:
        """
        Compares Date header with the first Received header.
        """
        alerts = []

        date_header = headers.date
        first_received_header = earliest_received_date(headers.received_chain)

        drift_minutes = DATE_RECEIVED_DRIFT_MINUTES

        meta = {
            "date_header": date_header,
            "first_received_header": first_received_header,
            "drift_minutes": drift_minutes,
        }
        result = {
            "email_date": None,
            "received_date": None,
            "drift_minutes": drift_minutes,
            "status": None,  # will be 'ok', 'before', 'after', or 'malformed'
        }

        # Parse headers
        try:
            email_date = parser.parse(date_header)
            result["email_date"] = email_date.isoformat()
        except Exception:
            alerts.append(
                {"type": "MALFORMED_DATE", "message": "Malformed Date header"}
            )
            result["status"] = "malformed"
            return {"flags": True, "result": result, "alerts": alerts, "meta": meta}

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
            return {"flags": True, "result": result, "alerts": alerts, "meta": meta}

        # Normalize to UTC
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

        flags = bool(alerts)
        return {"flags": flags, "result": result, "alerts": alerts, "meta": meta}

    async def _whois_lookup(self, label: str, domain: str):
        entry = {"age_days": None, "expiry_days_left": None, "error": None}
        alerts = []
        meta = {"domain": domain}

        now = datetime.now(timezone.utc)

        try:
            w = await asyncio.to_thread(whois.whois, domain)

            # Creation date
            created = (
                w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            )
            if isinstance(created, str):
                created = parser.parse(created)

            # Expiration date
            expires = (
                w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            )
            if isinstance(expires, str):
                expires = parser.parse(expires)

            # Normalize to UTC
            if created:
                created = (
                    created.replace(tzinfo=timezone.utc)
                    if created.tzinfo is None
                    else created.astimezone(timezone.utc)
                )
                entry["age_days"] = (now - created).days

            if expires:
                expires = (
                    expires.replace(tzinfo=timezone.utc)
                    if expires.tzinfo is None
                    else expires.astimezone(timezone.utc)
                )
                entry["expiry_days_left"] = (expires - now).days

            # Alerts
            if entry["age_days"] is not None and entry["age_days"] < THRESHOLD_YOUNG:
                alerts.append(
                    {
                        "type": "YOUNG_DOMAIN",
                        "message": f"Domain {domain} appears newly registered — only {entry['age_days']} days old.",
                    }
                )
            if (
                entry["expiry_days_left"] is not None
                and entry["expiry_days_left"] <= THRESHOLD_EXPIRING
            ):
                alerts.append(
                    {
                        "type": "DOMAIN_EXPIRING_SOON",
                        "message": f"Domain {domain} is expiring soon — {entry['expiry_days_left']} days left.",
                    }
                )

        except Exception as e:
            err_msg = str(e).splitlines()[0] if str(e) else "Unknown WHOIS error"
            entry["error"] = err_msg
            alerts.append(
                {
                    "type": "WHOIS_ERROR",
                    "message": f"⚠️ Unable to retrieve WHOIS data for {domain}: {err_msg}",
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
            self._whois_lookup(label, domain)
            for label, domain in domains.items() if domain
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
        """
        Check if a domain has valid MX records.
        """
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
   
        if self._resolver is None:
            self._resolver = aiodns.DNSResolver()

        try:
            resp = await self._resolver.query_dns(domain, "MX")

            mx_records = sorted(
                r.data.exchange.rstrip(".")
                for r in resp.answer
            )

            result["has_mx"] = bool(mx_records)
            result["records"] = mx_records

            if not mx_records:
                alerts.append(
                    {
                        "type": "MX_MISSING",
                        "message": f"Domain {domain} has no MX records; suspicious.",
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
                        "message": f"MX check error for domain {domain}: {message}",
                    }
                )

        except Exception as e:
            result["error"] = str(e)
            alerts.append(
                {
                    "type": "MX_ERROR",
                    "message": f"Unexpected MX check error for domain {domain}: {str(e)}",
                }
            )

        flags = bool(alerts)
        return {"flags": flags, "result": result, "alerts": alerts, "meta": meta}

    async def _check_spamhaus_dbl_lookup(self, label:str, domain: str) -> dict:
        entry = {"listed": False, "error": None}
        alerts = []
        meta = {
            "domain": domain,
            "query": f"{domain}.dbl.spamhaus.org",
        }

        query_domain = meta["query"]

        if self._resolver is None:
            self._resolver = aiodns.DNSResolver()

        try:
            result = await self._resolver.query_dns(query_domain, "A")

            if result.answer:
                entry["listed"] = True
                alerts.append(
                    {
                        "type": "DOMAIN_BLACKLISTED",
                        "message": f"Domain {domain} is listed on Spamhaus DBL",
                    }
                )
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

        tasks = [self._check_spamhaus_dbl_lookup(label, domain) 
                 for label, domain in domains.items()
                 if domain]

        
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
            "meta": final_meta
        }

    
    async def run_headers_heuristics(self, headers):
        """
        Runs all email header heuristics and aggregates results and alerts.
        """

        results = {}
        alerts = []

        # ---- Authentication ----
        auth_data = self.auth_check(headers)
        results["auth"] = auth_data["result"]
        alerts.extend(auth_data["alerts"])

        # ---- Address alignment ----
        address_alignment_data = self.check_address_alignment(headers)
        results["address_alignment"] = address_alignment_data
        alerts.extend(address_alignment_data["alerts"])

        # ---- Message-ID domain check ----
        msgid_data = self.check_message_id_domain(headers)
        results["message_id"] = msgid_data["result"]
        alerts.extend(msgid_data["alerts"])

        # ---- Domain consistency ----
        domain_consistency_data = self.check_domain_mismatch(headers)
        results["domain_consistency"] = domain_consistency_data
        alerts.extend(domain_consistency_data["alerts"])

        # ---- Free domain usage ----
        free_domain_alerts = self.check_free_reply_to(headers)
        alerts.extend(free_domain_alerts["alerts"])

        # ---- Date sanity ----
        date_alerts = self.check_date_vs_received(headers)
        alerts.extend(date_alerts["alerts"])
        
        tasks = [
            asyncio.create_task(self.check_mx(headers)),
            asyncio.create_task(self.check_spamhaus(headers)),
            asyncio.create_task(self.domain_age_bulk(headers)),
        ]

        mx_data, spamhaus_data, domain_age_data = await asyncio.gather(*tasks)


        # ---- MX----
        results["mx"] = mx_data["result"]
        alerts.extend(mx_data["alerts"])

        # ---- Spamhaus ----
        results["spamhaus"] = spamhaus_data["result"]
        alerts.extend(spamhaus_data["alerts"])

        # ---- Domain age ----
        results["domain_age"] = domain_age_data["result"]
        alerts.extend(domain_age_data["alerts"])

        return {
            "flags": bool(alerts),
            "results": results,
            "alerts": alerts,
            "meta": {"mail_id": headers.mail_id},
        }
