import math
import asyncio
import ipaddress
import traceback
from collections import Counter

from phishsage.models.results import LinkHeuristicResult
from phishsage.parsers import parse_url


def shannon_entropy(s):
    if not s:
        return 0.0
    prob = Counter(s).values()
    prob = [p / len(s) for p in prob]
    return -sum(p * math.log2(p) for p in prob)


class LinkHeuristics:

    def __init__(
        self,
        config,
        whois_lookup=None,
        vt_lookup=None,
        redirect_lookup=None,
        ssl_fetcher=None,
        enrich=None,
    ):

        self.config = config

        self.whois_lookup = whois_lookup
        self.vt_lookup = vt_lookup
        self.ssl_fetcher = ssl_fetcher
        self.redirect_lookup = redirect_lookup

        self.enrich = enrich or []

    async def analyze_certificate(self, parsed) -> LinkHeuristicResult:
        hostname = parsed.hostname

        if not hostname:
            return LinkHeuristicResult(
                name="certificate",
                flags=False,
                reasons=["missing_hostname"],
                meta={},
            )

        if not self.ssl_fetcher:
            return LinkHeuristicResult(
                name="certificate",
                flags=False,
                reasons=["missing_ssl_service"],
                meta={"hostname": hostname},
            )

        try:
            cert = await self.ssl_fetcher(hostname)

            flags = False
            reasons = []

            if cert.days_until_expiry < 0:
                flags = True
                reasons.append("expired_certificate")

            if 0 <= cert.days_since_issued <= self.config.CERT_RECENT_ISSUE_DAYS_THRESHOLD:
                flags = True
                reasons.append("recently_issued_certificate")

            return LinkHeuristicResult(
                name="certificate",
                flags=flags,
                reasons=reasons,
                meta={
                    "hostname": hostname,
                    "issuer": cert.issuer,
                    "subject": cert.subject,
                    "valid_from": cert.valid_from,
                    "valid_to": cert.valid_to,
                    "days_since_issued": cert.days_since_issued,
                    "days_until_expiry": cert.days_until_expiry,
                },
            )

        except Exception as e:
            return LinkHeuristicResult(
                name="certificate",
                flags=True,
                reasons=["certificate_check_failed"],
                meta={"hostname": hostname, "error": str(e)},
            )

    def domain_entropy(self, parsed) -> LinkHeuristicResult:
        sub = parsed.subdomain or ""
        dom = parsed.domain or ""

        sub_ent = shannon_entropy(sub)
        dom_ent = shannon_entropy(dom)

        flags = False
        reasons = []

        if len(sub) >= 8 and sub_ent >= self.config.ENTROPY_THRESHOLD:
            flags = True
            reasons.append("high_subdomain_entropy")

        if len(dom) >= 6 and dom_ent >= self.config.ENTROPY_THRESHOLD:
            flags = True
            reasons.append("high_domain_entropy")

        return LinkHeuristicResult(
            name="domain_entropy",
            flags=flags,
            reasons=reasons,
            meta={
                "subdomain_entropy": sub_ent,
                "domain_entropy": dom_ent,
            },
        )

    def has_suspicious_tld(self, parsed) -> LinkHeuristicResult:
        suffix = parsed.suffix

        if not suffix:
            return LinkHeuristicResult(
                name="suspicious_tld", flags=False, reasons=["missing_suffix"], meta={}
            )

        is_known_suspicious = suffix in self.config.SUSPICIOUS_TLDS
        is_punycode = suffix.startswith("xn--")
        is_non_ascii = not suffix.isascii()

        flags = is_known_suspicious or is_punycode or is_non_ascii

        reasons = []
        if is_known_suspicious:
            reasons.append("known_suspicious_tld")
        if is_punycode:
            reasons.append("punycode_tld")
        if is_non_ascii:
            reasons.append("non_ascii_tld")

        return LinkHeuristicResult(
            name="suspicious_tld",
            flags=flags,
            reasons=reasons,
            meta={"suffix": suffix},
        )

    def is_ip_url(self, parsed) -> LinkHeuristicResult:
        hostname = parsed.hostname

        if not hostname:
            return LinkHeuristicResult(
                name="ip_url", flags=True, reasons=["no_hostname"], meta={}
            )

        try:
            ip = ipaddress.ip_address(hostname)

            return LinkHeuristicResult(
                name="ip_url",
                flags=True,
                reasons=["ip_based_url"],
                meta={
                    "hostname": hostname,
                    "ip_version": ip.version,
                },
            )

        except ValueError:
            return LinkHeuristicResult(
                name="ip_url",
                flags=False,
                reasons=[],
                meta={"hostname": hostname},
            )

    def too_many_subdomains(self, parsed) -> LinkHeuristicResult:
        threshold = self.config.SUBDOMAIN_THRESHOLD

        sub = parsed.subdomain or ""

        if not sub:
            return LinkHeuristicResult(
                name="subdomains",
                flags=False,
                reasons=[],
                meta={"subdomain_count": 0},
            )

        parts = [p for p in sub.split(".") if p]

        def digit_heavy(label: str) -> bool:
            if not label:
                return True
            digit_ratio = sum(c.isdigit() for c in label) / len(label)
            return digit_ratio > 0.4

        suspicious = [
            p
            for p in parts
            if p.lower() not in self.config.TRIVIAL_SUBDOMAINS
            and len(p) > 2
            and not digit_heavy(p)
        ]

        flags = len(suspicious) >= threshold

        return LinkHeuristicResult(
            name="subdomains",
            flags=flags,
            reasons=["excessive_suspicious_subdomains"] if flags else [],
            meta={
                "subdomain": sub,
                "suspicious": suspicious,
                "threshold": threshold,
            },
        )

    def is_shortened_url(self, parsed) -> LinkHeuristicResult:
        domain = parsed.registered_domain

        if not domain:
            return LinkHeuristicResult(
                name="shortened_url", flags=False, reasons=["missing_domain"], meta={}
            )

        domain = domain.lower()

        match = next((s for s in self.config.SHORTENERS if s.lower() == domain), None)

        flags = match is not None

        return LinkHeuristicResult(
            name="shortened_url",
            flags=flags,
            reasons=["url_shortener"] if flags else [],
            meta={
                "domain": domain,
                "matched": match,
            },
        )

    def uses_abusable_platform(self, parsed) -> LinkHeuristicResult:
        domain = parsed.registered_domain

        if not domain:
            return LinkHeuristicResult(
                name="abusable_platform",
                flags=False,
                reasons=["missing_domain"],
                meta={},
            )

        domain = domain.lower()

        match = next(
            (
                p
                for p in self.config.ABUSABLE_PLATFORM_DOMAINS
                if domain == p or domain.endswith("." + p)
            ),
            None,
        )

        return LinkHeuristicResult(
            name="abusable_platform",
            flags=match is not None,
            reasons=["abusable_platform"] if match else [],
            meta={"matched": match},
        )

    def excessive_path_depth(self, parsed) -> LinkHeuristicResult:
        path = parsed.path or "/"
        depth = len([p for p in path.split("/") if p])

        flags = depth > self.config.MAX_PATH_DEPTH

        return LinkHeuristicResult(
            name="path_depth",
            flags=flags,
            reasons=["excessive_path_depth"] if flags else [],
            meta={
                "path": path,
                "depth": depth,
                "max": self.config.MAX_PATH_DEPTH,
            },
        )

    def is_numeric_domain(self, parsed) -> LinkHeuristicResult:
        label = parsed.domain

        if not label:
            return LinkHeuristicResult(
                name="numeric_domain",
                flags=False,
                reasons=["missing_domain_label"],
                meta={},
            )

        flags = label.isdigit()

        return LinkHeuristicResult(
            name="numeric_domain",
            flags=flags,
            reasons=["numeric_domain"] if flags else [],
            meta={"domain": label},
        )

    async def domain_age(self, parsed) -> LinkHeuristicResult:
        domain = parsed.registered_domain

        if not domain:
            return LinkHeuristicResult(
                name="domain_age",
                flags=False,
                reasons=["missing_registered_domain"],
                meta={
                    "registered_domain": None,
                },
            )

        if not self.whois_lookup:
            return LinkHeuristicResult(
                name="domain_age",
                flags=False,
                reasons=["missing_whois_service"],
                meta={
                    "registered_domain": domain,
                },
            )

        try:
            w = await self.whois_lookup(domain)

            flags = False
            reasons = []

            if (
                w.age_days is not None
                and w.age_days < self.config.THRESHOLD_YOUNG
            ):
                flags = True
                reasons.append("young_domain")

            if (
                w.expiry_days is not None
                and w.expiry_days <= self.config.THRESHOLD_EXPIRING
            ):
                flags = True
                reasons.append("domain_expiring_soon")

            return LinkHeuristicResult(
                name="domain_age",
                flags=flags,
                reasons=reasons,
                meta={
                    "registered_domain": domain,
                    "age_days": w.age_days,
                    "expiry_days": w.expiry_days,
                    "created_at": (
                        w.created_at.isoformat()
                        if w.created_at
                        else None
                    ),
                    "expires_at": (
                        w.expires_at.isoformat()
                        if w.expires_at
                        else None
                    ),
                    "registrar": w.registrar,
                    "young_threshold": self.config.THRESHOLD_YOUNG,
                    "expiry_threshold": self.config.THRESHOLD_EXPIRING,
                },
            )

        except Exception as e:
            return LinkHeuristicResult(
                name="domain_age",
                flags=True,
                reasons=["whois_lookup_failed"],
                meta={
                    "registered_domain": domain,
                    "error": str(e),
                },
            )

    async def scan_virustotal(self, parsed) -> LinkHeuristicResult:
        url = parsed.normalized

        if not self.vt_lookup:
            return LinkHeuristicResult(
                name="virustotal",
                flags=False,
                reasons=["missing_vt_service"],
                meta={},
            )

        try:
            vt = await self.vt_lookup(url)

            if vt.status != "ok":
                return LinkHeuristicResult(
                    name="virustotal",
                    flags=True,
                    reasons=["vt_error"],
                    meta={
                        "status": vt.status,
                        "resource": vt.resource,
                        "error": getattr(vt, "error", None),
                    },
                )

            stats = vt.stats

            flags = stats.malicious > 0 or stats.suspicious > 0
            reasons = []

            if stats.malicious > 0:
                reasons.append("vt_malicious")
            elif stats.suspicious > 0:
                reasons.append("vt_suspicious")

            return LinkHeuristicResult(
                name="virustotal",
                flags=flags,
                reasons=reasons,
                meta={
                    "status": vt.status,
                    "resource": vt.resource,
                    "stats": stats.__dict__,
                    "last_analysis_date": vt.last_analysis_date,
                    "first_submission_date": vt.first_submission_date,
                },
            )

        except Exception as e:
            return LinkHeuristicResult(
                name="virustotal",
                flags=True,
                reasons=["vt_failed"],
                meta={"error": str(e)},
            )

    async def resolve_redirect_chain(self, parsed) -> LinkHeuristicResult:
        if not self.redirect_lookup:                          
            return LinkHeuristicResult(
                name="redirect_chain",
                flags=False,
                reasons=["missing_redirect_service"],
                meta={},
            )

        url = parsed.normalized

        try:
            chain_result = await self.redirect_lookup(url)

            if chain_result.redirected and len(chain_result.chain) == 0:
                return LinkHeuristicResult(
                    name="redirect_chain",
                    flags=True,
                    reasons=["excessive_redirects"],
                    meta={
                        "original_url": url,
                        "redirect_count": chain_result.redirect_count,
                    },
                )

            if len(chain_result.chain) == 0:
                return LinkHeuristicResult(
                    name="redirect_chain",
                    flags=True,
                    reasons=["redirect_resolution_failed"],
                    meta={"original_url": url},
                )

            
            reasons = []
            redirect_count = len(chain_result.chain) - 1
            redirected = redirect_count > 0

            if redirected:
                reasons.append("has_redirect_chain")

            return LinkHeuristicResult(
                name="redirect_chain",
                flags=redirected,
                reasons=reasons,
                meta={
                    "original_url": url,
                    "redirect_chain": chain_result.chain,
                    "status_codes": chain_result.status_codes,
                    "final_url": chain_result.final_url,
                    "final_status": chain_result.final_status,
                    "redirect_count": redirect_count,
                    "redirected": redirected,
                },
            )

        except Exception as exc:
            return LinkHeuristicResult(
                name="redirect_chain",
                flags=True,
                reasons=["redirect_resolution_failed"],
                meta={"original_url": url, "error": str(exc)},
            )

    async def _analyze_single_url(self, url: str) -> dict:
        try:
            parsed = parse_url(url)

            heuristics = {
                "ip_based":             self.is_ip_url(parsed),
                "suspicious_tld":       self.has_suspicious_tld(parsed),
                "excessive_subdomains": self.too_many_subdomains(parsed),
                "shortened_url":        self.is_shortened_url(parsed),
                "numeric_domain":       self.is_numeric_domain(parsed),
                "excessive_path":       self.excessive_path_depth(parsed),
                "abusable_platform":    self.uses_abusable_platform(parsed),
                "domain_entropy":       self.domain_entropy(parsed),
            }

            enrich = self.enrich or []
            if "all" in enrich:
                enrich = ["virustotal", "domain_age", "certificate", "redirects"]

            tasks = {}
            if "virustotal" in enrich:
                tasks["virustotal"] = self.scan_virustotal(parsed)
            if "domain_age" in enrich:
                tasks["domain_age"] = self.domain_age(parsed)
            if "certificate" in enrich:
                tasks["certificate"] = self.analyze_certificate(parsed)
            if "redirects" in enrich:
                tasks["redirect_chain"] = self.resolve_redirect_chain(parsed)

            enrichment: dict = {}
            if tasks:
                results = await asyncio.gather(*tasks.values(), return_exceptions=True)
                for name, data in zip(tasks.keys(), results):
                    if isinstance(data, Exception):
                        data = LinkHeuristicResult(
                            name=name,
                            flags=True,
                            reasons=[f"{name}_failed"],
                            meta={"error": str(data)},
                        )
                    enrichment[name] = data

            # Aggregate flags across all LinkHeuristicResult objects
            all_results = list(heuristics.values()) + list(enrichment.values())
            aggregated_flags = sorted(
                {reason for r in all_results if r.flags for reason in r.reasons}
            )

            return {
                "url": url,
                "heuristics": {k: v.__dict__ for k, v in heuristics.items()},
                "enrichment": {k: v.__dict__ for k, v in enrichment.items()},
                "aggregated_flags": aggregated_flags,
            }

        except Exception as e:
            return {
                "url": url,
                "flags": True,
                "reasons": ["unhandled_exception"],
                "meta": {
                    "error": f"{type(e).__name__}: {str(e)}",
                    "traceback": traceback.format_exc(),
                },
            }


    async def run_link_heuristics(self, urls: list[str]) -> list[dict]:
        tasks = [self._analyze_single_url(url) for url in urls]
        return await asyncio.gather(*tasks)
