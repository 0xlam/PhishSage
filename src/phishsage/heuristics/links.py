import re
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


def make_meta(inspected=None, evidence=None, rule=None, diagnostic=None):
    meta = {"inspected": inspected or {}}
    if evidence:
        meta["evidence"] = evidence
    if rule:
        meta["rule"] = rule
    if diagnostic:
        meta["diagnostic"] = diagnostic
    return meta


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
                reasons=[],
                status="skipped",
                meta=make_meta(diagnostic={"missing": "hostname"}),
            )

        if not self.ssl_fetcher:
            return LinkHeuristicResult(
                name="certificate",
                flags=False,
                reasons=[],
                status="skipped",
                meta=make_meta(
                    inspected={"hostname": hostname},
                    diagnostic={"missing_service": "ssl_fetcher"},
                ),
            )

        try:
            cert = await self.ssl_fetcher(hostname)

            flags = False
            reasons = []

            if cert.days_until_expiry < 0:
                flags = True
                reasons.append("expired_certificate")

            if (
                0
                <= cert.days_since_issued
                <= self.config.CERT_RECENT_ISSUE_DAYS_THRESHOLD
            ):
                flags = True
                reasons.append("recently_issued_certificate")

            return LinkHeuristicResult(
                name="certificate",
                flags=flags,
                reasons=reasons,
                meta=make_meta(
                    inspected={
                        "hostname": hostname,
                        "issuer": cert.issuer,
                        "subject": cert.subject,
                        "valid_from": cert.valid_from,
                        "valid_to": cert.valid_to,
                    },
                    evidence={
                        "days_since_issued": cert.days_since_issued,
                        "days_until_expiry": cert.days_until_expiry,
                    },
                    rule={
                        "cert_recent_issue_days_threshold": self.config.CERT_RECENT_ISSUE_DAYS_THRESHOLD,
                    },
                ),
            )

        except Exception as e:
            return LinkHeuristicResult(
                name="certificate",
                flags=False,
                reasons=[],
                status="error",
                meta=make_meta(
                    inspected={"hostname": hostname},
                    diagnostic={"error": str(e), "exception_type": type(e).__name__},
                ),
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
            meta=make_meta(
                inspected={"subdomain": sub, "domain": dom},
                evidence={
                    "subdomain_entropy": sub_ent,
                    "domain_entropy": dom_ent,
                },
                rule={"entropy_threshold": self.config.ENTROPY_THRESHOLD},
            ),
        )

    def has_suspicious_tld(self, parsed) -> LinkHeuristicResult:
        suffix = parsed.suffix

        if not suffix:
            return LinkHeuristicResult(
                name="suspicious_tld",
                flags=False,
                reasons=[],
                status="skipped",
                meta=make_meta(diagnostic={"missing": "suffix"}),
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
            meta=make_meta(
                inspected={"suffix": suffix},
                evidence={
                    "known_suspicious": is_known_suspicious,
                    "punycode": is_punycode,
                    "non_ascii": is_non_ascii,
                },
            ),
        )

    def embedded_tld(self, parsed) -> LinkHeuristicResult:

        subdomain = parsed.subdomain or ""
        domain = parsed.domain or ""
        real_suffix = (parsed.suffix or "").lower()
        common_tlds = {tld.lower() for tld in self.config.COMMON_TLDS}

        def find_matches(value: str) -> list[str]:
            segments = re.split(r"[-.]", value.lower())
            return sorted(
                {
                    seg
                    for seg in segments
                    if seg in common_tlds and seg != real_suffix
                }
            )

        subdomain_matches = find_matches(subdomain)
        domain_matches = find_matches(domain)

        reasons = []
        if domain_matches:
            reasons.append("embedded_fake_tld_in_domain")
        if subdomain_matches:
            reasons.append("embedded_fake_tld_in_subdomain")

        return LinkHeuristicResult(
            name="embedded_tld",
            flags=bool(reasons),
            reasons=reasons,
            meta=make_meta(
                inspected={
                    "subdomain": subdomain,
                    "domain": domain,
                    "suffix": real_suffix,
                },
                evidence={
                    "subdomain_matched_tlds": subdomain_matches,
                    "domain_matched_tlds": domain_matches,
                },
            ),
        )

    def is_ip_url(self, parsed) -> LinkHeuristicResult:
        hostname = parsed.hostname

        if not hostname:
            return LinkHeuristicResult(
                name="ip_url", flags=False, reasons=[],
                status="skipped",
                meta=make_meta(diagnostic={"missing": "hostname"}),
            )

        try:
            ip = ipaddress.ip_address(hostname)

            return LinkHeuristicResult(
                name="ip_url",
                flags=True,
                reasons=["ip_based_url"],
                meta=make_meta(
                    inspected={"hostname": hostname},
                    evidence={"is_ip": True, "ip_version": ip.version},
                ),
            )

        except ValueError:
            return LinkHeuristicResult(
                name="ip_url",
                flags=False,
                reasons=[],
                meta=make_meta(inspected={"hostname": hostname}),
            )

    def too_many_subdomains(self, parsed) -> LinkHeuristicResult:
        threshold = self.config.SUBDOMAIN_THRESHOLD

        sub = parsed.subdomain or ""

        if not sub:
            return LinkHeuristicResult(
                name="subdomains",
                flags=False,
                reasons=[],
                meta=make_meta(
                    inspected={"subdomain": ""},
                    evidence={"suspicious_count": 0},
                    rule={"subdomain_threshold": threshold},
                ),
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
            meta=make_meta(
                inspected={"subdomain": sub},
                evidence={
                    "suspicious_labels": suspicious,
                    "suspicious_count": len(suspicious),
                },
                rule={"subdomain_threshold": threshold},
            ),
        )

    def is_shortened_url(self, parsed) -> LinkHeuristicResult:
        domain = parsed.registered_domain

        if not domain:
            return LinkHeuristicResult(
                name="shortened_url",
                flags=False,
                reasons=[],
                status="skipped",
                meta=make_meta(diagnostic={"missing": "registered_domain"}),
            )

        domain = domain.lower()

        match = next((s for s in self.config.SHORTENERS if s.lower() == domain), None)

        flags = match is not None

        return LinkHeuristicResult(
            name="shortened_url",
            flags=flags,
            reasons=["url_shortener"] if flags else [],
            meta=make_meta(
                inspected={"registered_domain": domain},
                evidence={"matched_shortener": match},
            ),
        )

    def uses_abusable_platform(self, parsed) -> LinkHeuristicResult:
        domain = parsed.registered_domain

        if not domain:
            return LinkHeuristicResult(
                name="abusable_platform",
                flags=False,
                reasons=[],
                status="skipped",
                meta=make_meta(diagnostic={"missing": "registered_domain"}),
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
            meta=make_meta(
                inspected={"registered_domain": domain},
                evidence={"matched_platform": match},
            ),
        )

    def hyphen_abuse(self, parsed) -> LinkHeuristicResult:
        sub = parsed.subdomain or ""
        dom = parsed.domain or ""

        sub_count = sub.count("-")
        dom_count = dom.count("-")

        reasons = []
        if dom_count >= self.config.HYPHEN_THRESHOLD:
            reasons.append("excessive_hyphens_in_domain")
        if sub_count >= self.config.HYPHEN_THRESHOLD:
            reasons.append("excessive_hyphens_in_subdomain")

        flags = bool(reasons)

        return LinkHeuristicResult(
            name="hyphen_abuse",
            flags=flags,
            reasons=reasons,
            meta=make_meta(
                inspected={"subdomain": sub, "domain": dom},
                evidence={
                    "subdomain_hyphen_count": sub_count,
                    "domain_hyphen_count": dom_count,
                },
                rule={"hyphen_threshold": self.config.HYPHEN_THRESHOLD},
            ),
        )

    def double_hyphen_abuse(self, parsed) -> LinkHeuristicResult:
        sub = parsed.subdomain or ""
        dom = parsed.domain or ""

        def has_suspicious_double_hyphen(label: str) -> bool:
            return "--" in label and not label.startswith("xn--")

        dom_flag = has_suspicious_double_hyphen(dom)
        sub_flag = has_suspicious_double_hyphen(sub)

        reasons = []
        if dom_flag:
            reasons.append("double_hyphen_in_domain")
        if sub_flag:
            reasons.append("double_hyphen_in_subdomain")

        flags = bool(reasons)

        return LinkHeuristicResult(
            name="double_hyphen_abuse",
            flags=flags,
            reasons=reasons,
            meta=make_meta(
                inspected={"subdomain": sub, "domain": dom},
                evidence={
                    "domain_has_double_hyphen": dom_flag,
                    "subdomain_has_double_hyphen": sub_flag,
                },
            ),
        )

    def excessive_path_depth(self, parsed) -> LinkHeuristicResult:
        path = parsed.path or "/"
        depth = len([p for p in path.split("/") if p])

        flags = depth > self.config.MAX_PATH_DEPTH

        return LinkHeuristicResult(
            name="path_depth",
            flags=flags,
            reasons=["excessive_path_depth"] if flags else [],
            meta=make_meta(
                inspected={"path": path},
                evidence={"depth": depth},
                rule={"max_path_depth": self.config.MAX_PATH_DEPTH},
            ),
        )

    def is_numeric_domain(self, parsed) -> LinkHeuristicResult:
        label = parsed.domain

        if not label:
            return LinkHeuristicResult(
                name="numeric_domain",
                flags=False,
                reasons=[],
                status="skipped",
                meta=make_meta(diagnostic={"missing": "domain_label"}),
            )

        flags = label.isdigit()

        return LinkHeuristicResult(
            name="numeric_domain",
            flags=flags,
            reasons=["numeric_domain"] if flags else [],
            meta=make_meta(
                inspected={"domain": label},
                evidence={"is_numeric": flags},
            ),
        )

    async def domain_age(self, parsed) -> LinkHeuristicResult:
        domain = parsed.registered_domain

        if not domain:
            return LinkHeuristicResult(
                name="domain_age",
                flags=False,
                reasons=[],
                status="skipped",
                meta=make_meta(
                    inspected={"registered_domain": None},
                    diagnostic={"missing": "registered_domain"},
                ),
            )

        if not self.whois_lookup:
            return LinkHeuristicResult(
                name="domain_age",
                flags=False,
                reasons=[],
                status="skipped",
                meta=make_meta(
                    inspected={"registered_domain": domain},
                    diagnostic={"missing_service": "whois_lookup"},
                ),
            )

        try:
            w = await self.whois_lookup(domain)

            flags = False
            reasons = []

            if w.age_days is not None and w.age_days < self.config.THRESHOLD_YOUNG:
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
                meta=make_meta(
                    inspected={
                        "registered_domain": domain,
                        "registrar": w.registrar,
                        "created_at": (
                            w.created_at.isoformat() if w.created_at else None
                        ),
                        "expires_at": (
                            w.expires_at.isoformat() if w.expires_at else None
                        ),
                    },
                    evidence={
                        "age_days": w.age_days,
                        "expiry_days": w.expiry_days,
                    },
                    rule={
                        "young_threshold": self.config.THRESHOLD_YOUNG,
                        "expiry_threshold": self.config.THRESHOLD_EXPIRING,
                    },
                ),
            )

        except Exception as e:
            return LinkHeuristicResult(
                name="domain_age",
                flags=False,
                reasons=[],
                status="error",
                meta=make_meta(
                    inspected={"registered_domain": domain},
                    diagnostic={"error": str(e), "exception_type": type(e).__name__},
                ),
            )

    async def scan_virustotal(self, parsed) -> LinkHeuristicResult:
        url = parsed.normalized

        if not self.vt_lookup:
            return LinkHeuristicResult(
                name="virustotal",
                flags=False,
                reasons=[],
                status="skipped",
                meta=make_meta(
                    inspected={"normalized_url": url},
                    diagnostic={"missing_service": "vt_lookup"},
                ),
            )

        try:
            vt = await self.vt_lookup(url)

            if vt.status != "ok":
                return LinkHeuristicResult(
                    name="virustotal",
                    flags=False,
                    reasons=[],
                    status="error",
                    meta=make_meta(
                        inspected={"normalized_url": url},
                        diagnostic={
                            "error": vt.status if isinstance(vt.status, str) else "failed",
                        },
                    ),
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
                meta=make_meta(
                    inspected={
                        "normalized_url": url,
                        "resource": vt.resource,
                        "status": vt.status,
                        "last_analysis_date": vt.last_analysis_date,
                        "first_submission_date": vt.first_submission_date,
                    },
                    evidence={"stats": stats.__dict__},
                ),
            )

        except Exception as e:
            return LinkHeuristicResult(
                name="virustotal",
                flags=False,
                reasons=[],
                status="error",
                meta=make_meta(
                    inspected={"normalized_url": url},
                    diagnostic={"error": str(e), "exception_type": type(e).__name__},
                ),
            )

    async def resolve_redirect_chain(self, parsed) -> LinkHeuristicResult:
        if not self.redirect_lookup:
            return LinkHeuristicResult(
                name="redirect_chain",
                flags=False,
                reasons=[],
                status="skipped",
                meta=make_meta(diagnostic={"missing_service": "redirect_lookup"}),
            )

        url = parsed.normalized

        try:
            chain_result = await self.redirect_lookup(url)

            if chain_result.redirected and len(chain_result.chain) == 0:
                return LinkHeuristicResult(
                    name="redirect_chain",
                    flags=True,
                    reasons=["excessive_redirects"],
                    meta=make_meta(
                        inspected={"normalized_url": url},
                        evidence={"redirect_count": chain_result.redirect_count},
                    ),
                )

            if len(chain_result.chain) == 0:
                return LinkHeuristicResult(
                    name="redirect_chain",
                    flags=False,
                    reasons=[],
                    status="error",
                    meta=make_meta(
                        inspected={"normalized_url": url},
                        diagnostic={"error": "no redirect chain resolved"},
                    ),
                )

            redirect_count = len(chain_result.chain) - 1
            redirected = redirect_count > 0

            reasons = []
            if redirected:
                reasons.append("has_redirect_chain")

            return LinkHeuristicResult(
                name="redirect_chain",
                flags=redirected,
                reasons=reasons,
                meta=make_meta(
                    inspected={
                        "normalized_url": url,
                        "final_url": chain_result.final_url,
                        "final_status": chain_result.final_status,
                    },
                    evidence={
                        "redirect_chain": chain_result.chain,
                        "status_codes": chain_result.status_codes,
                        "redirect_count": redirect_count,
                    },
                ),
            )

        except Exception as exc:
            return LinkHeuristicResult(
                name="redirect_chain",
                flags=False,
                reasons=[],
                status="error",
                meta=make_meta(
                    inspected={"normalized_url": url},
                    diagnostic={
                        "error": str(exc),
                        "exception_type": type(exc).__name__,
                    },
                ),
            )

    async def _analyze_single_url(self, url: str) -> dict:
        try:
            parsed = parse_url(url)

            if parsed is None:
                return {
                    "url": url,
                    "flags": False,
                    "reasons": [],
                    "status": "skipped",
                    "meta": make_meta(
                        inspected={"url": url},
                        diagnostic={"error": "unparseable"},
                    ),
                }

            heuristics = {
                "ip_based": self.is_ip_url(parsed),
                "suspicious_tld": self.has_suspicious_tld(parsed),
                "embedded_tld": self.embedded_tld(parsed),
                "excessive_subdomains": self.too_many_subdomains(parsed),
                "shortened_url": self.is_shortened_url(parsed),
                "abusable_platform": self.uses_abusable_platform(parsed),
                "hyphen_abuse": self.hyphen_abuse(parsed),
                "double_hyphen_abuse": self.double_hyphen_abuse(parsed),
                "excessive_path": self.excessive_path_depth(parsed),
                "numeric_domain": self.is_numeric_domain(parsed),
                "domain_entropy": self.domain_entropy(parsed),
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
                            flags=False,
                            reasons=[],
                            status="error",
                            meta=make_meta(
                                diagnostic={
                                    "error": str(data),
                                    "exception_type": type(data).__name__,
                                }
                            ),
                        )
                    enrichment[name] = data

            # Aggregate flags across all LinkHeuristicResult objects
            all_results = list(heuristics.values()) + list(enrichment.values())
            aggregated_flags = sorted(
                {reason for r in all_results if r.flags for reason in r.reasons}
            )

            service_errors = sorted(
                name for name, r in enrichment.items() if r.status == "error"
            )

            extra = {"service_errors": service_errors} if service_errors else {}

            return {
                "url": url,
                "heuristics": {k: v.__dict__ for k, v in heuristics.items()},
                "enrichment": {k: v.__dict__ for k, v in enrichment.items()},
                "aggregated_flags": aggregated_flags,
                **extra,
            }

        except Exception as e:
            return {
                "url": url,
                "flags": True,
                "reasons": ["unhandled_exception"],
                "meta": make_meta(
                    inspected={"url": url},
                    diagnostic={
                        "error": f"{type(e).__name__}: {str(e)}",
                        "traceback": traceback.format_exc(),
                    },
                ),
            }

    async def run_link_heuristics(self, urls: list[str]) -> list[dict]:
        tasks = [self._analyze_single_url(url) for url in urls]
        return await asyncio.gather(*tasks)
