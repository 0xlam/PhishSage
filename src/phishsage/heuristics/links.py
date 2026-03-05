import socket
import ssl
import traceback
from datetime import datetime, timezone


import asyncio
import aiohttp
import ipaddress
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from dateutil import parser


from phishsage.config.loader import (
    ABUSABLE_PLATFORM_DOMAINS,
    CERT_RECENT_ISSUE_DAYS_THRESHOLD,
    ENTROPY_THRESHOLD,
    MAX_PATH_DEPTH,
    SHORTENERS,
    SSL_DEFAULT_PORT,
    SUBDOMAIN_THRESHOLD,
    SUSPICIOUS_TLDS,
    THRESHOLD_EXPIRING,
    THRESHOLD_YOUNG,
    TRIVIAL_SUBDOMAINS,
)

from phishsage.utils import (
    check_virustotal,
    shannon_entropy,
    get_redirect_chain,
    parse_url,
)


class LinkHeuristics:
    """docstring for LinkHeuristics"""

    def __init__(self, vt_throttle: float = 1.0, include_redirects: bool = False):
        self.vt_throttle = vt_throttle
        self.include_redirects = include_redirects
        self._session = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()
            self._session = None

    async def analyze_certificate(self, parsed) -> dict:

        hostname = parsed.hostname

        if not hostname:
            return {"flags": False, "reason": ["invalid_url"], "meta": {}}

        def cert_check(hostname):

            result = {
                "flags": False,
                "reason": [],
                "meta": {},
            }

            try:

                socket.setdefaulttimeout(10)
                cert_pem = ssl.get_server_certificate((hostname, SSL_DEFAULT_PORT))

                cert = x509.load_pem_x509_certificate(
                    cert_pem.encode(), default_backend()
                )

                now = datetime.now(timezone.utc)
                valid_from = cert.not_valid_before_utc
                valid_to = cert.not_valid_after_utc

                days_since_issued = (now - valid_from).total_seconds() / 86400
                days_until_expiry = (valid_to - now).total_seconds() / 86400

                # Flags
                if now >= valid_to:
                    result["flags"] = True
                    result["reason"].append("expired_certificate")
                if 0 <= days_since_issued <= CERT_RECENT_ISSUE_DAYS_THRESHOLD:
                    result["flags"] = True
                    result["reason"].append("recently_issued_certificate")

                # Meta
                issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)

                result["meta"] = {
                    "hostname": hostname,
                    "issuer_cn": issuer_cn[0].value if issuer_cn else None,
                    "subject_cn": subject_cn[0].value if subject_cn else None,
                    "valid_from": valid_from.isoformat(),
                    "valid_to": valid_to.isoformat(),
                    "days_since_issued": int(days_since_issued),
                    "days_until_expiry": int(days_until_expiry),
                }

            except socket.timeout:
                result = {
                    "flags": True,
                    "reason": ["ssl_handshake_timeout"],
                    "meta": {"hostname": hostname, "error": "Connection timeout"},
                }
            except ssl.SSLError as e:
                msg = str(e).upper()
                reason = []
                if "CERTIFICATE_VERIFY_FAILED" in msg:
                    reason = ["certificate verification failed"]
                elif "WRONG_VERSION_NUMBER" in msg:
                    reason = ["tls_protocol_mismatch"]
                elif "HANDSHAKE_FAILURE" in msg:
                    reason = ["handshake_failure"]
                else:
                    reason = ["ssl_error"]
                result = {
                    "flags": True,
                    "reason": reason,
                    "meta": {"hostname": hostname, "error": str(e)},
                }
            except ConnectionRefusedError:
                result = {
                    "flags": True,
                    "reason": ["connection_refused"],
                    "meta": {"hostname": hostname, "error": "Connection refused"},
                }
            except Exception as e:
                result = {
                    "flags": True,
                    "reason": ["unhandled_exception"],
                    "meta": {"hostname": hostname, "error": str(e)},
                }

            return result

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(cert_check, hostname), timeout=15
            )
        except asyncio.TimeoutError:
            return {
                "flags": True,
                "reason": ["operation_timeout"],
                "meta": {"hostname": hostname, "error": "Certificate check timed out"},
            }

    def domain_entropy(self, parsed) -> dict:
        """
        Flags URLs where the domain label or subdomain has suspiciously high Shannon entropy
        """
        entropy_threshold = ENTROPY_THRESHOLD

        try:
            registered_domain = parsed.registered_domain
            domain_label = parsed.domain
            subdomain = parsed.subdomain

            subdomain = subdomain or ""
            domain_label = domain_label or ""

            subdomain_ent = shannon_entropy(subdomain)
            domain_ent = shannon_entropy(domain_label)

            sub_high = len(subdomain) >= 8 and subdomain_ent >= entropy_threshold
            domain_high = len(domain_label) >= 6 and domain_ent >= entropy_threshold

            flag = sub_high or domain_high

            reason = []
            if sub_high:
                reason.append("high_subdomain_entropy")
            if domain_high:
                reason.append("high_domain_entropy")

            return {
                "flags": flag,
                "reason": reason,
                "meta": {
                    "registered_domain": registered_domain,
                    "domain_label": domain_label,
                    "subdomain": subdomain,
                    "subdomain_entropy": round(subdomain_ent, 3),
                    "domain_entropy": round(domain_ent, 3),
                    "entropy_threshold": entropy_threshold,
                },
            }

        except Exception as e:
            return {
                "flags": True,
                "reason": ["entropy_calculation_failed"],
                "meta": {
                    "registered_domain": None,
                    "domain_label": None,
                    "subdomain": None,
                    "subdomain_entropy": None,
                    "domain_entropy": None,
                    "entropy_threshold": entropy_threshold,
                    "error": str(e),
                },
            }

    def has_suspicious_tld(self, parsed) -> dict:
        """
        Checks if the URL's top-level domain (TLD) is in a known list of suspicious TLDs.
        """
        try:
            registered_domain = parsed.registered_domain
            public_suffix = parsed.suffix

            if not public_suffix:
                return {
                    "flags": False,
                    "reason": ["no_public_suffix_extracted"],
                    "meta": {
                        "registered_domain": (
                            registered_domain if registered_domain else None
                        ),
                        "public_suffix": None,
                    },
                }

            is_known_suspicious = public_suffix in SUSPICIOUS_TLDS
            is_punycode = public_suffix.startswith("xn--")
            flag = is_known_suspicious or is_punycode

            reason = []
            if is_known_suspicious:
                reason.append("known_suspicious_tld")

            if is_punycode:
                reason.append("punycode_tld")

            return {
                "flags": flag,
                "reason": reason,
                "meta": {
                    "registered_domain": registered_domain,
                    "public_suffix": public_suffix,
                },
            }

        except Exception as e:
            return {
                "flags": True,
                "reason": ["tld_check_failed"],
                "meta": {
                    "registered_domain": None,
                    "public_suffix": None,
                    "error": str(e),
                },
            }

    def is_ip_url(self, parsed) -> dict:
        """Detects if a URL directly uses an IP address instead of a domain name."""
        try:
            hostname = parsed.hostname
            registered_domain = parsed.registered_domain

            if not hostname:
                return {
                    "flags": True,
                    "reason": ["no_hostname_extracted"],
                    "meta": {
                        "registered_domain": None,
                        "hostname": None,
                    },
                }

            try:
                ip_obj = ipaddress.ip_address(hostname)
                return {
                    "flags": True,
                    "reason": ["ip_based_url"],
                    "meta": {
                        "registered_domain": None,
                        "hostname": hostname,
                        "ip_version": ip_obj.version,
                    },
                }

            except ValueError:
                # Not an IP

                return {
                    "flags": False,
                    "reason": [],
                    "meta": {
                        "registered_domain": registered_domain,
                        "hostname": hostname,
                    },
                }

        except Exception as e:
            return {
                "flags": True,
                "reason": ["ip_url_check_failed"],
                "meta": {
                    "registered_domain": None,
                    "hostname": None,
                    "error": str(e),
                },
            }

    def too_many_subdomains(self, parsed) -> dict:
        """
        Detect whether a URL contains an excessive number of suspicious subdomains.
        Trivial subdomains like 'www' are ignored.
        """
        threshold = SUBDOMAIN_THRESHOLD

        def looks_like_junk(label: str) -> bool:
            if not label:
                return True
            digit_ratio = sum(c.isdigit() for c in label) / len(label)
            return digit_ratio > 0.4

        try:

            registered_domain = parsed.registered_domain
            subdomain = parsed.subdomain

            if not subdomain:
                return {
                    "flags": False,
                    "reason": [],
                    "meta": {
                        "registered_domain": registered_domain,
                        "subdomain": None,
                        "suspicious_count": 0,
                        "threshold": threshold,
                        "suspicious_subdomains": [],
                    },
                }

            parts = [p for p in subdomain.split(".") if p]

            suspicious_parts = []
            for p in parts:
                lower_p = p.lower()

                if lower_p in TRIVIAL_SUBDOMAINS:
                    continue

                if len(p) <= 2:
                    continue

                if looks_like_junk(p):
                    suspicious_parts.append(p)

            suspicious_count = len(suspicious_parts)
            is_excessive = suspicious_count >= threshold

            return {
                "flags": is_excessive,
                "reason": ["excessive_suspicious_subdomains"] if is_excessive else [],
                "meta": {
                    "registered_domain": registered_domain,
                    "subdomain": subdomain,
                    "suspicious_count": suspicious_count,
                    "threshold": threshold,
                    "suspicious_subdomains": suspicious_parts,
                },
            }

        except Exception as e:
            return {
                "flags": True,
                "reason": ["subdomain_analysis_failed"],
                "meta": {
                    "registered_domain": None,
                    "subdomain": None,
                    "suspicious_count": None,
                    "threshold": threshold,
                    "suspicious_subdomains": [],
                    "error": str(e),
                },
            }

    def is_shortened_url(self, parsed) -> dict:
        """Check whether the URL uses a known URL shortening service."""
        try:
            registered_domain = parsed.registered_domain

            if not registered_domain:
                return {
                    "flags": False,
                    "reason": ["no_registered_domain"],
                    "meta": {
                        "registered_domain": None,
                        "matched_shortener": None,
                    },
                }

            registered_domain_lower = registered_domain.lower()
            shorteners = [s.lower() for s in SHORTENERS]

            matched_shortener = next(
                (s for s in shorteners if registered_domain_lower == s),
                None,
            )

            is_shortened = matched_shortener is not None

            return {
                "flags": is_shortened,
                "reason": ["url_shortening_service"] if is_shortened else [],
                "meta": {
                    "registered_domain": registered_domain,
                    "matched_shortener": matched_shortener,
                },
            }

        except Exception as e:
            return {
                "flags": True,
                "reason": ["shortened_url_check_failed"],
                "meta": {
                    "registered_domain": None,
                    "matched_shortener": None,
                    "error": str(e),
                },
            }

    def uses_abusable_platform(self, parsed) -> dict:
        """Detect whether a URL uses a commonly abused web platform or service."""
        try:
            registered_domain = parsed.registered_domain

            if not registered_domain:
                return {
                    "flags": False,
                    "reason": ["no_registered_domain"],
                    "meta": {
                        "registered_domain": None,
                        "matched_platform": None,
                    },
                }

            registered_domain = registered_domain.lower()
            platforms = [d.lower() for d in ABUSABLE_PLATFORM_DOMAINS]

            matched = next(
                (
                    p
                    for p in platforms
                    if registered_domain == p or registered_domain.endswith("." + p)
                ),
                None,
            )

            return {
                "flags": matched is not None,
                "reason": ["abusable_platform"] if matched else [],
                "meta": {
                    "registered_domain": registered_domain,
                    "matched_platform": matched,
                },
            }

        except Exception as e:
            return {
                "flags": True,
                "reason": ["abusable_platform_check_failed"],
                "meta": {
                    "registered_domain": None,
                    "matched_platform": None,
                    "error": str(e),
                },
            }

    def excessive_path_depth(self, parsed) -> dict:
        """Check if the URL path has excessive depth."""

        max_depth = MAX_PATH_DEPTH

        try:
            registered_domain = parsed.registered_domain

            path = parsed.path or "/"

            depth = len([segment for segment in path.split("/") if segment])
            is_excessive = depth > max_depth

            return {
                "flags": is_excessive,
                "reason": ["excessive_path_depth"] if is_excessive else [],
                "meta": {
                    "registered_domain": registered_domain,
                    "path": path,
                    "depth": depth,
                    "max_allowed": max_depth,
                },
            }

        except Exception as e:
            return {
                "flags": True,
                "reason": ["path_depth_check_failed"],
                "meta": {
                    "registered_domain": None,
                    "path": None,
                    "depth": None,
                    "max_allowed": max_depth,
                    "error": str(e),
                },
            }

    def is_numeric_domain(self, parsed) -> dict:

        try:
            registered_domain = parsed.registered_domain
            domain_label = parsed.domain

            if not domain_label:
                return {
                    "flags": False,
                    "reason": ["no_domain_label_extracted"],
                    "meta": {
                        "registered_domain": None,
                        "domain_label": None,
                    },
                }

            is_numeric = domain_label.isdigit()

            return {
                "flags": is_numeric,
                "reason": ["numeric_domain"] if is_numeric else [],
                "meta": {
                    "registered_domain": registered_domain,
                    "domain_label": domain_label,
                },
            }

        except Exception as e:
            return {
                "flags": True,
                "reason": ["numeric_domain_check_failed"],
                "meta": {
                    "registered_domain": None,
                    "domain_label": None,
                    "error": str(e),
                },
            }

    async def domain_age(self, parsed) -> dict:
        """
        Flags True if domain is newly registered, expiring soon, or WHOIS failed.
        """
        result = {
            "flags": False,
            "reason": [],
            "meta": {
                "registered_domain": parsed.registered_domain,
                "age_days": None,
                "expiry_days_left": None,
            },
        }

        threshold_young = THRESHOLD_YOUNG
        threshold_expiring = THRESHOLD_EXPIRING

        try:
            w = await asyncio.to_thread(whois.whois, parsed.registered_domain)

            # Handle creation date
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if isinstance(created, str):
                created = parser.parse(created)

            # Handle expiration date
            expires = w.expiration_date
            if isinstance(expires, list):
                expires = expires[0]
            if isinstance(expires, str):
                expires = parser.parse(expires)

            now = datetime.now(timezone.utc)

            # Normalize timezone
            if created:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                else:
                    created = created.astimezone(timezone.utc)
                result["meta"]["age_days"] = (now - created).days
                if result["meta"]["age_days"] < threshold_young:
                    result["flags"] = True
                    result["reason"].append("young_domain")

            if expires:
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                else:
                    expires = expires.astimezone(timezone.utc)
                result["meta"]["expiry_days_left"] = (expires - now).days
                if result["meta"]["expiry_days_left"] <= threshold_expiring:
                    result["flags"] = True
                    result["reason"].append("domain_expiring_soon")

        except Exception as e:
            err_msg = str(e).splitlines()[0] if str(e) else "Unknown WHOIS error"
            result["flags"] = True
            result["reason"].append("whois_lookup_failed")
            result["meta"]["error"] = err_msg

        return result

    async def scan_with_virustotal(self, parsed) -> dict:
        """
        Scan a URL with VirusTotal and return flags, reason, and meta.
        Flags True if malicious/suspicious or if scan failed.
        """
        url = parsed.normalized

        try:
            vt_result = await check_virustotal(url=url)

            status = vt_result.get("status")
            reason_from_vt = vt_result.get("reason")
            meta = vt_result.get("meta", {})

            if status != "rate_limited":
                await asyncio.sleep(self.vt_throttle)

            # Handle non-success
            if status != "ok":
                return {
                    "flags": False if status == "not_found" else True,
                    "reason": (
                        [f"vt_{reason_from_vt}"] if reason_from_vt else [f"vt_{status}"]
                    ),
                    "meta": {
                        "status": status,
                        "stats": None,
                        "resource": meta.get("resource"),
                    },
                }

            stats = meta.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0) > 0
            suspicious = stats.get("suspicious", 0) > 0
            is_flagged = malicious or suspicious

            reasons = []
            if malicious:
                reasons.append("vt_malicious")
            elif suspicious:
                reasons.append("vt_suspicious")

            return {
                "flags": is_flagged,
                "reason": reasons,
                "meta": {
                    "status": "ok",
                    "stats": stats,
                    "resource": meta.get("resource"),
                    "last_analysis_date": meta.get("last_analysis_date"),
                    "first_submission_date": meta.get("first_submission_date"),
                },
            }

        except Exception as e:
            return {
                "flags": True,
                "reason": ["vt_exception"],
                "meta": {
                    "status": "exception",
                    "error": str(e),
                },
            }

    async def _analyze_single_url(self, url: str) -> dict:
        try:
            parsed = parse_url(url)

            # --- URL-based heuristics ---
            heuristics = {
                "ip_based": self.is_ip_url(parsed),
                "suspicious_tld": self.has_suspicious_tld(parsed),
                "excessive_subdomains": self.too_many_subdomains(parsed),
                "shortened_url": self.is_shortened_url(parsed),
                "numeric_domain": self.is_numeric_domain(parsed),
                "excessive_path": self.excessive_path_depth(parsed),
                "abusable_platform": self.uses_abusable_platform(parsed),
            }

            # --- Entropy ---
            entropy = self.domain_entropy(parsed)

            tasks = [
                asyncio.create_task(self.analyze_certificate(parsed)),
                asyncio.create_task(self.domain_age(parsed)),
                asyncio.create_task(self.scan_with_virustotal(parsed)),
            ]

            # Optional redirect chain
            if self.include_redirects:
                tasks.append(
                    asyncio.create_task(get_redirect_chain(parsed, self._session))
                )

            results = await asyncio.gather(*tasks, return_exceptions=True)

            certificate = (
                results[0]
                if not isinstance(results[0], Exception)
                else {
                    "flags": True,
                    "reason": ["cert_analysis_failed"],
                    "meta": {"error": str(results[0])},
                }
            )

            domain_age_result = (
                results[1]
                if not isinstance(results[1], Exception)
                else {
                    "flags": True,
                    "reason": ["whois_failed"],
                    "meta": {"error": str(results[1])},
                }
            )

            virustotal = (
                results[2]
                if not isinstance(results[2], Exception)
                else {
                    "flags": True,
                    "reason": ["vt_scan_failed"],
                    "meta": {"error": str(results[2])},
                }
            )

            redirect_chain = results[3] if self.include_redirects else None
            if self.include_redirects and isinstance(redirect_chain, Exception):
                redirect_chain = {
                    "error": f"redirect_check_failed: {str(redirect_chain)}"
                }

            # --- Aggregate Flags ---
            aggregated_flags = set()
            for result in heuristics.values():
                if result.get("flags"):
                    aggregated_flags.update(result.get("reason", []))
            for result in [entropy, certificate, domain_age_result, virustotal]:
                if result.get("flags"):
                    aggregated_flags.update(result.get("reason", []))
            if redirect_chain and redirect_chain.get("redirected", False):
                aggregated_flags.add("redirected_url")

            # --- Final Result ---
            result = {
                "url": url,
                "heuristics": heuristics,
                "entropy": entropy,
                "certificate": certificate,
                "domain_age": domain_age_result,
                "virustotal": virustotal,
            }
            if redirect_chain:
                result["redirect_chain"] = redirect_chain

            result["aggregated_flags"] = sorted(aggregated_flags)

            return result

        except Exception as e:
            return {
                "url": url,
                "flags": True,
                "reason": ["unhandled_exception"],
                "meta": {
                    "error": f"{type(e).__name__}: {str(e)}",
                    "traceback": traceback.format_exc(),
                },
            }

    async def run_link_heuristics(self, urls: list[str]) -> list[dict]:
        tasks = [self._analyze_single_url(url) for url in urls]
        return await asyncio.gather(*tasks)
