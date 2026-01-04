import re
import time
import ipaddress
import ssl
import socket
import whois
import traceback
from dateutil import parser
from datetime import datetime, timezone
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from urllib.parse import urlparse, parse_qs
from phishsage.config.loader import (
    SUSPICIOUS_TLDS,
    SHORTENERS,
    FREE_HOSTING_PROVIDERS,
    SUBDOMAIN_THRESHOLD,
    ENTROPY_THRESHOLD,
    MAX_PATH_DEPTH,
    THRESHOLD_YOUNG,
    THRESHOLD_EXPIRING,
    TRIVIAL_SUBDOMAINS,
    CERT_RECENT_ISSUE_DAYS_THRESHOLD,
    CERT_EXPIRY_SOON_DAYS_THRESHOLD,
    SSL_DEFAULT_PORT,
)
from phishsage.utils.url_helpers import *
from phishsage.utils.api_clients import check_virustotal



def analyze_certificate(url):
    """
    Checks if certificate is expired or recently issued.
    """

    result = {
        "flags": False,
        "reason": [],
        "meta": {},   
    }

    try:
        hostname = get_hostname(url)
        if not hostname:
            result["reason"].append("invalid_url")
            return result

        cert_pem = ssl.get_server_certificate(
            (hostname, SSL_DEFAULT_PORT)
        )

        cert = x509.load_pem_x509_certificate(
            cert_pem.encode(),
            default_backend()
        )

        now = datetime.now(timezone.utc)
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc

        days_since_issued = (now - valid_from).total_seconds() / 86400
        days_until_expiry = (valid_to - now).total_seconds() / 86400

        # ---- expired ----
        if now >= valid_to:
            result["flags"] = True
            result["reason"].append("expired_certificate")

        # ---- recently issued ----
        if 0 <= days_since_issued <= CERT_RECENT_ISSUE_DAYS_THRESHOLD:
            result["flags"] = True
            result["reason"].append("recently_issued_certificate")

        # ---- minimal meta ----
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

        return result

    except socket.timeout:
        return {
            "flags": True,
            "reason": ["ssl_handshake_timeout"],
            "meta": {"hostname": hostname, "error": str(e)}    
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

        return {
            "flags": True,
            "reason": reason,
            "meta": {"hostname": hostname, "error": str(e)}
        }

    except Exception as e:
        return {
            "flags": True,
            "reason": ["unhandled_exception"],
            "meta": {"hostname": hostname, "error": str(e)}
        }


def domain_entropy(url, entropy_threshold = ENTROPY_THRESHOLD):
    """
    Flags URLs where the domain label or subdomain has suspiciously high Shannon entropy
    """
    try:
        registered_domain, domain_label, subdomain, _ = extract_domain_parts(url)
        
        subdomain = subdomain or ""
        domain_label = domain_label or ""

        
        subdomain_ent = shannon_entropy(subdomain)
        domain_ent = shannon_entropy(domain_label)
        
        # Only consider entropy meaningful if string is long enough
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
                "error": str(e)
            }   
        }


def has_suspicious_tld(url):
    """
    Checks if the URL's top-level domain (TLD) is in a known list of suspicious TLDs.
    """
    try:
        registered_domain, _, _, public_suffix = extract_domain_parts(url)

        if not public_suffix:
            return {
                "flags": False,
                "reason": ["no_public_suffix_extracted"],
                "meta": {
                    "registered_domain": registered_domain if registered_domain else None,
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
        

def is_ip_url(url):
    """ Detects if a URL directly uses an IP address instead of a domain name."""
    try:
        hostname = get_hostname(url)
        
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
            registered_domain, domain_label, _, _ = extract_domain_parts(url)
            
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


def too_many_subdomains(url, threshold=SUBDOMAIN_THRESHOLD):
    """
    Detect whether a URL contains an excessive number of suspicious subdomains.
    Trivial subdomains like 'www' are ignored.
    """

    def looks_like_junk(label: str) -> bool:
        if not label:
            return True
        digit_ratio = sum(c.isdigit() for c in label) / len(label)
        return digit_ratio > 0.4

    try:
        registered_domain, _, subdomain, _ = extract_domain_parts(url)

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



def is_shortened_url(url):
    """Check whether the URL uses a known URL shortening service."""
    try:
        registered_domain, _, _, _ = extract_domain_parts(url)

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



def uses_free_hosting_domain(url):
    """Detect whether a URL uses a known free or cheap hosting provider."""
    try:
        registered_domain, _, _, _ = extract_domain_parts(url)

        if not registered_domain:
            return {
                "flags": False,
                "reason": ["no_registered_domain"],
                "meta": {
                    "registered_domain": None,
                    "matched_provider": None,
                },
            }

        registered_domain = registered_domain.lower()
        providers = [d.lower() for d in FREE_HOSTING_PROVIDERS]

        matched_provider = next(
            (
                provider
                for provider in providers
                if registered_domain == provider
                or registered_domain.endswith("." + provider)
            ),
            None,
        )

        is_free_hosting = matched_provider is not None

        return {
            "flags": is_free_hosting,
            "reason": ["free_hosting_provider"] if is_free_hosting else [],
            "meta": {
                "registered_domain": registered_domain,
                "matched_provider": matched_provider,
            },
        }

    except Exception as e:
        return {
            "flags": True,
            "reason": ["free_hosting_check_failed"],
            "meta": {
                "registered_domain": None,
                "matched_provider": None,
                "error": str(e),
            },
        }




def excessive_path_depth(url, max_depth=MAX_PATH_DEPTH):
    """Check if the URL path has excessive depth."""
    try:
        registered_domain, _, _, _ = extract_domain_parts(url)

        parsed = urlparse(normalize_url(url))
        path = parsed.path or "/"

        depth = len([segment for segment in path.split("/") if segment])
        is_excessive = depth > max_depth

        return {
            "flags": is_excessive,
            "reason": ["excessive_path_depth"] if is_excessive else [],
            "meta": {
                "registered_domain": registered_domain,
                "path": parsed.path,
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


def is_numeric_domain(url):
    """Check if the registrable domain label is numeric-only."""
    try:
        registered_domain, domain_label, _, _ = extract_domain_parts(url)

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




def domain_age(domain, threshold_young=THRESHOLD_YOUNG, threshold_expiring=THRESHOLD_EXPIRING):
    """
    Flags True if domain is newly registered, expiring soon, or WHOIS failed.
    """
    result = {
        "flags": False,
        "reason": [],
        "meta": {
            "registered_domain": domain,
            "age_days": None,
            "expiry_days_left": None,
        },
    }

    try:
        w = whois.whois(domain)

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


def scan_with_virustotal(url, throttle=1.0):
    """
    Scan a URL with VirusTotal and return flags, reason, and meta.
    Flags True if malicious/suspicious or if scan failed.
    """
    try:
        vt = check_virustotal(url=url)
        status = vt.get("status")
        reason_from_vt = vt.get("reason")
        meta = vt.get("meta", {})

        # Throttle unless rate-limited
        if status != "rate_limited":
            time.sleep(throttle)

        # Handle non-success statuses
        if status != "ok":
            return {
                "flags": True,
                "reason": [reason_from_vt] if reason_from_vt else [f"vt_{status}"],
                "meta": {
                    "status": status,
                    "stats": None,
                    "resource": meta.get("resource"),
                },
            }

        # Extract stats
        stats = meta
        cleaned_stats = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "resource": stats.get("resource"),
        }

        malicious = cleaned_stats["malicious"] > 0
        suspicious = cleaned_stats["suspicious"] > 0
        is_flagged = malicious or suspicious

        # Determine reasons
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
                "stats": cleaned_stats,
            },
        }

    except Exception as e:
        # Network or unexpected error
        return {
            "flags": True,
            "reason": ["vt_exception"],
            "meta": {
                "status": "exception",
                "error": str(e),
            },
        }


def run_link_heuristics(urls, vt_throttle=1.0, include_redirects=False):
    """
    Run all link-based heuristics on a list of URLs.
    Returns a list of per-URL analysis dictionaries.
    Each heuristic follows the {flags, reason, meta} format.
    """

    full_results = []

    for url in urls:
        try:
            normalized_url = normalize_url(url.strip())
            hostname = get_hostname(normalized_url)

            # --- URL-based heuristics ---
            heuristics = {
                "ip_based": is_ip_url(normalized_url),
                "suspicious_tld": has_suspicious_tld(normalized_url),
                "excessive_subdomains": too_many_subdomains(normalized_url),
                "shortened_url": is_shortened_url(normalized_url),
                "numeric_domain": is_numeric_domain(normalized_url),
                "excessive_path": excessive_path_depth(normalized_url),
                "free_hosting": uses_free_hosting_domain(normalized_url),
            }

            # --- Entropy ---
            try:
                entropy = domain_entropy(normalized_url)
            except Exception as e:
                entropy = {
                    "flags": False,
                    "reason": ["entropy_calc_failed"],
                    "meta": {"error": str(e)},
                }

            # --- SSL Certificate ---
            try:
                certificate = analyze_certificate(normalized_url)
            except Exception as e:
                certificate = {
                    "flags": True,
                    "reason": ["cert_analysis_failed"],
                    "meta": {"error": str(e)},
                }

            # --- Domain Age / WHOIS ---
            try:
                if hostname:
                    registered_domain, domain_label, _, _ = extract_domain_parts(url)
                    domain_age_result = domain_age(registered_domain)
                else:
                    domain_age_result = {
                        "flags": False,
                        "reason": ["no_hostname"],
                        "meta": {"domain": None},
                    }
            except Exception as e:
                domain_age_result = {
                    "flags": True,
                    "reason": ["whois_failed"],
                    "meta": {"error": str(e)},
                }

            # --- VirusTotal ---
            try:
                vt_raw = scan_with_virustotal(normalized_url, throttle=vt_throttle)
                virustotal = {
                    "flags": vt_raw.get("flags", False),
                    "reason": vt_raw.get("reason", []),
                    "meta": vt_raw.get("meta", {}),
                }
            except Exception as e:
                virustotal = {
                    "flags": True,
                    "reason": ["vt_scan_failed"],
                    "meta": {"error": str(e)},
                }

            # --- Optional Redirect Chain ---
            redirect_chain = None
            if include_redirects:
                try:
                    redirect_chain = get_redirect_chain(normalized_url)
                except Exception as e:
                    redirect_chain = {"error": f"redirect_check_failed: {str(e)}"}

            # --- Aggregate Flags ---
            aggregated_flags = set()
            for key, result in heuristics.items():
                if result.get("flags"):
                    aggregated_flags.update(result.get("reason", []))
            if entropy.get("flags"):
                aggregated_flags.update(entropy.get("reason", []))
            if certificate.get("flags"):
                aggregated_flags.update(certificate.get("reason", []))
            if domain_age_result.get("flags"):
                aggregated_flags.update(domain_age_result.get("reason", []))
            if virustotal.get("flags"):
                aggregated_flags.update(virustotal.get("reason", []))

            # --- Final Result per URL ---
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

            full_results.append(result)

        except Exception as e:
            # Catch-all for any URL-level processing failure
            full_results.append({
                "url": url,
                "flags": True,
                "reason": ["unhandled_exception"],
                "meta": {
                    "error": f"{type(e).__name__}: {str(e)}",
                    "traceback": traceback.format_exc(),
                },
            })

    return full_results
