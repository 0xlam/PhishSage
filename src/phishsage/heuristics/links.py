import re
import time
import ipaddress
import ssl
import socket
import datetime
import traceback
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
from phishsage.config.loader import (
    SUSPICIOUS_TLDS,
    SHORTENERS,
    SUBDOMAIN_THRESHOLD,
    SUSPICIOUS_URL_KEYWORDS,
    TRIVIAL_SUBDOMAINS,
    CERT_RECENT_ISSUE_DAYS_THRESHOLD,
    CERT_EXPIRY_SOON_DAYS_THRESHOLD,
    SSL_DEFAULT_PORT,
    SSL_HANDSHAKE_TIMEOUT_SECONDS,
)
from phishsage.utils.url_helpers import *
from phishsage.utils.api_clients import check_virustotal
from phishsage.heuristics.headers import domain_age_bulk



def analyze_certificate(url, timeout=5):
    """ SSL/TLS certificate analysis. """

    result = {
        "certificate_analysis": {
            "status": "no_ssl",
            "flags": [],
            "meta": {}
        }
    }

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            result["certificate_analysis"]["status"] = "invalid_url"
            return result

        # Fetch and parse certificate
        cert_pem = ssl.get_server_certificate((hostname,
            SSL_DEFAULT_PORT), timeout=timeout)
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        # Issuer
        issuer_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        issuer_name = issuer_attrs[0].value if issuer_attrs else "Unknown"

        # Validity
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.UTC)
        days_since_issued = (now - valid_from).days
        days_until_expiry = (valid_to - now).days

        # Domain match
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            sans = []
        cn_list = [attr.value for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
        names = set(sans + cn_list)
        domain_match = any(hostname.lower().endswith(name.lower()) for name in names)

        # Flags
        flags = []
        if days_since_issued <= CERT_RECENT_ISSUE_DAYS_THRESHOLD:
            flags.append("cert_recently_issued")
        if days_until_expiry <= 0:
            flags.append("cert_expired")
        elif days_until_expiry <= CERT_EXPIRY_SOON_DAYS_THRESHOLD:
            flags.append("cert_expiring_soon")
        if not domain_match:
            flags.append("cert_domain_mismatch")
        if issuer_name.lower() == hostname.lower():
            flags.append("cert_self_signed")

        # Fill meta
        meta = {
            "issuer": issuer_name,
            "valid_from": valid_from.strftime("%Y-%m-%d"),
            "valid_to": valid_to.strftime("%Y-%m-%d"),
            "days_since_issued": days_since_issued,
            "days_until_expiry": days_until_expiry,
            "domain_match": domain_match,
            "san_list": sans,
            "cn_list": cn_list,
            "hostname": hostname
        }

        result["certificate_analysis"].update({
            "status": "valid",
            "flags": flags,
            "meta": meta
        })

    except ssl.SSLError:
        result["certificate_analysis"].update({
            "status": "invalid_ssl",
            "flags": [],
            "meta": {"hostname": hostname}
        })
    except socket.timeout:
        result["certificate_analysis"].update({
            "status": "timeout",
            "flags": [],
            "meta": {"hostname": hostname}
        })
    except (ConnectionRefusedError, socket.gaierror):
        result["certificate_analysis"].update({
            "status": "no_ssl",
            "flags": [],
            "meta": {"hostname": hostname}
        })
    except Exception as e:
        result["certificate_analysis"].update({
            "status": f"error: {type(e).__name__}",
            "flags": [],
            "meta": {"hostname": hostname, "error": str(e)}
        })

    return result


def domain_entropy(url):
    """ Analyze entropy of the domain and subdomain components in a URL. """
    try:
        _, domain, subdomain, tld = extract_domain_parts(url)

        subdomain = subdomain or ""
        domain = domain or ""
        tld = tld or ""

        subdomain_entropy = shannon_entropy(subdomain)
        domain_entropy_score = shannon_entropy(domain)

        # Flags based on thresholds
        sub_flag = subdomain_entropy > 3.0
        domain_flag = domain_entropy_score > 3.5

        return {
            "flag": sub_flag or domain_flag, 
            "meta": {
                "subdomain": subdomain,
                "domain": domain,
                "tld": tld,
                "subdomain_entropy": subdomain_entropy,
                "domain_entropy": domain_entropy_score,
                "thresholds": {
                    "subdomain": 3.0,
                    "domain": 3.5
                },
                "flags": [
                    "high_subdomain_entropy" if sub_flag else None,
                    "high_domain_entropy" if domain_flag else None
                ]
            }
        }

    except Exception as e:
        return {"flag": False, "meta": {"error": str(e), "subdomain": None, "domain": None, "tld": None}}


def has_suspicious_tld(url):
    """
    Checks if the URL's top-level domain (TLD) is in a known list of suspicious TLDs.
    """
    try:
        _, _, _, tld = extract_domain_parts(url)
        if not tld:
            return {"flag": False, "meta": {"tld": None}}

        flag = tld in SUSPICIOUS_TLDS or tld.startswith("xn--") 
        meta = {
            "tld": tld,
            "is_suspicious": flag,
            "reason": "known_suspicious_tld" if flag and tld in SUSPICIOUS_TLDS else
                      "punycode_tld" if flag else "none"
        }

        return {"flag": flag, "meta": meta}

    except Exception as e:
        return {"flag": False, "meta": {"error": str(e), "tld": None}}


def is_ip_url(url):
    """ Detects if a URL directly uses an IP address instead of a domain name."""
    try:
        hostname = get_hostname(url)
        if not hostname:
            return {"flag": False, "meta": {"hostname": None}}

        try:
            ip_obj = ipaddress.ip_address(hostname)
            return {
                "flag": True,
                "meta": {
                    "hostname": hostname,
                    "ip_version": ip_obj.version,
                    "is_ip": True
                }
            }
        except ValueError:
            # Not an IP
            return {
                "flag": False,
                "meta": {
                    "hostname": hostname,
                    "is_ip": False
                }
            }

    except Exception as e:
        return {"flag": False, "meta": {"hostname": None, "error": str(e)}}


def too_many_subdomains(url, threshold=SUBDOMAIN_THRESHOLD):
    """
    Detects if a URL contains an excessive number of subdomains.
    Ignores trivial subdomains like 'www'.
    """
    try:
        _, _, subdomain, _ = extract_domain_parts(url)
        if not subdomain:
            return {"flag": False, "meta": {"subdomain": None, "meaningful_count": 0, "threshold": threshold, "meaningful_subdomains": []}}

        # Split subdomains and ignore trivial ones
        meaningful_parts = [s for s in subdomain.split('.') if s.lower() not in TRIVIAL_SUBDOMAINS and s]
        flag = len(meaningful_parts) > threshold

        meta = {
            "subdomain": subdomain,
            "meaningful_count": len(meaningful_parts),
            "threshold": threshold,
            "meaningful_subdomains": meaningful_parts
        }

        return {"flag": flag, "meta": meta}

    except Exception as e:
        return {"flag": False, "meta": {"error": str(e), "subdomain": None}}


def url_has_suspicious_keywords(url):
    """ Checks for suspicious keywords in domain, path, or query parameters. """
    try:
        parsed = urlparse(normalize_url(url))
        matched = set()

        domain = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parse_qs(parsed.query)

        for kw in SUSPICIOUS_URL_KEYWORDS:
            if kw in domain or kw in path:
                matched.add(kw)

            for param, values in query.items():
                if kw in param.lower():
                    matched.add(kw)
                for v in values:
                    if kw in v.lower():
                        matched.add(kw)

        flag = bool(matched)
        meta = {
            "domain": domain,
            "path": parsed.path,
            "query": {k: v for k, v in query.items()},
            "matched_keywords": sorted(matched)
        }

        return {"flag": flag, "meta": meta}

    except Exception as e:
        return {"flag": False, "meta": {"error": str(e), "domain": None}}


def is_shortened_url(url):
    """ Identifies whether a URL belongs to a known shortening service. """
    try:
        hostname = get_hostname(url)
        if not hostname:
            return {"flag": False, "meta": {"hostname": None, "shortener": None}}

        hostname_lower = hostname.lower()
        matched_shortener = None

        for shortener in SHORTENERS:
            shortener_lower = shortener.lower()
            if hostname_lower == shortener_lower:
                matched_shortener = shortener_lower
                break

        flag = matched_shortener is not None
        meta = {
            "hostname": hostname,
            "shortener": matched_shortener,
            "reason": "known_shortening_service" if flag else "none"
        }

        return {"flag": flag, "meta": meta}

    except Exception as e:
        return {"flag": False, "meta": {"hostname": None, "shortener": None, "error": str(e)}}


def has_unicode_homograph(url):
    """ Detects Unicode homoglyphs or non-ASCII characters in a URL. """
    try:
        hostname = get_hostname(url)
        if not hostname:
            return {"flag": False, "meta": {"hostname": None, "punycode": None}}

        non_ascii_chars = any(ord(c) > 127 for c in hostname)
        punycode = None

        if non_ascii_chars:
            try:
                punycode = hostname.encode("idna").decode("ascii")
            except UnicodeError:
                punycode = None

        flag = non_ascii_chars
        meta = {
            "hostname": hostname,
            "punycode": punycode,
            "reason": "unicode_homograph" if flag else "none"
        }

        return {"flag": flag, "meta": meta}

    except Exception as e:
        return {"flag": False, "meta": {"hostname": None, "punycode": None, "error": str(e)}}


def scan_with_virustotal(url, throttle = 1.0):

    vt = check_virustotal(url=url)
    status = vt.get("status")

    # Throttle only on successful requests
    if status == "ok":
        time.sleep(throttle)

    # If there was an error or not found, return clean empty stats
    if status != "ok":
        return {
            "flag": False,
            "meta": {
                "status": status,
                "stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 0,
                    "harmless": 0,
                    "resource": vt.get("meta", {}).get("resource")
                }
            },
            "flags": vt.get("flags", [])
        }

   
    stats = vt.get("meta", {})
    cleaned_stats = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "harmless": stats.get("harmless", 0),
        "resource": stats.get("resource")
    }

    
    flag = cleaned_stats["malicious"] > 0 or cleaned_stats["suspicious"] > 0


    return {
        "flag": flag,
        "meta": {
            "status": status,
            "stats": cleaned_stats
        },
        "flags": ["vt_flagged"] if flag else []

    }



def run_link_heuristics(urls, vt_throttle=1.0, include_redirects=False):
    """
    Run all link-based heuristics on a list of URLs.
   
    """
    full_results = []

    for url in urls:
        try:
            
            normalized_url = normalize_url(url.strip())

           
            heuristics = {
                "ip_based": is_ip_url(normalized_url),
                "suspicious_tld": has_suspicious_tld(normalized_url),
                "excessive_subdomains": too_many_subdomains(normalized_url),
                "shortened_url": is_shortened_url(normalized_url),
                "suspicious_keywords": url_has_suspicious_keywords(normalized_url),
                "unicode_homograph": has_unicode_homograph(normalized_url),
            }

            # --- Entropy ---
            try:
                entropy = domain_entropy(normalized_url)
            except Exception as e:
                entropy = {"flag": False, "meta": {"error": f"entropy_calc_failed: {str(e)}"}}

            # --- SSL Certificate ---
            try:
                cert_full = analyze_certificate(normalized_url)
                cert_analysis = cert_full.get("certificate_analysis", {})
                certificate = {
                    "flag": cert_analysis.get("status") == "valid" and bool(cert_analysis.get("flags")),
                    "meta": {
                        "status": cert_analysis.get("status", "unknown"),
                        "flags": cert_analysis.get("flags", []),
                        **cert_analysis.get("meta", {})  # spread all meta fields
                    }
                }
            except Exception as e:
                certificate = {"flag": False, "meta": {"error": f"cert_analysis_failed: {str(e)}"}}

            # --- Domain Age / WHOIS---
            try:
                hostname = get_hostname(normalized_url)
                domain_data = domain_age_bulk({"url_domain": hostname}) or {}
                result_data = domain_data.get("result", {})
                raw = result_data.get("url_domain", {})
                alerts = domain_data.get("alerts", [])

                alert_types = [a.get("type", "unknown") for a in alerts if isinstance(a, dict)]

                domain_age = {
                    "flag": bool(alerts),  # any alert = suspicious
                    "meta": {
                        "age_days": raw.get("age_days"),
                        "expiry_days_left": raw.get("expiry_days_left"),
                        "alerts": alert_types,
                        "error": raw.get("error")
                    }
                }
            except Exception as e:
                domain_age = {
                    "flag": False,
                    "meta": {"error": f"whois_failed: {type(e).__name__}: {str(e)}"}
                }

            # --- VirusTotal ---
            try:
                vt_raw = scan_with_virustotal(normalized_url, throttle=vt_throttle)
                virustotal = {
                    "flag": vt_raw.get("flag", False),
                    "meta": {
                        "status": vt_raw.get("status", "error"),
                        "stats": vt_raw.get("meta", {}).get("stats", {}),
                        "flags": vt_raw.get("flags", [])
                    }
                }
            except Exception as e:
                virustotal = {
                    "flag": False,
                    "meta": {"error": f"vt_scan_failed: {str(e)}"}
                }

            # --- Optional Redirect Chain ---
            redirect_chain = None
            if include_redirects:
                try:
                    redirect_chain = get_redirect_chain(normalized_url)
                except Exception as e:
                    redirect_chain = {"error": f"redirect_check_failed: {str(e)}"}

            # --- Aggregate Flags (top-level summary) ---
            aggregated_flags = set()

            # From heuristics
            for name, result in heuristics.items():
                if result.get("flag"):
                    aggregated_flags.add(name)

            # Entropy
            if entropy.get("flag"):
                aggregated_flags.add("high_entropy")

            # Certificate
            if certificate.get("flag"):
                aggregated_flags.update(certificate["meta"].get("flags", []))

            # Domain age alerts
            if domain_age.get("flag"):
                aggregated_flags.update(domain_age["meta"].get("alerts", []))

            # VirusTotal
            if virustotal.get("flag"):
                aggregated_flags.update(virustotal["meta"].get("flags", []))

            # --- Final Result for This URL ---
            result = {
                "url": url,
                "heuristics": heuristics,
                "entropy": entropy,
                "certificate": certificate,
                "domain_age": domain_age,
                "virustotal": virustotal,
                "aggregated_flags": sorted(aggregated_flags)
            }

            if redirect_chain:
                result["redirect_chain"] = redirect_chain

            full_results.append(result)

        except Exception as e:
            # Don't let one bad URL crash the whole party
            full_results.append({
                "url": url,
                "error": "unhandled_exception",
                "message": f"{type(e).__name__}: {str(e)}",
                "traceback": traceback.format_exc()
            })

    return full_results