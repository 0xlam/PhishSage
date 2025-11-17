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
from phishsage.config.loader import SUSPICIOUS_TLDS, SHORTENERS, SUBDOMAIN_THRESHOLD, SUSPICIOUS_URL_KEYWORDS, TRIVIAL_SUBDOMAINS
from phishsage.utils.url_helpers import *
from phishsage.utils.api_clients import check_virustotal
from phishsage.heuristics.headers import domain_age_bulk



def analyze_certificate(url, timeout = 5):

    result = {
        "certificate_analysis": {
            "status": "no_ssl",
            "issuer": None,
            "valid_from": None,
            "valid_to": None,
            "days_since_issued": None,
            "days_until_expiry": None,
            "domain_match": None,
            "flags": []
        }
    }

    try:
        # Extract domain
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return result

        # Get certificate PEM
        cert_pem = ssl.get_server_certificate((hostname, 443), timeout=timeout)
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        # Parse key info
        issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        issuer_name = issuer[0].value if issuer else "Unknown"

        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.UTC)

        # Compute days
        days_since_issued = (now - valid_from).days
        days_until_expiry = (valid_to - now).days

        # Check domain match
        domain_match = False
        try:
            # Extract SANs
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            sans = []
        cn_list = [attr.value for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
        names = set(sans + cn_list)
        if any(hostname.lower().endswith(name.lower()) for name in names):
            domain_match = True

        # Flags
        flags = []
        if days_since_issued <= 30:
            flags.append("recently_issued")
        if days_until_expiry <= 0:
            flags.append("expired")
        elif days_until_expiry <= 10:
            flags.append("expiring_soon")
        if not domain_match:
            flags.append("domain_mismatch")
        if issuer_name.lower() == hostname.lower():
            flags.append("self_signed")

        # Fill result
        result["certificate_analysis"].update({
            "status": "valid",
            "issuer": issuer_name,
            "valid_from": valid_from.strftime("%Y-%m-%d"),
            "valid_to": valid_to.strftime("%Y-%m-%d"),
            "days_since_issued": days_since_issued,
            "days_until_expiry": days_until_expiry,
            "domain_match": domain_match,
            "flags": flags
        })

    except ssl.SSLError:
        result["certificate_analysis"]["status"] = "invalid"
    except socket.timeout:
        result["certificate_analysis"]["status"] = "timeout"
    except (ConnectionRefusedError, socket.gaierror):
        result["certificate_analysis"]["status"] = "no_ssl"
    except Exception as e:
        result["certificate_analysis"]["status"] = f"error: {type(e).__name__}"

    return result


def domain_entropy(url):
    """
    Analyze entropy of the domain and subdomain components in a URL.
    """

    # Extract domain parts using your standard utility
    _, domain, subdomain, tld = extract_domain_parts(url)

    subdomain_entropy = shannon_entropy(subdomain)
    domain_entropy_score = shannon_entropy(domain)

    flags = []

    # Heuristic flags — tweak thresholds as needed
    if subdomain_entropy > 3.0:
        flags.append("high_subdomain_entropy")
    if domain_entropy_score > 3.5:
        flags.append("high_domain_entropy")

    return {
        "subdomain": subdomain or "",
        "domain": domain or "",
        "tld": tld or "",
        "subdomain_entropy": subdomain_entropy,
        "domain_entropy": domain_entropy_score,
        "flags": flags
    }


def has_suspicious_tld(url):
    """Checks if the URL's top-level domain (TLD) is in a known list of suspicious TLDs."""
    _, _, _, tld = extract_domain_parts(url) 
    if tld in SUSPICIOUS_TLDS or tld.startswith("xn--"):
        return {"flag": True, "tld": tld}
    return {"flag": False}


def is_ip_url(url):
    """Detects if a URL directly uses an IP address instead of a domain name."""
    try:
        ipaddress.ip_address(get_hostname(url))
        return {"flag": True}
    except Exception:
        return {"flag": False}


def too_many_subdomains(url, threshold=SUBDOMAIN_THRESHOLD):
    """
    Detects if a URL contains an excessive number of subdomains
    Ignores trivial subdomains like 'www'
    """
    _, _, subdomain, _ = extract_domain_parts(url)
    
    if not subdomain:
        return {"flag": False} 
    
    # Split subdomains and ignore trivial ones
    meaningful_parts = [s for s in subdomain.split('.') if s.lower() not in TRIVIAL_SUBDOMAINS and s]
    
    return {"flag": len(meaningful_parts) > threshold}


def url_has_suspicious_keywords(url):
    """Checks for suspicious keywords in domain, path, or query parameters."""
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
        
        if matched:
            return {
                "flag": True,
                "matched_keywords": sorted(matched),
            }
        else:
            return {
                "flag": False
            }


    except Exception:
        return {"flag": False}


def is_shortened_url(url):
    """Identifies whether a URL belongs to a known shortening service"""
    hostname = get_hostname(url).lower()
    
    for shortener in SHORTENERS:
        shortener = shortener.lower()
        # match exact or subdomain
        if hostname == shortener or hostname.endswith("." + shortener):
            return {
                "flag": True,
                "shortener": shortener,
            }

    return {"flag": False}


def has_unicode_homograph(url):
    """Detects Unicode homoglyphs or non-ASCII characters in a URL."""
    try:
        hostname = get_hostname(url)
        if not hostname:
            return {"flag": False}

        # Check if hostname contains non-ASCII characters
        if any(ord(c) > 127 for c in hostname):
            try:
                punycode = hostname.encode("idna").decode("ascii")
                return {"flag": True, "domain": hostname, "punycode": punycode}
            except UnicodeError:
                return {"flag": True, "domain": hostname, "punycode": None}

        return {"flag": False}

    except Exception:
        return {"flag": False}


def scan_with_virustotal(url, throttle=1.0):
    result = check_virustotal(url=url)

    # Simplified handling
    if not isinstance(result, dict):
        return {"error": "Invalid VT response format"}

    if "error" in result:
        err_msg = result["error"].lower()
        if "404" in err_msg:
            output = {"status": "not_found", "message": "URL not found in VirusTotal database"}
        elif "401" in err_msg or "unauthorized" in err_msg:
            output = {"status": "auth_error", "message": "Invalid or missing API key"}
        elif "429" in err_msg or "rate" in err_msg:
            output = {"status": "rate_limited", "message": "API rate limit exceeded"}
        else:
            output = {"status": "error", "message": result["error"]}
    else:
        output = {"status": "ok", "data": result}

    # Only throttle if request was actually made successfully
    if output["status"] != "auth_error":
        time.sleep(throttle)

    return output



def run_link_heuristics(urls, vt_throttle=1.0, include_redirects=False):
    full_results = []

    for url in urls:
        try:
            # --- Heuristics ---
            heuristics = {
                "ip_based": is_ip_url(url),
                "suspicious_tld": has_suspicious_tld(url),
                "excessive_subdomains": too_many_subdomains(url),
                "shortened": is_shortened_url(url),
                "suspicious_keywords": url_has_suspicious_keywords(url),
                "unicode_homograph": has_unicode_homograph(url)
            }


            # --- Entropy ---
            try:
                entropy = domain_entropy(url)
            except Exception as e:
                entropy = {"error": f"entropy_failed: {type(e).__name__}"}

            # --- SSL Certificate ---
            try:
                certificate = analyze_certificate(url)
                # Normalize shape: flatten “certificate_analysis”
                if "certificate_analysis" in certificate:
                    certificate = certificate["certificate_analysis"]
            except Exception as e:
                certificate = {"status": "error", "message": str(e)}


           
            # --- Domain WHOIS ---
            try:
                domain_data = domain_age_bulk({"url_domain": get_hostname(url)}) or {}
                result_data = domain_data.get("result") or {}
                domain_age_result = result_data.get("url_domain") or {}

                alerts = domain_data.get("alerts") or []

                if alerts:
                    domain_age_result["flags"] = [
                        a.get("type", "unknown")
                        for a in alerts
                        if isinstance(a, dict)
                    ]

            except Exception as e:
                domain_age_result = {
                    "error": f"whois_failed: {type(e).__name__}",
                    "details": str(e)
                }


            # --- VirusTotal ---
            try:
                vt_result = scan_with_virustotal(url, throttle=vt_throttle)
                if vt_result.get("status") == "error":
                    vt_result["message"] = "VirusTotal lookup failed"
            except Exception as e:
                vt_result = {"status": "error", "message": f"VT_failed: {type(e).__name__}"}

            
            
            # --- Redirect Chain (optional) ---
            redirect_info = None
            if include_redirects:
                try:
                    redirect_info = get_redirect_chain(url)
                except Exception as e:
                    redirect_info = {"error": f"redirect_check_failed: {type(e).__name__}"}

        
            # --- Aggregate risk flags ---
            flags = []

            # Heuristics
            for key in ["ip_based", "suspicious_tld", "excessive_subdomains", "shortened", "suspicious_keywords", "unicode_homograph"]:
                h = heuristics.get(key)
                if isinstance(h, dict) and h.get("flag"):
                    flags.append(key)

            # Certificate flags
            if certificate.get("flags"):
                flags.extend(certificate["flags"])

            # Domain age flags
            if domain_age_result.get("flags"):
                flags.extend(domain_age_result["flags"])
            
        
            # --- Combine all ---
            combined = {
                "url": url,
                "heuristics": heuristics,
                "entropy": entropy,
                "certificate": certificate,
                "domain_age": domain_age_result,
                "virustotal": vt_result,
            }

            if redirect_info:
                combined["redirect_chain"] = redirect_info

            combined["flags"] = sorted(set(flags)),

            full_results.append(combined)

        except Exception as e:
            traceback.print_exc()
            full_results.append({
                "url": url,
                "error": f"unhandled_error: {type(e).__name__}",
                "message": str(e)
            })

    return full_results

