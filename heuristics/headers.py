import re
import whois
import dns.resolver
from dateutil import parser
from datetime import datetime, timedelta, timezone
from utils.config import FREE_EMAIL_DOMAINS, DATE_RECEIVED_DRIFT_MINUTES, THRESHOLD_YOUNG, THRESHOLD_EXPIRING
from utils.header_helpers import is_domain_match, earliest_received_date


def auth_check(auth_results):
    """
    Parses SPF, DKIM, and DMARC results from Authentication-Results headers
    """

    # Normalize input safely
    if isinstance(auth_results, list):
        # Preserve each header separately for clarity and accuracy
        auth_results_text = "\n".join(str(x).strip() for x in auth_results if x)
    elif isinstance(auth_results, str):
        auth_results_text = auth_results.strip()
    else:
        auth_results_text = str(auth_results or "").strip()

    auth_results_text = auth_results_text.lower()

    # Helper to extract results (searches across all headers)
    def extract_result(field):
        match = re.search(rf"{field}\s*=\s*([\w-]+)", auth_results_text, re.IGNORECASE)
        return match.group(1).lower() if match else None

    # Extract each authentication field
    spf = extract_result("spf")
    dkim = extract_result("dkim")
    dmarc = extract_result("dmarc")

    result = {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc
    }

    alerts = []

    if spf != "pass":
        alerts.append({
            "type": "SPF_FAIL",
            "message": f"SPF check failed (spf={spf or 'missing'})"
        })

    if dkim != "pass":
        alerts.append({
            "type": "DKIM_FAIL",
            "message": f"DKIM check failed (dkim={dkim or 'missing'})"
        })

    if dmarc != "pass":
        alerts.append({
            "type": "DMARC_FAIL",
            "message": f"DMARC check failed (dmarc={dmarc or 'missing'})"
        })

    return {"result": result, "alerts": alerts}


def check_address_alignment(from_email, reply_to_email, return_path_email):
    """
    Checks if From, Reply-To, and Return-Path email addresses are aligned.
    """
    # Normalize emails
    from_email_norm = from_email.lower() if from_email else None
    reply_to_email_norm = reply_to_email.lower() if reply_to_email else None
    return_path_email_norm = return_path_email.lower() if return_path_email else None

    result = {
        "from": from_email,
        "reply": reply_to_email,
        "return": return_path_email,
        "from_vs_reply": None,       # default if data missing
        "from_vs_return": None     # default if data missing
    }

    # Check alignment
    if from_email and reply_to_email:
        result["from_vs_reply"] = from_email == reply_to_email

    if from_email and return_path_email:
        result["from_vs_return"] = from_email == return_path_email

    return result


def check_message_id_domain(from_domain, msgid_domain):
    """
    Checks if the Message-ID domain matches the From domain.
    """
    result = {
        "msgid_domain": msgid_domain,
        "from_domain": from_domain,
        "msgid_vs_from": None
    }
    alerts = []

    if not from_domain or not msgid_domain:
        result["msgid_vs_from"] = "missing"
        alerts.append({
            "type": "MISSING_MSGID_OR_FROM",
            "message": "Missing From or Message-ID domain"
        })
    else:
        match = from_domain.lower() == msgid_domain.lower()
        result["msgid_vs_from"] = "match" if match else "mismatch"
        if not match:
            alerts.append({
                "type": "MSGID_MISMATCH",
                "message": f"Message-ID domain ({msgid_domain}) does not match From domain ({from_domain})"
            })

    return {"result": result, "alerts": alerts}


def check_domain_mismatch(from_domain, return_path_domain, reply_to_domain=None):
    """Checks for mismatched domains between From, Return-Path, and optionally Reply-To."""

    result = {
        "from_domain": from_domain or None,
        "return_domain": return_path_domain or None,
        "reply_domain": reply_to_domain or None,
        "from_vs_return": None,  # default if data missing
        "from_vs_reply": None      # default if data missing
    }

    #Check From vs Return-Path
    if from_domain and return_path_domain:
        result["from_vs_return"] = is_domain_match(from_domain, return_path_domain)
    
    #Check From vs Reply-To
    if from_domain and reply_to_domain:
        result["from_vs_reply"] = is_domain_match(from_domain, reply_to_domain)

    return result


def check_free_reply_to(from_domain, reply_to_domain, return_path_domain):
    """
    Returns only structured alerts for suspicious use of free email domains.
    """
    alerts = []

    from_is_free = from_domain and from_domain.lower() in FREE_EMAIL_DOMAINS
    return_path_is_free = return_path_domain and return_path_domain.lower() in FREE_EMAIL_DOMAINS
    reply_to_is_free = reply_to_domain and reply_to_domain.lower() in FREE_EMAIL_DOMAINS

    if not reply_to_domain and not return_path_domain:
        alerts.append({
            "type": "MISSING_REPLY_RETURN",
            "message": "Missing Reply-To and Return-Path domains"
        })
    elif reply_to_domain:
        if reply_to_is_free and not (from_is_free or return_path_is_free):
            alerts.append({
                "type": "REPLY_TO_FREE",
                "message": f"Reply-To is free ({reply_to_domain}) but From/Return-Path are not"
            })
        elif reply_to_is_free and (from_is_free or return_path_is_free):
            alerts.append({
                "type": "REPLY_TO_AND_FROM_FREE",
                "message": f"Reply-To ({reply_to_domain}) and at least one of From/Return-Path are free"
            })
        elif not reply_to_is_free and reply_to_domain not in {from_domain, return_path_domain}:
            alerts.append({
                "type": "REPLY_TO_MISMATCH",
                "message": f"Reply-To ({reply_to_domain}) mismatches From/Return-Path "
                           f"({from_domain or '-'}, {return_path_domain or '-'})"
            })
    elif return_path_domain:
        if return_path_is_free and not from_is_free:
            alerts.append({
                "type": "RETURN_PATH_FREE",
                "message": f"Return-Path is free ({return_path_domain}) but From is not"
            })

    return alerts


def check_date_vs_received(date_header, first_received_header, drift_minutes=DATE_RECEIVED_DRIFT_MINUTES):
    """
    Compares Date header with the first Received header.
    """

    alerts = []

    # Parse headers
    try:
        email_date = parser.parse(date_header)
    except Exception:
        return [{"type": "MALFORMED_DATE", "message": "Malformed Date header"}]

    try:
        received_date = parser.parse(first_received_header)
    except Exception:
        return [{"type": "MALFORMED_RECEIVED", "message": "Malformed first Received header"}]

    # Normalize to UTC
    email_date = email_date.astimezone(timezone.utc) if email_date.tzinfo else email_date.replace(tzinfo=timezone.utc)
    received_date = received_date.astimezone(timezone.utc) if received_date.tzinfo else received_date.replace(tzinfo=timezone.utc)

    drift = timedelta(minutes=drift_minutes)

    if email_date > received_date + drift:
        alerts.append({
            "type": "DATE_AFTER_RECEIVED",
            "message": f"Date header ({email_date.isoformat()}) is after first Received ({received_date.isoformat()})"
        })
    elif email_date < received_date - drift:
        alerts.append({
            "type": "DATE_BEFORE_RECEIVED",
            "message": f"Date header ({email_date.isoformat()}) is before first Received ({received_date.isoformat()})"
        })

    return alerts


def domain_age_bulk(domains, threshold_young=THRESHOLD_YOUNG, threshold_expiring=THRESHOLD_EXPIRING):
    """
    Runs WHOIS lookup for multiple domains and returns age data with alerts
    for newly registered or soon-to-expire domains.
    """
    results = {}
    alerts = []
    now = datetime.now(timezone.utc)

    for label, domain in domains.items():
        if not domain:
            continue

        entry = {
            "domain": domain,
            "age_days": None,
            "expiry_days_left": None,
            "error": None
        }

        try:
            w = whois.whois(domain)

            # Handle creation date
            created = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if isinstance(created, str):
                created = parser.parse(created)

            # Handle expiration date
            expires = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            if isinstance(expires, str):
                expires = parser.parse(expires)

            # Normalize both to UTC
            if created:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                else:
                    created = created.astimezone(timezone.utc)

            if expires:
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                else:
                    expires = expires.astimezone(timezone.utc)

            # Compute metrics
            if created:
                entry["age_days"] = (now - created).days
            if expires:
                entry["expiry_days_left"] = (expires - now).days

            # Alerts
            if entry["age_days"] is not None and entry["age_days"] < threshold_young:
                alerts.append({
                    "type": "YOUNG_DOMAIN",
                    "message": f"Domain {domain} appears newly registered — only {entry['age_days']} days old."
                })

            if entry["expiry_days_left"] is not None and entry["expiry_days_left"] <= threshold_expiring:
                alerts.append({
                    "type": "EXPIRING_SOON",
                    "message": f"Domain {domain} is expiring soon — {entry['expiry_days_left']} days left."
                })

        except Exception as e:
            err_msg = str(e).splitlines()[0] if str(e) else "Unknown WHOIS error"
            entry["error"] = err_msg
            alerts.append({
                "type": "WHOIS_ERROR",
                "message": f"⚠️ Unable to retrieve WHOIS data for {domain}: {err_msg}"
            })

        results[label] = entry

    return {"result": results, "alerts": alerts}


def check_mx(domain):
    """
    Check if a domain has valid MX records.
    """
    result = {
        "has_mx": False,
        "records": None,
        "error": None
        
    }
    alerts = []

    if not domain:
        result["error"] = "No domain provided"
        alerts.append({
            "type": "MX_MISSING",
            "message": "No domain provided for MX check"
        })
        return {"result": result, "alerts": alerts}

    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted([str(r.exchange).rstrip('.') for r in answers])
        result["has_mx"] = bool(mx_records)
        result["records"] = mx_records
        if not mx_records:
            alerts.append({
                "type": "MX_MISSING",
                "message": f"Domain {domain} has no MX records; suspicious."
            })
    except dns.resolver.NXDOMAIN:
        result["error"] = f"Domain does not exist: {domain}"
        alerts.append({
            "type": "MX_MISSING",
            "message": f"Domain {domain} does not exist"
        })
    except dns.resolver.NoAnswer:
        result["error"] = f"No MX record found for domain: {domain}"
        alerts.append({
            "type": "MX_MISSING",
            "message": f"No MX record found for domain {domain}"
        })
    except dns.exception.Timeout:
        result["error"] = "DNS query timed out"
        alerts.append({
            "type": "MX_ERROR",
            "message": f"MX query timed out for domain {domain}"
        })
    except Exception as e:
        result["error"] = str(e)
        alerts.append({
            "type": "MX_ERROR",
            "message": f"MX check error for domain {domain}: {str(e)}"
        })

    return {"result": result, "alerts": alerts}


def check_spamhaus(domains):
    """
    Run Spamhaus DBL lookup for multiple domains.
    """
    results = {}
    alerts = []

    for label, domain in domains.items():
        if not domain:
            continue

        entry = {"domain": domain, "listed": False, "error": None}
        try:
            query_domain = f"{domain}.dbl.spamhaus.org"
            dns.resolver.resolve(query_domain, "A")
            entry["listed"] = True
            alerts.append({
                "type": "DOMAIN_BLACKLISTED",
                "message": f"Domain {domain} is listed on Spamhaus DBL"
            })
        except dns.resolver.NXDOMAIN:
            # Not listed — normal
            entry["listed"] = False
        except Exception as e:
            entry["error"] = str(e).splitlines()[0] if str(e) else "Unknown Spamhaus error"
            alerts.append({
                "type": "SPAMHAUS_ERROR",
                "message": f"Error checking Spamhaus for {domain}: {entry['error']}"
            })

        results[label] = entry

    return {"result": results, "alerts": alerts}


def run_headers_heuristics(headers):
    """
    Runs all email header heuristics and returns structured JSON.
    Focus: authentication, alignment, domain consistency, free domains, date sanity, MX presence, 
    and Spamhaus blocklist check.
    """

    from_email = headers.from_email
    reply_to_email = headers.reply_to_email
    return_path_email = headers.return_path_email
    from_domain = headers.from_domain
    message_id_domain = headers.message_id_domain
    return_path_domain = headers.return_path_domain
    reply_to_domain = headers.reply_to_domain
    date_header = headers.date
    first_received_header = earliest_received_date(headers.received_chain)

    # Start with an empty alerts list
    alerts = []

    # Auth check + alerts
    auth_data = auth_check(headers.auth_results)
    alerts.extend(auth_data["alerts"])

    # Message-ID domain check + alerts
    msgid_data = check_message_id_domain(from_domain, message_id_domain)
    alerts.extend(msgid_data["alerts"])

    # Free domain alerts
    free_alerts = check_free_reply_to(from_domain, reply_to_domain, return_path_domain)
    alerts.extend(free_alerts)

    # Date vs Received alerts
    date_alerts = check_date_vs_received(date_header, first_received_header)
    alerts.extend(date_alerts)

    # MX check
    mx_check = check_mx(from_domain)
    alerts.extend(mx_check["alerts"])

    # Spamhaus check (now targets return-path domain, not From)
    spamhaus_check = check_spamhaus({
            "from": from_domain,
            "reply_to": reply_to_domain,
            "return_path": return_path_domain
        })
    alerts.extend(spamhaus_check["alerts"])
    
    #domain age check
    domain_age_data = domain_age_bulk({
        "from": from_domain,
        "reply_to": reply_to_domain,
        "return_path": return_path_domain
    })
    alerts.extend(domain_age_data["alerts"])

    # Build final results
    results = {
        "mail_id": headers.mail_id,
        "auth_results": auth_data["result"],
        "alignment": check_address_alignment(from_email, reply_to_email, return_path_email),
        "message_id_check": msgid_data["result"],
        "domain_consistency": check_domain_mismatch(from_domain, return_path_domain, reply_to_domain),
        "domain_ages": domain_age_data["result"],
        "mx_check": mx_check["result"],
        "spamhaus_check": spamhaus_check["result"],
        "alerts": alerts  # merged all alerts here
    }

    return results
