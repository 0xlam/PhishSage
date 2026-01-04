import re
import whois
import dns.resolver
from dateutil import parser
from datetime import datetime, timedelta, timezone
from phishsage.config.loader import FREE_EMAIL_DOMAINS, DATE_RECEIVED_DRIFT_MINUTES, THRESHOLD_YOUNG, THRESHOLD_EXPIRING
from phishsage.utils.header_helpers import is_domain_match, earliest_received_date


def auth_check(auth_results):
    """
    Parses SPF, DKIM, and DMARC results from Authentication-Results headers.
    """

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
        alerts.append({
            "type": "SPF_MISSING",
            "message": "SPF result missing from Authentication-Results header",
        })
    elif spf != "pass":
        alerts.append({
            "type": "SPF_FAIL",
            "message": f"SPF check failed (spf={spf})",
        })

    if dkim is None:
        alerts.append({
            "type": "DKIM_MISSING",
            "message": "DKIM result missing from Authentication-Results header",
        })
    elif dkim != "pass":
        alerts.append({
            "type": "DKIM_FAIL",
            "message": f"DKIM check failed (dkim={dkim})",
        })

    if dmarc is None:
        alerts.append({
            "type": "DMARC_MISSING",
            "message": "DMARC result missing from Authentication-Results header",
        })
    elif dmarc != "pass":
        alerts.append({
            "type": "DMARC_FAIL",
            "message": f"DMARC check failed (dmarc={dmarc})",
        })

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


def check_address_alignment(from_email, reply_to_email, return_path_email):
    """
    Checks alignment between From, Reply-To, and Return-Path addresses.
    """

    alerts = []
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
            alerts.append({
                "type": "FROM_REPLY_MISMATCH",
                "message": (
                    f"From address ({from_email}) does not match "
                    f"Reply-To address ({reply_to_email})"
                )
            })

    # From vs Return-Path
    if from_norm and return_norm:
        aligned = from_norm == return_norm
        result["from_vs_return"] = aligned
        if not aligned:
            alerts.append({
                "type": "FROM_RETURN_PATH_MISMATCH",
                "message": (
                    f"From address ({from_email}) does not match "
                    f"Return-Path address ({return_path_email})"
                )
            })

    flags = bool(alerts)

    return {
        "flags": flags,
        "result": result,
        "alerts": alerts,
        "meta": meta,
    }


def check_message_id_domain(from_domain, msgid_domain):
    """
    Checks if the Message-ID domain matches the From domain.
    """

    alerts = []
    meta = {
        "from_domain": from_domain,
        "msgid_domain": msgid_domain,
    }

    result = {
        "msgid_vs_from": None,  # True / False / None (if missing)
    }

    # Missing data
    if not from_domain or not msgid_domain:
        alerts.append({
            "type": "MISSING_MSGID_OR_FROM",
            "message": "Missing From or Message-ID domain"
        })
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
        alerts.append({
            "type": "MSGID_DOMAIN_MISMATCH",
            "message": (
                f"Message-ID domain ({msgid_domain}) does not match "
                f"From domain ({from_domain})"
            )
        })

    flags = bool(alerts)

    return {
        "flags": flags,
        "result": result,
        "alerts": alerts,
        "meta": meta,
    }


def check_domain_mismatch(from_domain, return_path_domain, reply_to_domain=None):
    """
    Checks for mismatched domains between From, Return-Path, and optionally Reply-To.
    """

    alerts = []
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
            alerts.append({
                "type": "FROM_RETURN_MISMATCH",
                "message": f"From domain ({from_domain}) does not match Return-Path domain ({return_path_domain})"
            })

    # From vs Reply-To
    if from_domain and reply_to_domain:
        match = is_domain_match(from_domain, reply_to_domain)
        result["from_vs_reply"] = match
        if not match:
            alerts.append({
                "type": "FROM_REPLY_MISMATCH",
                "message": f"From domain ({from_domain}) does not match Reply-To domain ({reply_to_domain})"
            })

    flags = bool(alerts)

    return {
        "flags": flags,
        "result": result,
        "alerts": alerts,
        "meta": meta,
    }


def check_free_reply_to(from_domain, reply_to_domain, return_path_domain):
    """
    Detects use of free email domains in From, Reply-To, and Return-Path.
    """

    alerts = []
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
        result["return_path_is_free"] = return_path_domain.lower() in FREE_EMAIL_DOMAINS

    # Missing routing headers
    if not reply_to_domain and not return_path_domain:
        alerts.append({
            "type": "MISSING_REPLY_AND_RETURN_PATH",
            "message": "Both Reply-To and Return-Path headers are missing"
        })

    # Reply-To analysis
    if reply_to_domain and result["reply_to_is_free"]:
        if not result["from_is_free"] and not result["return_path_is_free"]:
            alerts.append({
                "type": "FREE_REPLY_TO_DOMAIN",
                "message": (
                    f"Reply-To domain ({reply_to_domain}) is a free email provider "
                    f"while From and Return-Path are not"
                )
            })

    # Return-Path analysis
    if return_path_domain and result["return_path_is_free"] and not result["from_is_free"]:
        alerts.append({
            "type": "FREE_RETURN_PATH_DOMAIN",
            "message": (
                f"Return-Path domain ({return_path_domain}) is a free email provider "
                f"while From is not"
            )
        })

    flags = bool(alerts)

    return {
        "flags": flags,
        "result": result,
        "alerts": alerts,
        "meta": meta,
    }


def check_date_vs_received(date_header, first_received_header, drift_minutes=DATE_RECEIVED_DRIFT_MINUTES):
    """
    Compares Date header with the first Received header.
    """
    alerts = []
    meta = {
        "date_header": date_header,
        "first_received_header": first_received_header,
        "drift_minutes": drift_minutes
    }
    result = {
        "email_date": None,
        "received_date": None,
        "drift_minutes": drift_minutes,
        "status": None  # will be 'ok', 'before', 'after', or 'malformed'
    }

    # Parse headers
    try:
        email_date = parser.parse(date_header)
        result["email_date"] = email_date.isoformat()
    except Exception:
        alerts.append({"type": "MALFORMED_DATE", "message": "Malformed Date header"})
        result["status"] = "malformed"
        return {"flags": True, "result": result, "alerts": alerts, "meta": meta}

    try:
        received_date = parser.parse(first_received_header)
        result["received_date"] = received_date.isoformat()
    except Exception:
        alerts.append({"type": "MALFORMED_RECEIVED", "message": "Malformed first Received header"})
        result["status"] = "malformed"
        return {"flags": True, "result": result, "alerts": alerts, "meta": meta}

    # Normalize to UTC
    email_date = email_date.astimezone(timezone.utc) if email_date.tzinfo else email_date.replace(tzinfo=timezone.utc)
    received_date = received_date.astimezone(timezone.utc) if received_date.tzinfo else received_date.replace(tzinfo=timezone.utc)

    drift = timedelta(minutes=drift_minutes)

    if email_date > received_date + drift:
        alerts.append({
            "type": "DATE_AFTER_RECEIVED",
            "message": f"Date header ({email_date.isoformat()}) is after first Received ({received_date.isoformat()})"
        })
        result["status"] = "after"
    elif email_date < received_date - drift:
        alerts.append({
            "type": "DATE_BEFORE_RECEIVED",
            "message": f"Date header ({email_date.isoformat()}) is before first Received ({received_date.isoformat()})"
        })
        result["status"] = "before"
    else:
        result["status"] = "ok"

    flags = bool(alerts)
    return {"flags": flags, "result": result, "alerts": alerts, "meta": meta}


def domain_age_bulk(domains, threshold_young=THRESHOLD_YOUNG, threshold_expiring=THRESHOLD_EXPIRING):
    """
    Runs WHOIS lookup for multiple domains and returns age/expiry data with alerts
    for newly registered or soon-to-expire domains.
    """
    results = {}
    alerts = []
    meta = {}
    now = datetime.now(timezone.utc)

    for label, domain in domains.items():
        if not domain:
            continue

        entry = {"age_days": None, "expiry_days_left": None, "error": None}
        domain_meta = {"domain": domain}

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

            # Normalize to UTC
            if created:
                created = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created.astimezone(timezone.utc)
            if expires:
                expires = expires.replace(tzinfo=timezone.utc) if expires.tzinfo is None else expires.astimezone(timezone.utc)

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
                    "type": "DOMAIN_EXPIRING_SOON",
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
        meta[label] = domain_meta

    flags = bool(alerts)
    return {"flags": flags, "result": results, "alerts": alerts, "meta": meta}


def check_mx(domain):
    """
    Check if a domain has valid MX records.
    """
    meta = {"domain": domain}
    result = {"has_mx": False, "records": None, "error": None}
    alerts = []

    if not domain:
        result["error"] = "No domain provided"
        alerts.append({
            "type": "MX_MISSING",
            "message": "No domain provided for MX check"
        })
        return {"flags": True, "result": result, "alerts": alerts, "meta": meta}

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

    flags = bool(alerts)
    return {"flags": flags, "result": result, "alerts": alerts, "meta": meta}


def check_spamhaus(domains):
    """
    Run Spamhaus DBL lookup for multiple domains.
    """
    results = {}
    alerts = []
    meta = {}

    for label, domain in domains.items():
        if not domain:
            continue

        entry = {"listed": False, "error": None}
        domain_meta = {"domain": domain, "query": f"{domain}.dbl.spamhaus.org"}
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
        meta[label] = domain_meta

    flags = bool(alerts)
    return {"flags": flags, "result": results, "alerts": alerts, "meta": meta}


def run_headers_heuristics(headers):
    """
    Runs all email header heuristics and aggregates results and alerts.
    """

    from_email = headers.from_email
    reply_to_email = headers.reply_to_email
    return_path_email = headers.return_path_email

    from_domain = headers.from_domain
    reply_to_domain = headers.reply_to_domain
    return_path_domain = headers.return_path_domain
    message_id_domain = headers.message_id_domain

    date_header = headers.date
    first_received_header = earliest_received_date(headers.received_chain)

    results = {}
    alerts = []

    # ---- Authentication ----
    auth_data = auth_check(headers.auth_results)
    results["auth"] = auth_data["result"]
    alerts.extend(auth_data["alerts"])

    # ---- Address alignment ----
    address_alignment_data = check_address_alignment(
        from_email, reply_to_email, return_path_email
    )
    results["address_alignment"] = address_alignment_data
    alerts.extend(address_alignment_data["alerts"])


    # ---- Message-ID domain check ----
    msgid_data = check_message_id_domain(from_domain, message_id_domain)
    results["message_id"] = msgid_data["result"]
    alerts.extend(msgid_data["alerts"])

    # ---- Domain consistency ----
    domain_consistency_data = check_domain_mismatch(
        from_domain, return_path_domain, reply_to_domain
    )
    results["domain_consistency"] = domain_consistency_data
    alerts.extend(domain_consistency_data["alerts"])

    # ---- Free domain usage ----
    free_domain_alerts = check_free_reply_to(
        from_domain, reply_to_domain, return_path_domain
    )
    alerts.extend(free_domain_alerts["alerts"])

    # ---- Date sanity ----
    date_alerts = check_date_vs_received(
        date_header, first_received_header
    )
    alerts.extend(date_alerts["alerts"])

    # ---- MX check ----
    mx_data = check_mx(from_domain)
    results["mx"] = mx_data["result"]
    alerts.extend(mx_data["alerts"])

    # ---- Spamhaus ----
    spamhaus_data = check_spamhaus({
        "from": from_domain,
        "reply_to": reply_to_domain,
        "return_path": return_path_domain,
    })
    results["spamhaus"] = spamhaus_data["result"]
    alerts.extend(spamhaus_data["alerts"])

    # ---- Domain age ----
    domain_age_data = domain_age_bulk({
        "from": from_domain,
        "reply_to": reply_to_domain,
        "return_path": return_path_domain,
    })
    results["domain_age"] = domain_age_data["result"]
    alerts.extend(domain_age_data["alerts"])

    return {
        "flags": bool(alerts),
        "results": results,
        "alerts": alerts,
        "meta": {
            "mail_id": headers.mail_id
        }
    }

