# outputs/printer.py

import json
from datetime import datetime

WIDTH = 60


# =====================
# Headers
# =====================
def print_header_heuristics(results):

    lines = []
    lines.append("\n🛡️  Header Heuristics Analysis")
    lines.append("=" * 60)

    meta = results.get("meta", {})
    mail_id = meta.get("mail_id", "N/A")
    lines.append(f"📧 Mail ID: {mail_id}\n")


    heuristics_data = results.get("results", {})

    flags = results.get("flags", False)
    alerts = results.get("alerts", [])

    def status_icon(val):
        if val is True:
            return "✅"
        if val is False:
            return "❌"
        return "⚠️"

    # Authentication (SPF, DKIM, DMARC)
    auth = heuristics_data.get("auth")
    if auth:
        lines.append("📧 Authentication Results:")
        for proto in ("spf", "dkim", "dmarc"):
            data = auth.get(proto, {})
            val = data.get("value")
            passed = data.get("passed")
            lines.append(f"  • {proto.upper()}: {status_icon(passed)} (value: {val})")
        lines.append("")

    #  Address alignment (From vs Reply‑To / Return‑Path)
    addr_align = heuristics_data.get("address_alignment")
    if addr_align:
        lines.append("📧 Address Alignment:")
        res = addr_align.get("result", {})
        from_reply = res.get("from_vs_reply")
        from_return = res.get("from_vs_return")
        if from_reply is not None:
            lines.append(f"  • From vs Reply‑To: {status_icon(from_reply)}")
        if from_return is not None:
            lines.append(f"  • From vs Return‑Path: {status_icon(from_return)}")
        lines.append("")

    #  Message‑ID domain vs From domain
    msgid = heuristics_data.get("message_id")
    if msgid:
        lines.append("📧 Message‑ID Domain:")
        match = msgid.get("msgid_vs_from")
        if match is not None:
            lines.append(
                f"  • Message‑ID domain matches From domain? {status_icon(match)}"
            )
        lines.append("")

    #  Domain consistency
    domain_cons = heuristics_data.get("domain_consistency")
    if domain_cons:
        lines.append("📧 Domain Consistency:")
        res = domain_cons.get("result", {})
        from_return = res.get("from_vs_return")
        from_reply = res.get("from_vs_reply")
        if from_return is not None:
            lines.append(f"  • From vs Return‑Path domain: {status_icon(from_return)}")
        if from_reply is not None:
            lines.append(f"  • From vs Reply‑To domain: {status_icon(from_reply)}")
        lines.append("")

    #  MX records
    mx = heuristics_data.get("mx")
    if mx:
        lines.append("📧 MX Records:")
        has_mx = mx.get("has_mx", False)
        records = mx.get("records")
        error = mx.get("error")
        if error:
            lines.append(f"  • MX check error: {error} ❌")
        else:
            lines.append(f"  • Has MX records: {status_icon(has_mx)}")
            if records:
                lines.append(f"    Records: {', '.join(records)}")
        lines.append("")

    #  Spamhaus DBL
    spamhaus = heuristics_data.get("spamhaus")
    if spamhaus:
        lines.append("📧 Spamhaus DBL:")
        for label, data in spamhaus.items():
            listed = data.get("listed", False)
            error = data.get("error")
            if error:
                lines.append(f"  • {label.capitalize()}: Error – {error} ❌")
            else:
                status = "Listed ⚠️" if listed else "Not listed ✅"
                lines.append(f"  • {label.capitalize()}: {status}")
        lines.append("")

    # Domain age
    domain_age = heuristics_data.get("domain_age")
    if domain_age:
        lines.append("📧 Domain Age:")
        for label, data in domain_age.items():
            age = data.get("age_days")
            expiry = data.get("expiry_days_left")
            error = data.get("error")
            if error:
                lines.append(f"  • {label.capitalize()}: Error – {error} ❌")
            else:
                parts = []
                if age is not None:
                    parts.append(f"age: {age} days")
                if expiry is not None:
                    parts.append(f"expires in {expiry} days")
                if parts:
                    lines.append(f"  • {label.capitalize()}: {', '.join(parts)}")
                else:
                    lines.append(f"  • {label.capitalize()}: No age information")
        lines.append("")

    # Alerts
    if alerts:
        lines.append(f"⚠️ Alerts ({len(alerts)}):")
        for alert in alerts:
            typ = alert.get("type", "UNKNOWN")
            msg = alert.get("message", "")
            lines.append(f"  • [{typ}] {msg}")
        lines.append("")
    else:
        lines.append("✅ No alerts.\n")

    print("\n".join(lines))


# =====================
# Attachments
# =====================
def print_attachment_listing(results):
    if not results:
        print("\n📎 Attachment Listing\n" + "=" * WIDTH)
        print("  ⚠️  No attachments found.\n")
        return

    lines = ["\n📎 Attachment Listing", "=" * WIDTH]
    for filename, metadata in results.items():
        size = metadata.get("size_human", "N/A")
        mime = metadata.get("mime_type", "N/A")
        lines.append(f"  • {filename} ({size}) [{mime}]")
    lines.append("=" * WIDTH)
    lines.append(f"📊 Total attachments: {len(results)}")
    lines.append("=" * WIDTH)
    print("\n".join(lines))


def print_attachment_extraction(results, save_dir):
    if not results:
        print(f"\n📂 Extracting Attachments → {save_dir}\n" + "=" * WIDTH)
        print("  ⚠️  No attachments found.\n")
        return

    lines = [f"\n📂 Extracting Attachments → {save_dir}", "=" * WIDTH]
    saved_count = 0
    for filename, path in results.items():
        if path:
            lines.append(f"  ✅ {filename} -> {path}")
            saved_count += 1
        else:
            lines.append(f"  ⚠️  {filename} -> (not saved)")
    lines.append("=" * WIDTH)
    lines.append(f"📊 Saved {saved_count} of {len(results)} attachments")
    lines.append("=" * WIDTH)
    print("\n".join(lines))


def print_attachment_hashes(hashes):
    if not hashes:
        print("\n🔐 Attachment Hash Summary\n" + "=" * WIDTH)
        print("  ⚠️  No attachment hashes generated.\n")
        return

    lines = ["\n🔐 Attachment Hash Summary", "=" * WIDTH]
    for filename, info in hashes.items():
        lines.append(f"📄 {filename}")
        lines.append(f"    MD5:    {info.get('md5', 'N/A')}")
        lines.append(f"    SHA1:   {info.get('sha1', 'N/A')}")
        lines.append(f"    SHA256: {info.get('sha256', 'N/A')}")
        lines.append("")
    lines.append("=" * WIDTH)
    lines.append(f"📊 Total files hashed: {len(hashes)}")
    lines.append("=" * WIDTH)
    print("\n".join(lines))


def print_vt_scan_attachments(results):

    if not results:
        print("\n🧪 VirusTotal Scan (Attachments)")
        print("=" * WIDTH)
        print("  ⚠️  No attachments scanned.")
        return

    lines = []
    lines.append("\n🧪 VirusTotal Scan (Attachments)")
    lines.append("=" * WIDTH)

    total_files = 0
    malicious_count = 0
    suspicious_count = 0
    undetected_count = 0

    for filename, info in results.items():
        total_files += 1
        lines.append(f"\n📄 {filename}:")

        sha256 = info.get("sha256", "N/A")
        lines.append(f"    🔑 SHA256: {sha256}")

        vt = info.get("virustotal", {})
        status = vt.get("status", "unknown")
        reason = vt.get("reason")
        lines.append(f"    📊 Status: {status}")
        if reason and status != "ok":
            lines.append(f"    ⚠️  Reason: {reason}")

        stats = vt.get("stats", {})
        if not stats:
            lines.append("    ⚠️  No scan statistics available.")
        else:

            analysis_stats = stats.get("last_analysis_stats", {})
            if analysis_stats:
                malicious = analysis_stats.get("malicious", 0)
                suspicious = analysis_stats.get("suspicious", 0)
                undetected = analysis_stats.get("undetected", 0)
                harmless = analysis_stats.get("harmless", 0)

                malicious_count += malicious
                suspicious_count += suspicious
                undetected_count += undetected

                lines.append("    📈 Detection Stats:")
                lines.append(f"      🔴 Malicious:   {malicious}")
                lines.append(f"      🟠 Suspicious:  {suspicious}")
                lines.append(f"      🟢 Undetected:  {undetected}")
                lines.append(f"      ⚪ Harmless:    {harmless}")
            else:
                lines.append("    ⚠️  No detailed detection stats.")

            last_scan = stats.get("last_analysis_date")
            if last_scan:
                dt = datetime.fromisoformat(last_scan)
                date_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                lines.append(f"    🕒 Last Scan: {date_str}")

            first_seen = stats.get("first_submission_date")
            if first_seen:
                dt = datetime.fromisoformat(first_seen)
                date_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                lines.append(f"    📅 First Seen: {date_str}")

    lines.append("\n" + "=" * WIDTH)
    lines.append(f"📊 Summary: {total_files} file(s) scanned")
    if total_files > 0:
        lines.append(f"   🔴 Total malicious detections:  {malicious_count}")
        lines.append(f"   🟠 Total suspicious detections: {suspicious_count}")
        lines.append(f"   🟢 Total undetected: {undetected_count}")

    lines.append("=" * WIDTH)

    print("\n".join(lines))


def print_yara_scan_attachments(results, verbose=False):

    if isinstance(results, dict) and "error" in results:
        print("\n🛡️  YARA Scan Results (Attachments)")
        print("=" * WIDTH)
        print(f"  ❌ Scan failed: {results['error']}")
        return

    if not results:
        print("\n🛡️  YARA Scan Results (Attachments)")
        print("=" * WIDTH)
        print("  ⚠️  No attachments scanned.")
        return

    lines = []
    lines.append("\n🛡️  YARA Scan Results (Attachments)")
    lines.append("=" * WIDTH)

    total_files = 0
    matched_files = 0
    error_files = 0

    for filename, scan_result in results.items():
        total_files += 1
        lines.append(f"\n📄 {filename}:")

        if "error" in scan_result:
            error_files += 1
            lines.append(f"  ❌ Scan failed: {scan_result['error']}")
            continue

        if not scan_result.get("flag", False):
            lines.append("  ✅ No rules matched")
            continue

        matched_files += 1
        matches = scan_result.get("matches", [])
        lines.append(f"  ⚠️  Matched {len(matches)} rule(s):")

        for idx, match in enumerate(matches, start=1):
            rule = match.get("rule", "unknown_rule")
            namespace = match.get("namespace", "?")
            meta = match.get("rule_meta", {})

            lines.append(f"    {idx}. Rule: {rule}  (namespace: {namespace})")

            if meta:
                severity = meta.get("severity", meta.get("Severity", "unknown"))

                if severity.lower() == "high":
                    sev_icon = "🔴"
                elif severity.lower() == "medium":
                    sev_icon = "🟠"
                elif severity.lower() == "low":
                    sev_icon = "🟢"
                else:
                    sev_icon = "⚪"
                lines.append(f"       {sev_icon} Meta: {meta}")

            # Matched strings (verbose only)
            if verbose and match.get("strings"):
                lines.append("       Strings:")
                for s in match["strings"]:
                    name = s.get("name", "?")
                    offset = s.get("offset", "?")
                    data_hex = s.get("data", "")

                    try:
                        data_bytes = bytes.fromhex(data_hex)
                        ascii_repr = data_bytes.decode("ascii", errors="replace")

                        if all(32 <= c < 127 for c in data_bytes):
                            data_disp = f" (ASCII: {ascii_repr})"
                        else:
                            data_disp = ""
                    except Exception:
                        data_disp = ""

                    lines.append(f"         • {name} @ {offset}: {data_hex}{data_disp}")

    # Summary footer
    lines.append("\n" + "=" * WIDTH)
    lines.append(
        f"📊 Summary: {total_files} file(s) scanned, "
        f"{matched_files} matched, {error_files} error(s)."
    )
    lines.append("=" * WIDTH)

    print("\n".join(lines))


# =====================
# Links
# =====================
def print_url_extraction(links, non_web):

    lines = ["\n🔍 URL Extraction", "=" * WIDTH]
    lines.append(f"🌐 Web URLs found: {len(links)}")
    for url in links:
        lines.append(f"  • {url}")

    if non_web:
        lines.append(f"\n⚠️  Non‑web URLs skipped: {len(non_web)}")
        for url in non_web:
            lines.append(f"  • {url}")

    lines.append("=" * WIDTH)
    lines.append(
        f"📊 Total URLs processed: {len(links) + len(non_web) if non_web else len(links)}"
    )
    lines.append("=" * WIDTH)
    print("\n".join(lines))


def print_vt_scan_links(web_urls, vt_results):
    if not web_urls or not vt_results:
        print("\n🧪 VirusTotal Scan (Links)\n" + "=" * WIDTH)
        print("  ⚠️  No URLs to scan.")
        return

    lines = ["\n🧪 VirusTotal Scan (Links)", "=" * WIDTH]
    total_flagged = 0
    total_errors = 0

    for url, result in zip(web_urls, vt_results):
        lines.append(f"\n🔗 {url}")
        flags = result.get("flags", False)
        reasons = result.get("reason", [])
        meta = result.get("meta", {})
        status = meta.get("status", "unknown")

        if flags:
            total_flagged += 1
            lines.append(f"  ⚠️  Flagged: {', '.join(reasons) if reasons else 'yes'}")
        else:
            lines.append(f"  ✅ Not flagged")

        lines.append(f"  📊 Status: {status}")

        if status == "exception" and "error" in meta:
            lines.append(f"  ❌ Error: {meta['error']}")
            total_errors += 1

        stats = meta.get("stats")
        if stats and isinstance(stats, dict):
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)

            lines.append("  📈 Detection Stats:")
            lines.append(f"      🔴 Malicious:   {malicious}")
            lines.append(f"      🟠 Suspicious:  {suspicious}")
            lines.append(f"      🟢 Undetected:  {undetected}")
            lines.append(f"      ⚪ Harmless:    {harmless}")

            last_scan = meta.get("last_analysis_date")
            if last_scan:
                dt = datetime.fromisoformat(last_scan)
                date_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                lines.append(f"    🕒 Last Scan: {date_str}")

            first_seen = stats.get("first_submission_date")
            if first_seen:
                dt = datetime.fromisoformat(first_seen)
                date_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                lines.append(f"    📅 First Seen: {date_str}")

        else:
            lines.append("  ⚠️  No detailed stats available.")

    lines.append("\n" + "=" * WIDTH)
    lines.append(f"📊 Summary: {len(web_urls)} URL(s) scanned")
    lines.append(f"   ⚠️  Flagged: {total_flagged}")
    lines.append(f"   ❌ Errors:  {total_errors}")
    lines.append("=" * WIDTH)

    print("\n".join(lines))


def print_redirect_chain(results):

    if not results:
        print("\n🔗 Redirect Chain Analysis\n" + "=" * 50)
        print("  ⚠️  No redirect data.\n")
        return

    lines = ["\n🔗 Redirect Chain Analysis", "=" * 50]
    total = len(results)
    error_count = 0
    redirected_count = 0

    for info in results:
        if "error" in info:
            error_count += 1
            lines.append(f"\n❌ {info['original_url']}")
            lines.append(f"    Error: {info['error']}")
            continue

        redirected = info.get("redirected", False)
        if redirected:
            redirected_count += 1

        lines.append(f"\n🔗 {info['original_url']}")
        lines.append(f"  ↳ Final URL: {info.get('final_url', 'N/A')}")
        lines.append(f"  ↳ Redirected: {'✅ Yes' if redirected else '❌ No'}")
        lines.append(f"  ↳ Redirect Count: {info.get('redirect_count', 0)}")
        lines.append(f"  ↳ Status Codes: {info.get('status_codes', [])}")

        chain = info.get("redirect_chain", [])
        if chain:
            lines.append("  ↳ Chain:")
            for i, url in enumerate(chain):
                prefix = "     └── " if i == len(chain) - 1 else "     ├── "
                lines.append(f"{prefix}{url}")
        else:
            lines.append("  ↳ Chain: (none)")

    # Summary footer
    lines.append("\n" + "=" * 50)
    lines.append(f"📊 Summary: {total} URL(s) analyzed")
    lines.append(f"   🔀 Redirected: {redirected_count}")
    lines.append(f"   ❌ Errors:     {error_count}")
    lines.append("=" * 50)

    print("\n".join(lines))


def print_link_heuristics(results: list) -> None:

    if not results:
        print("\n🔗 Link Heuristics Analysis\n" + "=" * 60)
        print("  ⚠️  No URLs analyzed.\n")
        return

    lines = []
    lines.append("\n🔗 Link Heuristics Analysis")
    lines.append("=" * 60)

    total_urls = len(results)
    flagged_urls = 0

    for idx, res in enumerate(results, 1):
        url = res.get("url", "N/A")
        lines.append(f"\n{idx}. 🔗 {url}")

        # Aggregated flags
        agg_flags = res.get("aggregated_flags", [])
        if agg_flags:
            flagged_urls += 1
            lines.append(f"   ⚠️  Flags: {', '.join(agg_flags)}")
        else:
            lines.append(f"   ✅ No flags")

        # --- Heuristics (URL-based) ---
        heuristics = res.get("heuristics", {})
        if heuristics:
            lines.append("   📋 URL Heuristics:")

            def bool_icon(val):
                return "✅" if val else "❌"

            items = [
                ("IP-based", heuristics.get("ip_based", {}).get("flags", False)),
                (
                    "Suspicious TLD",
                    heuristics.get("suspicious_tld", {}).get("flags", False),
                ),
                (
                    "Excessive subdomains",
                    heuristics.get("excessive_subdomains", {}).get("flags", False),
                ),
                (
                    "Shortened URL",
                    heuristics.get("shortened_url", {}).get("flags", False),
                ),
                (
                    "Numeric domain",
                    heuristics.get("numeric_domain", {}).get("flags", False),
                ),
                (
                    "Excessive path",
                    heuristics.get("excessive_path", {}).get("flags", False),
                ),
                (
                    "Abusable platform",
                    heuristics.get("abusable_platform", {}).get("flags", False),
                ),
            ]
            for label, flag in items:
                lines.append(f"     {bool_icon(flag)} {label}")

        # --- Entropy ---
        entropy = res.get("entropy", {})
        if entropy:
            lines.append("   📊 Entropy:")
            meta = entropy.get("meta", {})
            sub_ent = meta.get("subdomain_entropy")
            dom_ent = meta.get("domain_entropy")
            if sub_ent is not None:
                lines.append(f"     Subdomain entropy: {sub_ent:.3f}")
            if dom_ent is not None:
                lines.append(f"     Domain entropy: {dom_ent:.3f}")
            if entropy.get("flags"):
                reasons = entropy.get("reason", [])
                lines.append(f"     ⚠️  {', '.join(reasons)}")

        # --- VirusTotal (if present) ---
        vt = res.get("virustotal")
        if vt:
            lines.append("   🧪 VirusTotal:")
            meta = vt.get("meta", {})
            status = meta.get("status", "unknown")
            lines.append(f"     Status: {status}")
            stats = meta.get("stats")
            if stats and isinstance(stats, dict):
                lines.append("     Detection Stats:")
                lines.append(f"       🔴 Malicious:   {stats.get('malicious', 0)}")
                lines.append(f"       🟠 Suspicious:  {stats.get('suspicious', 0)}")
                lines.append(f"       🟢 Undetected:  {stats.get('undetected', 0)}")
                lines.append(f"       ⚪ Harmless:    {stats.get('harmless', 0)}")
            if vt.get("flags"):
                lines.append(f"     ⚠️  Reasons: {', '.join(vt.get('reason', []))}")

        # --- Domain Age (if present) ---
        domain_age = res.get("domain_age")
        if domain_age:
            lines.append("   📅 Domain Age:")
            meta = domain_age.get("meta", {})
            age = meta.get("age_days")
            expiry = meta.get("expiry_days_left")
            error = meta.get("error")
            if error:
                lines.append(f"     ⚠️  WHOIS error: {error}")
            else:
                if age is not None:
                    lines.append(f"     Age: {age} days")
                if expiry is not None:
                    lines.append(f"     Expires in: {expiry} days")
            if domain_age.get("flags"):
                reasons = domain_age.get("reason", [])
                lines.append(f"     ⚠️  {', '.join(reasons)}")

        # --- Certificate (if present) ---
        cert = res.get("certificate")
        if cert:
            lines.append("   🔒 Certificate:")
            meta = cert.get("meta", {})
            hostname = meta.get("hostname", "N/A")
            issuer = meta.get("issuer_cn")
            subject = meta.get("subject_cn")
            valid_from = meta.get("valid_from")
            valid_to = meta.get("valid_to")
            days_issued = meta.get("days_since_issued")
            days_expiry = meta.get("days_until_expiry")
            error = meta.get("error")
            if error:
                lines.append(f"     ⚠️  Error: {error}")
            else:
                lines.append(f"     Hostname: {hostname}")
                if issuer:
                    lines.append(f"     Issuer: {issuer}")
                if subject:
                    lines.append(f"     Subject: {subject}")
                if valid_from:
                    lines.append(f"     Valid from: {valid_from}")
                if valid_to:
                    lines.append(f"     Valid to: {valid_to}")
                if days_issued is not None:
                    lines.append(f"     Days since issued: {days_issued}")
                if days_expiry is not None:
                    lines.append(f"     Days until expiry: {days_expiry}")
            if cert.get("flags"):
                reasons = cert.get("reason", [])
                lines.append(f"     ⚠️  {', '.join(reasons)}")

        # --- Redirect Chain (if present) ---
        redirect = res.get("redirect_chain")
        if redirect:
            lines.append("   🔀 Redirect Chain:")
            if "error" in redirect:
                lines.append(f"     ⚠️  Error: {redirect['error']}")
            else:
                original = redirect.get("original_url", "N/A")
                final = redirect.get("final_url", "N/A")
                redirected = redirect.get("redirected", False)
                count = redirect.get("redirect_count", 0)
                lines.append(f"     Original: {original}")
                lines.append(f"     Final: {final}")
                lines.append(
                    f"     Redirected: {'✅ Yes' if redirected else '❌ No'} (count: {count})"
                )
                chain = redirect.get("redirect_chain", [])
                if chain:
                    lines.append("     Chain:")
                    for i, step in enumerate(chain):
                        prefix = "       └── " if i == len(chain) - 1 else "       ├── "
                        lines.append(f"{prefix}{step}")

    lines.append("\n" + "=" * 60)
    lines.append(f"📊 Summary: {total_urls} URL(s) analyzed, {flagged_urls} flagged")
    lines.append("=" * 60)

    print("\n".join(lines))


# =====================
# Warnings / Errors
# =====================
def print_warning(message):
    print(f"Warning: {message}")


def print_error(message):
    print(f"[!] {message}")
