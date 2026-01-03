import json
import mailparser
from phishsage.utils.cli_args import get_parser
from phishsage.utils.header_parser import extract_mail_headers
from phishsage.utils.attachments import process_attachments
from phishsage.utils.url_helpers import get_redirect_chain,extract_links
from phishsage.heuristics.links import run_link_heuristics, scan_with_virustotal
from phishsage.heuristics.headers import run_headers_heuristics



def handle_headers(args, headers):
    if args.heuristics:
        heuristics_result = run_headers_heuristics(headers)

        if args.json:
            print(json.dumps(heuristics_result, indent=None, sort_keys=False))
        else:
            print("\n📬 Header Heuristics Analysis\n" + "=" * 60)
            print(json.dumps(heuristics_result, indent=2, sort_keys=False))
        print()


def handle_attachments(args, mail):
   
    json_output = {}

    # === 1. List attachments ===
    if args.list:
        results = process_attachments(mail, "list")

        if args.json:
            json_output["listing"] = results or {}
        else:
            print("\n📎 Attachment Listing\n" + "=" * 60)
            if not results:
                print("⚠️  No attachments found.\n")
            else:
                for filename, metadata in results.items():
                    print(f"  - {filename} ({metadata.get('size_human', 'N/A')}) "
                          f"[{metadata.get('mime_type', 'N/A')}]")
            print()

    # === 2. Extract attachments ===
    if args.extract:
        results = process_attachments(mail, action="extract", save_dir=args.extract)

        if args.json:
            json_output["extraction"] = results or {}
        else:
            print(f"\n📂 Extracting Attachments → {args.extract}\n" + "=" * 60)
            if not results:
                print("⚠️  No attachments found.\n")
            else:
                for filename, path in results.items():
                    print(f"  {filename} -> {path if path else '(not saved)'}")

    # === 3. Hash attachments ===
    if args.hash:
        hashes = process_attachments(mail, action="hash")

        if args.json:
            json_output["hashes"] = hashes or {}
        else:
            print("\n🔐 Attachment Hash Summary\n" + "=" * 60)
            if not hashes:
                print("⚠️  No attachment hashes generated.\n")
            else:
                for filename, info in hashes.items():
                    print(f"- {filename}")
                    print(f"  MD5:    {info.get('md5', 'N/A')}")
                    print(f"  SHA1:   {info.get('sha1', 'N/A')}")
                    print(f"  SHA256: {info.get('sha256', 'N/A')}")
                    print()

    # === 4. VirusTotal ===
  
    if args.scan:
        results = process_attachments(mail, action="scan")

        if args.json:
            cleaned_results = {}

            for name, info in results.items():
                vt = info.get("virustotal", {})

            vt_clean = {}

            for k, v in vt.items():
                if k == "reason":
                    continue  # ← drop reason 

                vt_clean[k] = v


            cleaned_results[name] = {
                "sha256": info.get("sha256"),
                "virustotal": vt_clean
            }
    
            json_output["virustotal_scan"] = cleaned_results or {}


        else:
            print("\n🧪 VirusTotal Scan (Attachments)\n" + "=" * 60)

            if not results:
                print("  None\n")
            else:
                for filename, info in results.items():
                    vt = info.get("virustotal", {})

                    print(f"- {filename}")
                    print(f"    SHA256: {info.get('sha256')}")

                    status = vt.get("status", "unknown")
                    print(f"    Status: {status}")

                    stats = vt.get("stats") or {}

                    print(f"    Stats:")
                    for k, v in stats.items():
                        print(f"      {k}: {v}")

                    print()

                    
    # === 5. YARA Scan (single rule) ===
    if args.yara:
        
        results = process_attachments(mail, action="yara", rules_path=args.yara, verbose=args.yara_verbose) 

        if args.json:
            json_output["yara_scan"] = results or {}

        else:
            print("\n🛡️ YARA Scan Results (Attachments)\n" + "=" * 60)

            if isinstance(results, dict) and "error" in results:
                print(f"  ⚠️  Scan failed: {results['error']}")
                print()

            elif not results:
                print("  ⚠️  No attachments scanned.\n")

            else:
                for filename, scan_result in results.items():
                    print(f"{filename}:")

                    # Scan failed
                    if "error" in scan_result:
                        print(f"  ⚠️  Scan failed: {scan_result['error']}")
                        continue

                    # Scan suceeded but no matches 
                    if not scan_result.get("flag", False):
                        print("  ✅ No rules matched")
                        continue

                    # Process Matches 
                    for m in scan_result.get("matches",[]):
                        if not m.get("flag"):
                            print(f"  ✅ Rule '{m['rule']}' did not match")
                            continue
                        
                        # Rule matched
                        print(f"  ⚠️ Rule: {m['rule']}, Namespace: {m['namespace']}")
                            
                        if m.get("rule_meta"):
                            print(f"    Rule info: {m['rule_meta']}")

                        # Verbose matched strings
                        if args.yara_verbose and m.get("strings"):
                            for s in m["strings"]:
                                print(f"    - {s['name']} @ {s['offset']}: {s['data']}")

                        print("\n")
                    
                    print()
        

    # === Final Output (JSON mode) ===
    if args.json:
        print(json.dumps(json_output, indent=None, sort_keys=False))


def handle_links(args, mail):
    html_body = mail.body or ""
    links = extract_links(html_body)

    if not links:
        msg = {"error": "No URLs found in the email"}
        if args.json:
            print(json.dumps(msg))
        else:
            print("Warning: No URLs found in the email.\n")
        return


    # Split URLs into web (http/https) and non-web
    web_urls = [u for u in links if u.lower().startswith(("http://", "https://"))]
    non_web_urls = [u for u in links if not u.lower().startswith(("http://", "https://"))]

    # Base JSON object for --json mode
    json_output = {
        "total_urls": len(links),
        "web_urls": web_urls,
        "non_web_urls": non_web_urls,
    }

    # === 1. URL Extraction ===
    if args.extract:
        if args.json:
            json_output["extraction"] = links
        else:
            print(f"\n🔍 URL Extraction — {len(links)} Found\n" + "=" * 60)
            for url in links:
                print(f"- {url}")
            print()


    # === 2. VirusTotal Scan ===
    if args.scan:
        if not args.json and non_web_urls:
            print("Info: Non-web URLs skipped:")
            for url in non_web_urls:
                print(f"  - {url}")
            print()

    
        vt_results = {url: scan_with_virustotal(url) for url in web_urls}

        if args.json:

            for url, result in vt_results.items():
                meta = result.get("meta") or {}
                stats = (meta.get("stats") or {}).copy()

                stats.pop("resource", None)

                json_output["virustotal_scan"][url]  = {
                    "meta": {
                        "status": meta["status"],
                        "stats": stats  
                    }
                }

        else:
            print("\n🧪 VirusTotal Scan (Links)\n" + "=" * 60)
            for url, result in vt_results.items():

                meta = result.get("meta") or  {}
                stats = (meta.get("stats") or  {}).copy()
                
                # Strip redundant field
                stats.pop("resource", None)

                print(f"- {url}")
                print(f"    Status: {meta.get('status', 'unknown')}")
                print(f"    Stats:")
                for k, v in stats.items():
                    print(f"      {k}: {v}")
                print()

    # === 3. Redirect Chain Analysis ===
    if args.check_redirects:
        redirect_results = []

        if not args.json:
            if non_web_urls:
                print("Info: Non-web URLs skipped:")
                for url in non_web_urls:
                    print(f"  - {url}")
                print()
            print("\n🔗 Redirect Chain Analysis\n" + "=" * 60)

        for url in web_urls:
            info = get_redirect_chain(url)

            if info.get("error"):
                error_msg = info["error"].split(":")[0]
                result = {"original_url": url, "error": error_msg}
                redirect_results.append(result)

                if not args.json:
                    print(f"Error: Redirect error for {url}: {error_msg}\n")
                continue

            clean = {
                "original_url": info["original_url"],
                "final_url": info.get("final_url"),
                "redirected": info["redirect_count"] > 0,
                "redirect_count": info["redirect_count"],
                "status_codes": info.get("status_codes", []),
                "redirect_chain": info.get("redirect_chain", [])
            }
            redirect_results.append(clean)

            if not args.json:
                print(f"URL: {info['original_url']}")
                print(f" ↳ Final URL: {info.get('final_url', 'N/A')}")
                print(f" ↳ Redirected: {'Yes' if clean['redirected'] else 'No'}")
                print(f" ↳ Redirect Count: {clean['redirect_count']}")
                print(f" ↳ Status Codes: {clean['status_codes']}")
                print(" ↳ Chain:")
                for i, u in enumerate(clean["redirect_chain"]):
                    prefix = "   └──" if i == len(clean["redirect_chain"]) - 1 else "   ├──"
                    print(f"{prefix} {u}")
                print()

        json_output["redirect_analysis"] = redirect_results

    # === 4. Phishing Heuristics ===
    if args.heuristics:
        if not args.json:
            if non_web_urls:
                print("Info: Non-web URLs skipped:")
                for url in non_web_urls:
                    print(f"  - {url}")
            print()


        heuristics = run_link_heuristics(web_urls, include_redirects=args.include_redirects)

        if args.json:
            json_output["link_heuristics"] = heuristics
        else:
            print("\n🎯 Phishing Heuristics (Links)\n" + "=" * 60)
            print(json.dumps(heuristics, indent=2, sort_keys=False))
            print()

    # === Final Output (JSON mode) ===
    if args.json:
        print(json.dumps(json_output))


def main():
    parser = get_parser()
    args = parser.parse_args()

    if not args.file:
        print("[!] Missing input file. Use --file <path.eml>")
        return

    try:
        with open(args.file,"rb") as f:
            raw_mail_bytes = f.read() # raw bytes for hash + dirty parser

    except Exception as e:
        print(f"[!] Failed to read email file: {e}")
        return

    
    try:
        mail = mailparser.parse_from_bytes(raw_mail_bytes)
    except Exception as e:
        print(f"[!] Failed to parse email: {e}")
        return

    headers = extract_mail_headers(mail, raw_mail_bytes)
   

    if args.mode == "attachment":
        handle_attachments(args, mail)
    elif args.mode == "links":
        handle_links(args, mail)
    elif args.mode == "headers":
        handle_headers(args, headers)
    else:
        print(f"[!] Unknown mode: {args.mode}")


if __name__ == "__main__":
    main()