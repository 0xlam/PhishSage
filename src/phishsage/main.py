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
        print("\n📬 Header Heuristics Analysis\n" + "=" * 60)
        heuristics_result = run_headers_heuristics(headers)
        
        # Pretty-print JSON for readability
        print(json.dumps(heuristics_result, indent=2, sort_keys=False))


def handle_attachments(args, mail):

    if args.list:
        print("\n📎 Attachment Listing\n" + "=" * 60)
        results = process_attachments(mail, "list")
    
        if not results:
            print("⚠️  No attachments found.\n")
        else:
            for filename, metadata in results.items():
                print(f"  - {filename} ({metadata.get('size_human', 'N/A')}) [{metadata.get('mime_type', 'N/A')}]")
        print()
       
    if args.extract:
        print(f"\n📂 Extracting Attachments → {args.extract}\n" + "=" * 60)
        results = process_attachments(mail, action="extract", save_dir=args.extract)

        if not results:
            print("⚠️  No attachments found.\n")
        else:
            for filename, path in results.items():
                if path:
                    print(f"  {filename} -> {path}")
                else:
                    print(f"  {filename} (not saved)")

    if args.hash:
        print("\n🔐 Attachment Hash Summary\n" + "=" * 60)
        hashes = process_attachments(mail, action="hash")

        if not hashes:
            print("⚠️  No attachment hashes generated.\n")
        else:
            for filename, info in hashes.items():
                print(f"- {filename}")
                print(f"  MD5:    {info.get('md5', 'N/A')}")
                print(f"  SHA1:   {info.get('sha1', 'N/A')}")
                print(f"  SHA256: {info.get('sha256', 'N/A')}")
                print()  # blank line between attachments
            
    if args.scan:
        print("\n🧪 VirusTotal Scan (Attachments)\n" + "=" * 60)
        results = process_attachments(mail, action="scan")

        if not results:
            print("  None")
        else:
            for filename, info in results.items():
                print(f"{filename}:")
                print(f"  SHA256: {info['sha256']}")
            
                vt = info.get('virustotal', {})
                if not vt:
                    print("  ⚠️  No VT response")
                elif "error" in vt:
                    print(f"  ⚠️  Error: {vt['error']}")
                elif "warning" in vt:
                    print(f"  ⚠️  {vt['warning']}")
                else:
                    print(f"  🧪 VT Stats → Malicious: {vt.get('malicious', 0)}, Suspicious: {vt.get('suspicious', 0)}, Harmless: {vt.get('harmless', 0)}, Undetected: {vt.get('undetected', 0)}")
                print()  # blank line between attachments



def handle_links(args, mail):
    
    html_body = mail.body or ""
    links = extract_links(html_body)

    if not links:
        print("⚠️  No URLs found in the email.\n")
        return

    # Split URLs into web (http/https) and non-web
    web_urls = [u for u in links if u.lower().startswith(("http://", "https://"))]
    non_web_urls = [u for u in links if not u.lower().startswith(("http://", "https://"))]


    if args.extract:
        print(f"\n🔍 URL Extraction — {len(links)} Found\n" + "=" * 60)
        for url in links:
            print(f"- {url}")


    if args.scan:
        # Report non-web URLs
        if non_web_urls:
            print("ℹ️  Non-web URLs detected (skipped for scanning):")
            for url in non_web_urls:
                print(f"  - {url}")
            print()

        # Scan web URLs on VirusTotal
        print("\n🧪 VirusTotal Scan (Links)\n" + "=" * 60)
        vt_results = scan_with_virustotal(web_urls)
        for url, result in vt_results.items():
            print(f"- {url} => {result}")

      

    if args.check_redirects:

        # First, report non-web URLs
        print("ℹ️  Non-web URLs detected (skipped for redirect check):")

        for url in non_web_urls:
            print(f"  - {url}")
        print()
        
        print("\n🔗 Redirect Chain Analysis\n" + "=" * 60)
        # Now process only web URLs
        for url in web_urls:
            redirect_info = get_redirect_chain(url)

            # Handle errors
            if redirect_info.get("error"):
                error_msg = redirect_info["error"].split(":")[0]
                print(f"❌  Redirect error for {url}: {error_msg}\n")
                continue

            # Print redirect info
            print(f"URL: {redirect_info['original_url']}")
            print(f" ↳ Final URL: {redirect_info.get('final_url', 'N/A')}")
            redirected = redirect_info['redirect_count'] > 0
            print(f" ↳ Redirected: {'Yes' if redirected else 'No'}")
            print(f" ↳ Redirect Count: {redirect_info['redirect_count']}")
            print(f" ↳ Status Codes: {redirect_info.get('status_codes', [])}")

            # Print chain
            print(" ↳ Chain:")
            for idx, u in enumerate(redirect_info.get('redirect_chain', [])):
                prefix = "   └──" if idx == len(redirect_info['redirect_chain']) - 1 else "   ├──"
                print(f"{prefix} {u}")

            print()  # blank line for spacing


    if args.heuristics:
        print("\n🎯 Phishing Heuristics (Links)\n" + "=" * 60)

        # Inform about skipped non-web URLs
        for url in non_web_urls:
            print(f"[i] Non-web URL found (skipped for check): {url}")

        # Run heuristics on web URLs
        heuristics_result = run_link_heuristics(web_urls, include_redirects=args.include_redirects)

        print(json.dumps(heuristics_result, indent=2, sort_keys=False))



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
    
