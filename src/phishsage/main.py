import asyncio
import json
import mailparser
from datetime import datetime
from phishsage.utils import get_parser
from phishsage.parsers import extract_mail_headers

from phishsage.outputs.printer import (
    print_warning,
    print_error,
    print_url_extraction,
    print_vt_scan_links,
    print_redirect_chain,
    print_link_heuristics,
    print_header_heuristics,
    print_attachment_listing,
    print_attachment_extraction,
    print_attachment_hashes,
    print_vt_scan_attachments,
    print_yara_scan_attachments,
)


def default_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


def print_rich_output(args, output):
    if not output:
        return

    if "error" in output:
        print_warning(output["error"])
        return

    if args.mode == "headers":
        print_header_heuristics(output)
        return

    if args.mode == "links":
        analysis = output.get("analysis", {})

        # URL extraction
        if args.extract and "urls" in analysis:
            print_url_extraction(analysis["urls"])

        # VirusTotal
        if args.vt_scan and "virustotal" in analysis:
            print_vt_scan_links(analysis["virustotal"])

        # Redirect chain
        if args.check_redirects and "redirects" in analysis:
            print_redirect_chain(analysis["redirects"])

        # Heuristics
        if args.heuristics and "heuristics" in analysis:
            print_link_heuristics(analysis["heuristics"])

        return

    if args.mode == "attachments":
        if args.list and "listing" in output:
            print_attachment_listing(output["listing"])

        if args.extract and "extraction" in output:
            print_attachment_extraction(output["extraction"], args.extract)

        if args.hash and "hashes" in output:
            print_attachment_hashes(output["hashes"])

        if args.vt_scan and "virustotal_scan" in output:
            print_vt_scan_attachments(output["virustotal_scan"])

        if args.yara and "yara_scan" in output:
            print_yara_scan_attachments(output["yara_scan"], verbose=args.yara_verbose)
        return


def main():
    parser = get_parser()
    args = parser.parse_args()

    # ---- ARGUMENT VALIDATION ----
    if args.mode in ("headers", "links"):
        if args.enrich and not args.heuristics:
            parser.error("--enrich requires --heuristics")
        if args.enrich == []:
            args.enrich = ["all"]

    try:
        with open(args.file, "rb") as f:
            raw_mail_bytes = f.read()
    except Exception as e:
        print_error(f"Failed to read email file: {e}")
        return

    try:
        parsed_mail = mailparser.parse_from_bytes(raw_mail_bytes)
    except Exception as e:
        print_error(f"Failed to parse email: {e}")
        return

    mail_headers = extract_mail_headers(parsed_mail, raw_mail_bytes)
    output = asyncio.run(run(args, parsed_mail, mail_headers))

    if args.json:
        if output:
            print(
                json.dumps(
                    output,
                    indent=2,
                    sort_keys=False,
                    ensure_ascii=False,
                    default=default_serializer,
                )
            )
    else:
        print_rich_output(args, output)


async def run(args, mail, mail_headers):
    if args.mode == "attachments":
        from phishsage.handlers import handle_attachments

        return await handle_attachments(args, mail)
    elif args.mode == "links":
        from phishsage.handlers import handle_links

        return await handle_links(args, mail)
    elif args.mode == "headers":
        from phishsage.handlers import handle_headers

        return await handle_headers(args, mail_headers)
    else:
        print_error(f"Unknown mode: {args.mode}")
        return None


if __name__ == "__main__":
    main()
