import asyncio
import mailparser
from datetime import datetime
from phishsage.utils import get_parser
from phishsage.outputs.writer import OutputWriter
from phishsage.parsers import extract_mail_headers

from phishsage.outputs.printer import (
    print_warning,
    print_error,
    print_file_header,
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


def print_rich_output(args, filepath, output):
    if not output:
        return

    print_file_header(filepath)

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


def validate_args(args, parser):
    if args.mode in ("headers", "links"):
        if args.enrich and not args.heuristics:
            parser.error("--enrich requires --heuristics")
        if args.enrich == []:
            args.enrich = ["all"]

    if args.output and not args.json:
        parser.error("--output requires --json")

    if args.cache_dir and not args.cache:
        parser.error("--cache-dir requires --cache")


def deduplicate_files(files):
    seen = set()
    duplicates = []

    for path in files:
        if path in seen:
            duplicates.append(path)
        else:
            seen.add(path)

    if duplicates:
        print_warning(f"Duplicate files removed: {duplicates}")

    return list(dict.fromkeys(files))


def initialize_cache(args):
    if not args.cache:
        return None

    from phishsage.utils.cache import get_cache

    return get_cache(args.cache_dir)


def process_file(filepath, args, cache):
    try:
        with open(filepath, "rb") as f:
            raw_mail_bytes = f.read()
    except Exception as e:
        return {"error": f"Failed to read: {e}"}

    try:
        parsed_mail = mailparser.parse_from_bytes(raw_mail_bytes)
    except Exception as e:
        return {"error": f"Failed to parse: {e}"}

    mail_headers = extract_mail_headers(parsed_mail, raw_mail_bytes)

    return asyncio.run(run(args, parsed_mail, mail_headers, cache=cache))


def write_results(args, results):
    if args.json:
        writer = OutputWriter(args.output, default_serializer=default_serializer)
        writer.save(results)
        return

    for filepath, output in results.items():
        print_rich_output(args, filepath, output)


async def run(args, mail, mail_headers, cache=None):
    if args.mode == "attachments":
        from phishsage.handlers.attachments import handle_attachments

        return await handle_attachments(args, mail, cache=cache)

    elif args.mode == "links":
        from phishsage.handlers.links import handle_links

        return await handle_links(args, mail, cache=cache)

    elif args.mode == "headers":
        from phishsage.handlers.headers import handle_headers

        return await handle_headers(args, mail_headers, cache=cache)

    else:
        print_error(f"Unknown mode: {args.mode}")
        return None


def main():
    parser = get_parser()
    args = parser.parse_args()

    validate_args(args, parser)
    args.file = deduplicate_files(args.file)

    cache = initialize_cache(args)
    results = {}

    for filepath in args.file:
        try:
            results[filepath] = process_file(
                filepath=filepath,
                args=args,
                cache=cache,
            )
        except Exception as e:
            results[filepath] = {"error": f"Failed to process: {e}"}

    write_results(args, results)


if __name__ == "__main__":
    main()
