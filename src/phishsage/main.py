import asyncio
import json
import mailparser

from phishsage.utils import get_parser
from phishsage.parsers import extract_mail_headers
from phishsage.handlers import handle_attachments, handle_headers, handle_links
from phishsage.outputs import printer


def main():
    parser = get_parser()
    args = parser.parse_args()

    # ---- ARGUMENT VALIDATION ----
    if args.mode in ("headers", "links"):
        if args.enrich and not args.heuristics:
            parser.error("--enrich requires --heuristics")


        if args.enrich == []:
            args.enrich = ["all"]


    if not args.file:
        printer.print_error("Missing input file. Use --file <path.eml>")
        return

    try:
        with open(args.file, "rb") as f:
            raw_mail_bytes = f.read()
    except Exception as e:
        printer.print_error(f"Failed to read email file: {e}")
        return

    try:
        parsed_mail = mailparser.parse_from_bytes(raw_mail_bytes)
    except Exception as e:
        printer.print_error(f"Failed to parse email: {e}")
        return

    mail_headers = extract_mail_headers(parsed_mail, raw_mail_bytes)

    output = asyncio.run(run(args, parsed_mail, mail_headers))

    if args.json and output:
        print(json.dumps(output, indent=2, sort_keys=False))


async def run(args, mail, mail_headers):

    if args.mode == "attachments":
        return await handle_attachments(args, mail)

    elif args.mode == "links":
        return await handle_links(args, mail)

    elif args.mode == "headers":
        return await handle_headers(args, mail_headers)

    else:
        printer.print_error(f"Unknown mode: {args.mode}")
        return None


if __name__ == "__main__":
    main()
