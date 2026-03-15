import json

from phishsage.heuristics import HeaderHeuristics
from phishsage.outputs import printer


async def handle_headers(args, headers):
    if args.heuristics:

        checker = HeaderHeuristics()
        heuristics_result = await checker.run_headers_heuristics(
            headers, enrich=args.enrich
        )

        if args.json:
            return heuristics_result

        else:
            printer.print_header_heuristics(heuristics_result)
            return heuristics_result
