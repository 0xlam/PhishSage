import asyncio

from phishsage.parsers import parse_url, extract_links
from phishsage.heuristics.links import LinkHeuristics
from phishsage.outputs import printer


async def handle_links(args, mail):
    html_body = mail.body or ""
    links = extract_links(html_body)
    if not links:
        msg = {"error": "No URLs found in the email"}
        if args.json:
            return msg

        else:
            printer.print_warning("No URLs found in the email.")
            return msg

    # Split URLs into web (http/https) and non-web
    web_urls = [u for u in links if u.lower().startswith(("http://", "https://"))]
    non_web_urls = [
        u for u in links if not u.lower().startswith(("http://", "https://"))
    ]

    json_output = {}

    # --- URL Extraction ---
    if args.extract:
        json_output["urls"] = {
            "total": len(links),
            "web": web_urls,
            "non_web": non_web_urls,
        }

        if not args.json:
            printer.print_url_extraction(links, non_web_urls)

    # --- VirusTotal Scan ---
    if args.vt_scan:

        async with LinkHeuristics(vt_throttle=1.0) as checker:
            vt_tasks = [
                checker.scan_with_virustotal(parse_url(url)) for url in web_urls
            ]
            vt_results = await asyncio.gather(*vt_tasks)

        vt_dict = {}
        for url, result in zip(web_urls, vt_results):
            meta = result.get("meta") or {}
            stats = meta.get("stats") or {}
            vt_dict[url] = {
                "status": meta.get("status"),
                "stats": stats,
                "last_analysis_date": meta.get("last_analysis_date"),
                "first_submission_date": meta.get("first_submission_date"),
            }
        json_output.setdefault("analysis", {})["virustotal"] = vt_dict

        if not args.json:
            printer.print_vt_scan_links(web_urls, vt_results)

    # --- Redirect Analysis ---
    if args.check_redirects:
        redirect_results = []

        async with LinkHeuristics() as checker:

            tasks = [checker.resolve_redirect_chain(parse_url(url)) for url in web_urls]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for url, info in zip(web_urls, results):
                if isinstance(info, Exception) or info.get("error"):
                    error_msg = (
                        str(info).split(":")[0]
                        if isinstance(info, Exception)
                        else info.get("error", "unknown")
                    )
                    redirect_results.append({"original_url": url, "error": error_msg})
                    continue

                clean = {
                    "original_url": info["original_url"],
                    "final_url": info.get("final_url"),
                    "redirected": info["redirect_count"] > 0,
                    "redirect_count": info["redirect_count"],
                    "status_codes": info.get("status_codes", []),
                    "redirect_chain": info.get("redirect_chain", []),
                }
                redirect_results.append(clean)

        json_output.setdefault("analysis", {})["redirects"] = redirect_results

        if not args.json:
            printer.print_redirect_chain(redirect_results)

    # --- Phishing Heuristics ---
    if args.heuristics:

        async with LinkHeuristics(vt_throttle=1.0, enrich=args.enrich) as checker:
            heuristics = await checker.run_link_heuristics(web_urls)

        json_output.setdefault("analysis", {})["heuristics"] = heuristics

        if not args.json:
            printer.print_link_heuristics(heuristics)

    return json_output
