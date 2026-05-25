import asyncio
import os
import aiohttp

from phishsage.parsers import parse_url, extract_links
from phishsage.heuristics.links import LinkHeuristics
from phishsage.config.schemas import LinkHeuristicConfig
from phishsage.config.loader import (
    ABUSABLE_PLATFORM_DOMAINS,
    CERT_RECENT_ISSUE_DAYS_THRESHOLD,
    SSL_DEFAULT_PORT,
    ENTROPY_THRESHOLD,
    MAX_PATH_DEPTH,
    MAX_REDIRECTS,
    SHORTENERS,
    SUBDOMAIN_THRESHOLD,
    SUSPICIOUS_TLDS,
    THRESHOLD_EXPIRING,
    THRESHOLD_YOUNG,
    TRIVIAL_SUBDOMAINS,
    VIRUSTOTAL_API_KEY,
)
from phishsage.services.virustotal import VirusTotalService
from phishsage.services.whois import WhoisService
from phishsage.services.redirect import RedirectService
from phishsage.services.cert_checker import SSLService


def _build_config() -> LinkHeuristicConfig:
    return LinkHeuristicConfig(
        ENTROPY_THRESHOLD=ENTROPY_THRESHOLD,
        SUBDOMAIN_THRESHOLD=SUBDOMAIN_THRESHOLD,
        MAX_PATH_DEPTH=MAX_PATH_DEPTH,
        THRESHOLD_YOUNG=THRESHOLD_YOUNG,
        THRESHOLD_EXPIRING=THRESHOLD_EXPIRING,
        CERT_RECENT_ISSUE_DAYS_THRESHOLD=CERT_RECENT_ISSUE_DAYS_THRESHOLD,
        SUSPICIOUS_TLDS=SUSPICIOUS_TLDS,
        SHORTENERS=SHORTENERS,
        ABUSABLE_PLATFORM_DOMAINS=ABUSABLE_PLATFORM_DOMAINS,
        TRIVIAL_SUBDOMAINS=TRIVIAL_SUBDOMAINS,
    )

def _build_analyzer(enrich=None, redirect_service=None) -> LinkHeuristics:
    config = _build_config()
    enrich = enrich or []

    vt_lookup = None
    whois_lookup = None
    redirect_lookup = None
    ssl_fetcher = None

    if "virustotal" in enrich or "all" in enrich:
        vt_lookup = VirusTotalService(api_key=VIRUSTOTAL_API_KEY).lookup_url

    if "domain_age" in enrich or "all" in enrich:
        whois_lookup = WhoisService().lookup

    if redirect_service and ("redirects" in enrich or "all" in enrich):
        redirect_lookup = redirect_service.resolve

    if "certificate" in enrich or "all" in enrich:
        ssl_fetcher = SSLService(port=SSL_DEFAULT_PORT).fetch

    return LinkHeuristics(
        config=config,
        vt_lookup=vt_lookup,
        whois_lookup=whois_lookup,
        redirect_lookup=redirect_lookup,
        ssl_fetcher=ssl_fetcher,
        enrich=enrich,
    )


async def handle_links(args, mail):
    html_body = mail.body or ""
    links = extract_links(html_body)

    if not links:
        return {"error": "No URLs found in the email"}
        

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
        

    # --- VirusTotal Scan ---
    if args.vt_scan:
        analyzer = LinkHeuristics(
            config=None,
            vt_lookup=VirusTotalService(api_key=VIRUSTOTAL_API_KEY).lookup_url
            )

        vt_tasks = [analyzer.scan_virustotal(parse_url(url)) for url in web_urls]
        vt_results = await asyncio.gather(*vt_tasks)

        vt_dict = {}
        for url, result in zip(web_urls, vt_results):
            stats = result.meta.get("stats") or {}
            vt_dict[url] = {
                "status": result.meta.get("status"),
                "stats": stats,
                "last_analysis_date": result.meta.get("last_analysis_date"),
                "first_submission_date": result.meta.get("first_submission_date"),
            }

        json_output.setdefault("analysis", {})["virustotal"] = vt_dict

    # --- Redirect Analysis ---
    if args.check_redirects:
        async with aiohttp.ClientSession() as session:
            redirect_service = RedirectService(
                session=session,
                max_redirects=MAX_REDIRECTS,
            )

            analyzer = LinkHeuristics(
                config=None,
                redirect_lookup=redirect_service.resolve,
            )

            tasks = [analyzer.resolve_redirect_chain(parse_url(url)) for url in web_urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        redirect_results = []
        for url, result in zip(web_urls, results):
            if isinstance(result, Exception):
                redirect_results.append(
                    {
                        "original_url": url,
                        "error": str(result),
                    }
                )
                continue

            meta = result.meta
            final_url = meta.get("final_url")
            status_codes = meta.get("status_codes", [])

            if not final_url and not status_codes:
                redirect_results.append({
                    "original_url": meta.get("original_url", url),
                    "error": "request_failed",
                })
                continue


            redirect_results.append(
                {
                    "original_url": meta.get("original_url", url),
                    "final_url": meta.get("final_url"),
                    "redirected": meta.get("redirected", False),
                    "redirect_count": meta.get("redirect_count", 0),
                    "status_codes": meta.get("status_codes", []),
                    "redirect_chain": meta.get("redirect_chain", []),
                }
            )

        json_output.setdefault("analysis", {})["redirects"] = redirect_results
        

    # --- Phishing Heuristics ---
    if args.heuristics:
        enrich = args.enrich or []

        redirect_service = None
        if "redirects" in enrich or "all" in enrich:
            session = aiohttp.ClientSession()
            redirect_service = RedirectService(
                session=session,
                max_redirects=MAX_REDIRECTS,
            )

        try:
            analyzer = _build_analyzer(enrich=enrich, redirect_service=redirect_service)
            heuristics = await analyzer.run_link_heuristics(web_urls)
        finally:
            if redirect_service:
                await session.close()

        json_output.setdefault("analysis", {})["heuristics"] = heuristics

    return json_output
