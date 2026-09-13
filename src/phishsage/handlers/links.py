from functools import partial
import asyncio
import aiohttp

from phishsage.parsers import parse_url, extract_links
from phishsage.heuristics.links import LinkHeuristics
from phishsage.config.schemas import LinkHeuristicConfig
from phishsage.config.object import Config


def _build_config(config: Config) -> LinkHeuristicConfig:
    return LinkHeuristicConfig(
        ENTROPY_THRESHOLD=config.entropy_threshold,
        SUBDOMAIN_THRESHOLD=config.subdomain_threshold,
        MAX_PATH_DEPTH=config.max_path_depth,
        THRESHOLD_YOUNG=config.threshold_young,
        THRESHOLD_EXPIRING=config.threshold_expiring,
        CERT_RECENT_ISSUE_DAYS_THRESHOLD=config.cert_recent_issue_days_threshold,
        HYPHEN_THRESHOLD=config.hyphen_threshold,
        SUSPICIOUS_TLDS=config.suspicious_tlds,
        SHORTENERS=config.shorteners,
        ABUSABLE_PLATFORM_DOMAINS=config.abusable_platform_domains,
        TRIVIAL_SUBDOMAINS=config.trivial_subdomains,
        COMMON_TLDS=config.common_tlds,
    )


def _build_analyzer(
    config: Config,
    enrich=None,
    redirect_service=None,
    cache=None,
) -> LinkHeuristics:
    link_config = _build_config(config)
    enrich = enrich or []

    vt_lookup = whois_lookup = redirect_lookup = ssl_fetcher = None

    if "virustotal" in enrich or "all" in enrich:
        from phishsage.services.virustotal import VirusTotalService

        vt_service = VirusTotalService(
            api_key=config.virustotal_api_key, cache_ttl=config.cache_ttl_vt
        )
        vt_lookup = partial(vt_service.lookup_url, cache=cache)

    if "domain_age" in enrich or "all" in enrich:
        from phishsage.services.whois import WhoisService

        whois_lookup = partial(
            WhoisService(cache_ttl=config.cache_ttl_whois).lookup, cache=cache
        )

    if redirect_service and ("redirects" in enrich or "all" in enrich):
        redirect_lookup = partial(redirect_service.resolve, cache=cache)

    if "certificate" in enrich or "all" in enrich:
        from phishsage.services.cert_checker import SSLService

        ssl_fetcher = partial(
            SSLService(
                port=config.ssl_default_port, cache_ttl=config.cache_ttl_ssl
            ).fetch,
            cache=cache,
        )

    return LinkHeuristics(
        config=link_config,
        vt_lookup=vt_lookup,
        whois_lookup=whois_lookup,
        redirect_lookup=redirect_lookup,
        ssl_fetcher=ssl_fetcher,
        enrich=enrich,
    )


async def _vt_scan(web_urls, cache, config: Config):
    from phishsage.services.virustotal import VirusTotalService

    vt_service = VirusTotalService(
        api_key=config.virustotal_api_key, cache_ttl=config.cache_ttl_vt
    )
    analyzer = LinkHeuristics(
        config=None, vt_lookup=partial(vt_service.lookup_url, cache=cache)
    )

    vt_dict = {}

    parseable = []
    for url in web_urls:
        parsed = parse_url(url)
        if parsed is None:
            vt_dict[url] = {
                "status": "skipped",
                "error": "unparseable",
                "stats": {},
                "last_analysis_date": None,
                "first_submission_date": None,
            }
        else:
            parseable.append((url, parsed))

    tasks = [analyzer.scan_virustotal(p) for _, p in parseable]
    vt_results = await asyncio.gather(*tasks, return_exceptions=True)

    for (url, _), result in zip(parseable, vt_results):
        if isinstance(result, Exception):
            vt_dict[url] = {
                "status": "error",
                "error": str(result),
                "stats": {},
                "last_analysis_date": None,
                "first_submission_date": None,
            }
            continue

        inspected = result.meta.get("inspected") or {}
        evidence = result.meta.get("evidence") or {}
        diagnostic = result.meta.get("diagnostic") or {}

        entry = {
            "status": result.status,
            "stats": evidence.get("stats") or {},
            "last_analysis_date": inspected.get("last_analysis_date"),
            "first_submission_date": inspected.get("first_submission_date"),
        }
        if diagnostic.get("error"):
            entry["error"] = diagnostic["error"]

        vt_dict[url] = entry

    return vt_dict


async def _follow_redirects(web_urls, cache, config: Config):
    from phishsage.services.redirect import RedirectService

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(
            total=config.http_total_timeout, connect=config.http_connect_timeout
        )
    ) as session:
        redirect_service = RedirectService(
            session=session,
            max_redirects=config.max_redirects,
            cache_ttl=config.cache_ttl_redirect,
        )

        analyzer = LinkHeuristics(
            config=None, redirect_lookup=partial(redirect_service.resolve, cache=cache)
        )

        parseable = []
        redirect_results = []
        for url in web_urls:
            parsed = parse_url(url)
            if parsed is None:
                redirect_results.append(
                    {
                        "original_url": url,
                        "status": "skipped",
                        "error": "unparseable",
                    }
                )
            else:
                parseable.append((url, parsed))

        tasks = [analyzer.resolve_redirect_chain(p) for _, p in parseable]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for (url, _), result in zip(parseable, results):
        if isinstance(result, Exception):
            redirect_results.append(
                {
                    "original_url": url,
                    "status": "error",
                    "error": str(result),
                }
            )
            continue

        inspected = result.meta.get("inspected") or {}
        evidence = result.meta.get("evidence") or {}
        diagnostic = result.meta.get("diagnostic") or {}

        original_url = inspected.get("normalized_url", url)
        final_url = inspected.get("final_url")
        status_codes = evidence.get("status_codes", [])

        if diagnostic or (not final_url and not status_codes):
            redirect_results.append(
                {
                    "original_url": original_url,
                    "status": result.status,
                    "error": diagnostic.get("error", "request_failed"),
                }
            )
            continue

        redirect_results.append(
            {
                "original_url": original_url,
                "status": result.status,
                "final_url": final_url,
                "redirected": bool(evidence.get("redirect_count", 0) > 0),
                "redirect_count": evidence.get("redirect_count", 0),
                "status_codes": status_codes,
                "redirect_chain": evidence.get("redirect_chain", []),
            }
        )

    return redirect_results


async def _run_heuristics(web_urls, enrich, cache, config: Config):
    session = None
    redirect_service = None
    enrich = enrich or []

    try:
        if "redirects" in enrich or "all" in enrich:
            from phishsage.services.redirect import RedirectService

            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=config.http_total_timeout,
                    connect=config.http_connect_timeout,
                )
            )
            redirect_service = RedirectService(
                session=session,
                max_redirects=config.max_redirects,
                cache_ttl=config.cache_ttl_redirect,
            )

        analyzer = _build_analyzer(
            config=config,
            enrich=enrich,
            redirect_service=redirect_service,
            cache=cache,
        )
        return await analyzer.run_link_heuristics(web_urls)

    finally:
        if session:
            await session.close()


async def handle_links(args, mail, cache=None, config: Config = None):
    links = extract_links(mail.body or "")
    if not links:
        return {"error": "No URLs found in the email"}

    web_urls = []
    non_web = []

    for u in links:
        low = u.lower()
        if low.startswith(("http://", "https://")):
            web_urls.append(u)
        elif "://" not in u:
            web_urls.append(f"https://{u}")
        else:
            non_web.append(u)

    json_output = {}

    if args.extract:
        json_output.setdefault("analysis", {})["urls"] = {
            "total": len(links),
            "web": web_urls,
            "non_web": non_web,
        }

    if args.vt_scan:
        json_output.setdefault("analysis", {})["virustotal"] = await _vt_scan(
            web_urls, cache, config
        )

    if args.check_redirects:
        json_output.setdefault("analysis", {})["redirects"] = await _follow_redirects(
            web_urls, cache, config
        )

    if args.heuristics:
        json_output.setdefault("analysis", {})["heuristics"] = await _run_heuristics(
            web_urls, args.enrich, cache, config
        )

    return json_output
