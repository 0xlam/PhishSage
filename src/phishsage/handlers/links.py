from functools import partial
from types import SimpleNamespace
import asyncio
import aiohttp

from phishsage.parsers import parse_url, extract_links
from phishsage.heuristics.links import analyze_urls, virustotal, redirect_chain


def _build_deps(
    config,
    enrich,
    redirect_service=None,
    cache=None,
):
    deps = SimpleNamespace(
        vt_lookup=None,
        whois_lookup=None,
        redirect_lookup=None,
        ssl_fetcher=None,
    )

    if "virustotal" in enrich or "all" in enrich:
        from phishsage.services.virustotal import VirusTotalService

        service = VirusTotalService(
            api_key=config.virustotal_api_key,
            cache_ttl=config.cache_ttl_vt,
        )
        deps.vt_lookup = partial(service.lookup_url, cache=cache)

    if "domain_age" in enrich or "all" in enrich:
        from phishsage.services.whois import WhoisService

        service = WhoisService(cache_ttl=config.cache_ttl_whois)
        deps.whois_lookup = partial(service.lookup, cache=cache)

    if redirect_service and ("redirect_chain" in enrich or "all" in enrich):
        deps.redirect_lookup = partial(redirect_service.resolve, cache=cache)

    if "certificate" in enrich or "all" in enrich:
        from phishsage.services.cert_checker import SSLService

        service = SSLService(
            port=config.ssl_default_port,
            cache_ttl=config.cache_ttl_ssl,
        )
        deps.ssl_fetcher = partial(service.fetch, cache=cache)

    return deps


async def _vt_scan(web_urls, cache, config):
    deps = _build_deps(
        config=config,
        enrich=["virustotal"],
        cache=cache,
    )

    async def scan(url):
        parsed = parse_url(url)

        if parsed is None:
            return url, {
                "status": "skipped",
                "error": "unparseable",
                "stats": {},
            }

        result = await virustotal(parsed, deps)
        details = result.get("details", {})

        entry = {
            "status": result["status"],
            "stats": {},
        }

        if result["status"] == "ok":
            entry["stats"] = {
                "malicious": details.get("malicious", 0),
                "suspicious": details.get("suspicious", 0),
                "harmless": details.get("harmless", 0),
                "undetected": details.get("undetected", 0),
            }
            entry["last_analysis_date"] = details.get("last_analysis_date")
            entry["first_submission_date"] = details.get("first_submission_date")
        elif details.get("error"):
            entry["error"] = details["error"]

        return url, entry

    results = await asyncio.gather(*(scan(url) for url in web_urls))

    return dict(results)


async def _follow_redirects(web_urls, cache, config):
    from phishsage.services.redirect import RedirectService

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(
            total=config.http_total_timeout,
            connect=config.http_connect_timeout,
        )
    ) as session:

        service = RedirectService(
            session=session,
            max_redirects=config.max_redirects,
            cache_ttl=config.cache_ttl_redirect,
        )

        async def follow(url):
            parsed = parse_url(url)

            if parsed is None:
                return {
                    "original_url": url,
                    "status": "skipped",
                    "error": "unparseable",
                }

            try:
                result = await service.resolve(parsed.normalized, cache=cache)

                excessive = result.redirected and not result.chain

                return {
                    "original_url": parsed.normalized,
                    "status": "ok",
                    "redirected": result.redirected,
                    "excessive_redirects": excessive,
                    "redirect_count": result.redirect_count,
                    "final_url": result.final_url or None,
                    "status_codes": result.status_codes,
                    "redirect_chain": result.chain,
                }

            except Exception as e:
                return {
                    "original_url": parsed.normalized,
                    "status": "error",
                    "error": str(e),
                }

        return await asyncio.gather(*(follow(url) for url in web_urls))


async def _run_heuristics(web_urls, enrich, cache, config):
    enrich = enrich or []

    enrich = ["redirect_chain" if name == "redirects" else name for name in enrich]

    session = None
    redirect_service = None

    try:
        if "redirect_chain" in enrich or "all" in enrich:
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

        deps = _build_deps(
            config=config,
            enrich=enrich,
            redirect_service=redirect_service,
            cache=cache,
        )

        return await analyze_urls(
            urls=web_urls,
            config=config,
            deps=deps,
            enrich=enrich,
        )

    finally:
        if session:
            await session.close()


async def handle_links(args, mail, cache=None, config=None):
    links = extract_links(mail.body or "")

    if not links:
        return {"error": "No URLs found in the email"}

    web_urls = []
    non_web = []

    for url in links:
        low = url.lower()

        if low.startswith(("http://", "https://")):
            web_urls.append(url)
        elif "://" not in url:
            web_urls.append(f"https://{url}")
        else:
            non_web.append(url)

    output = {}

    if args.extract:
        output["urls"] = {
            "total": len(links),
            "web": web_urls,
            "non_web": non_web,
        }

    if args.vt_scan:
        output["virustotal"] = await _vt_scan(web_urls, cache, config)

    if args.check_redirects:
        output["redirects"] = await _follow_redirects(web_urls, cache, config)

    if args.heuristics:
        output["heuristics"] = await _run_heuristics(
            web_urls,
            args.enrich,
            cache,
            config,
        )

    return output
