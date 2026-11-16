from functools import partial
import aiodns

from phishsage.heuristics.headers import HeaderHeuristics
from phishsage.services.whois import WhoisService
from phishsage.config.object import Config


async def handle_headers(args, headers, cache=None, config: Config = None):
    if args.heuristics:
        enrich = args.enrich or []

        if "all" in enrich:
            enrich = ["mx", "spamhaus", "domain_age"]

        whois_lookup = None
        dns_resolver = None

        if "domain_age" in enrich:
            whois_lookup = partial(
                WhoisService(cache_ttl=config.cache_ttl_whois).lookup, cache=cache
            )

        if "mx" in enrich or "spamhaus" in enrich:
            dns_resolver = aiodns.DNSResolver()

        checker = HeaderHeuristics(
            config=config,
            whois_lookup=whois_lookup,
            dns_resolver=dns_resolver,
            cache=cache,
        )
        heuristics_result = await checker.run_headers_heuristics(headers, enrich=enrich)
        return {
            "flags": heuristics_result.flags,
            "results": heuristics_result.result,
            "alerts": heuristics_result.alerts,
            "meta": heuristics_result.meta,
        }
