from functools import partial
import aiodns

from phishsage.heuristics.headers import HeaderHeuristics
from phishsage.services.whois import WhoisService
from phishsage.config.object import Config
from phishsage.config.schemas import HeaderHeuristicConfig


def _build_header_config(config: Config) -> HeaderHeuristicConfig:
    return HeaderHeuristicConfig(
        DATE_RECEIVED_DRIFT_MINUTES=config.date_received_drift_minutes,
        THRESHOLD_YOUNG=config.threshold_young,
        THRESHOLD_EXPIRING=config.threshold_expiring,
        FREE_EMAIL_DOMAINS=config.free_email_domains,
        CACHE_TTL_MX=config.cache_ttl_mx,
        CACHE_TTL_SPAMHAUS=config.cache_ttl_spamhaus,
    )


async def handle_headers(args, headers, cache=None, config: Config = None):
    if args.heuristics:
        header_config = _build_header_config(config)
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
            config=header_config,
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
