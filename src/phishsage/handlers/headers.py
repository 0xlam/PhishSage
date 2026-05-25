import aiodns
from phishsage.heuristics.headers import HeaderHeuristics
from phishsage.services.whois import WhoisService
from phishsage.config.loader import (
    FREE_EMAIL_DOMAINS,
    DATE_RECEIVED_DRIFT_MINUTES,
    THRESHOLD_YOUNG,
    THRESHOLD_EXPIRING,
)
from phishsage.config.schemas import HeaderHeuristicConfig


def _build_header_config() -> HeaderHeuristicConfig:
    return HeaderHeuristicConfig(
        DATE_RECEIVED_DRIFT_MINUTES=DATE_RECEIVED_DRIFT_MINUTES,
        THRESHOLD_YOUNG=THRESHOLD_YOUNG,
        THRESHOLD_EXPIRING=THRESHOLD_EXPIRING,
        FREE_EMAIL_DOMAINS=FREE_EMAIL_DOMAINS,
    )


async def handle_headers(args, headers):
    if args.heuristics:
        config = _build_header_config()

        enrich = args.enrich or []

        whois_lookup = None
        dns_resolver = None

        if "domain_age" in enrich:
            whois_lookup = WhoisService().lookup

        if "mx" in enrich or "spamhaus" in enrich:
            dns_resolver = aiodns.DNSResolver()

        checker = HeaderHeuristics(
            config=config,
            whois_lookup=whois_lookup,
            dns_resolver=dns_resolver,
        )

        heuristics_result = await checker.run_headers_heuristics(
            headers, enrich=enrich
        )

        return {
            "flags":   heuristics_result.flags,
            "results": heuristics_result.result,
            "alerts":  heuristics_result.alerts,
            "meta":    heuristics_result.meta,
        }