from dataclasses import dataclass
from urllib.parse import urlparse
from phishsage.utils.url_helpers import (
    normalize_url,
    get_hostname,
    extract_domain_parts,
)


@dataclass(frozen=True)
class ParsedURL:
    raw: str
    normalized: str
    scheme: str
    hostname: str
    registered_domain: str
    domain: str
    subdomain: str
    suffix: str
    path: str
    query: str


def parse_url(url: str) -> ParsedURL | None:
    normalized = normalize_url(url)
    if not normalized:
        return None

    parsed = urlparse(normalized)

    hostname = get_hostname(normalized)
    if not hostname:
        return None

    registered, domain, subdomain, suffix = extract_domain_parts(normalized)
    if not registered:
        return None

    return ParsedURL(
        raw=url,
        normalized=normalized,
        scheme=parsed.scheme,
        hostname=hostname,
        registered_domain=registered,
        domain=domain,
        subdomain=subdomain,
        suffix=suffix,
        path=parsed.path,
        query=parsed.query,
    )
