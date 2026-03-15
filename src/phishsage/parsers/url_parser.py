from dataclasses import dataclass
from yarl import URL
import tldextract


def extract_domain_parts(host: str):
    try:
        e = tldextract.extract(host)
        registered = f"{e.domain}.{e.suffix}" if e.suffix else e.domain

        return registered, e.domain, e.subdomain, e.suffix

    except Exception:
        return (None,) * 4


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
    try:
        parsed_url = URL(url)

        if not parsed_url.host:
            return None

        hostname = parsed_url.host

        registered, domain, subdomain, suffix = extract_domain_parts(hostname)
        if not registered:
            return None

        return ParsedURL(
            raw=url,
            normalized=str(parsed_url),
            scheme=parsed_url.scheme,
            hostname=hostname,
            registered_domain=registered,
            domain=domain,
            subdomain=subdomain,
            suffix=suffix,
            path=parsed_url.path,
            query=parsed_url.query,
        )

    except ValueError:
        return None
