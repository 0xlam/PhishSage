import ipaddress
from yarl import URL
import tldextract
from phishsage.models.links import ParsedURL


def extract_domain_parts(host: str):
    try:
        e = tldextract.extract(host)
        registered = f"{e.domain}.{e.suffix}" if e.suffix else e.domain
        return registered, e.domain, e.subdomain, e.suffix
    except Exception:
        return (None,) * 4


def parse_url(url: str) -> ParsedURL | None:
    try:
        parsed_url = URL(url)
        if not parsed_url.host:
            return None

        hostname = parsed_url.host

        try:
            ipaddress.ip_address(hostname)
            return ParsedURL(
                raw=url,
                normalized=str(parsed_url),
                scheme=parsed_url.scheme,
                hostname=hostname,
                registered_domain=hostname,
                domain=hostname,
                subdomain="",
                suffix="",
                path=parsed_url.path,
                query=parsed_url.query,
            )
        except ValueError:
            pass

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