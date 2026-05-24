from dataclasses import dataclass

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
