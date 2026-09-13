from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # API
    virustotal_api_key: str = ""

    # Heuristics (sets)
    suspicious_tlds: set = field(default_factory=set)
    shorteners: set = field(default_factory=set)
    free_email_domains: set = field(default_factory=set)
    trivial_subdomains: set = field(default_factory=set)
    abusable_platform_domains: set = field(default_factory=set)
    common_tlds: set = field(default_factory=set)

    # Heuristics (scalars)
    hyphen_threshold: int = 4
    subdomain_threshold: int = 3
    entropy_threshold: float = 4
    max_path_depth: int = 4
    date_received_drift_minutes: int = 30
    max_redirects: int = 10
    threshold_young: int = 30
    threshold_expiring: int = 10

    # Certificate
    cert_recent_issue_days_threshold: int = 30
    ssl_default_port: int = 443

    # Network
    http_total_timeout: int = 30
    http_connect_timeout: int = 5

    # Cache
    cache_dir: Path = field(
        default_factory=lambda: Path("~/.cache/phishsage").expanduser()
    )
    cache_ttl_vt: int = 86400
    cache_ttl_whois: int = 604800
    cache_ttl_redirect: int = 21600
    cache_ttl_ssl: int = 43200
    cache_ttl_mx: int = 86400
    cache_ttl_spamhaus: int = 3600
