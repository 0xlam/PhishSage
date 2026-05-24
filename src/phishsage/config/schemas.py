from dataclasses import dataclass, field


@dataclass
class HeaderHeuristicConfig:
    DATE_RECEIVED_DRIFT_MINUTES: int
    THRESHOLD_YOUNG: int
    THRESHOLD_EXPIRING: int

    FREE_EMAIL_DOMAINS: set = field(default_factory=set)


@dataclass
class LinkHeuristicConfig:
    ENTROPY_THRESHOLD: float
    SUBDOMAIN_THRESHOLD: int
    MAX_PATH_DEPTH: int
    THRESHOLD_YOUNG: int
    THRESHOLD_EXPIRING: int
    CERT_RECENT_ISSUE_DAYS_THRESHOLD: int

    SUSPICIOUS_TLDS: set = field(default_factory=set)
    SHORTENERS: set = field(default_factory=set)
    ABUSABLE_PLATFORM_DOMAINS: set = field(default_factory=set)
    TRIVIAL_SUBDOMAINS: set = field(default_factory=set)