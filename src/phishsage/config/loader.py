import os
import tomllib
from pathlib import Path

from phishsage.config.object import Config

DEFAULT_CONFIG = Path(__file__).resolve().parent / "config.toml"


def _load_toml(path: Path) -> dict:
    path = Path(path)
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"Config file not found: {path}")
    except tomllib.TOMLDecodeError as e:
        raise RuntimeError(f"Invalid TOML in {path}: {e}")


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            out[key] = _deep_merge(base[key], value)
        else:
            out[key] = value
    return out


def load_config(path: Path | str | None = None) -> Config:

    if not DEFAULT_CONFIG.exists():
        raise RuntimeError(f"Packaged config missing: {DEFAULT_CONFIG}")

    base = _load_toml(DEFAULT_CONFIG)
    override = _load_toml(path) if path is not None else {}
    raw = _deep_merge(base, override)

    api = raw.get("api", {})
    heur = raw.get("heuristics", {})
    net = raw.get("network", {})
    cache = raw.get("cache", {})

    return Config(
        virustotal_api_key=os.getenv(
            "VIRUSTOTAL_API_KEY", api.get("virustotal_api_key", "")
        ),
        suspicious_tlds=set(heur.get("suspicious_tlds", [])),
        shorteners=set(heur.get("shorteners", [])),
        free_email_domains=set(heur.get("free_email_domains", [])),
        trivial_subdomains=set(heur.get("trivial_subdomains", [])),
        abusable_platform_domains=set(heur.get("abusable_platform_domains", [])),
        common_tlds=set(heur.get("common_tlds", [])),
        hyphen_threshold=heur.get("hyphen_threshold", 4),
        subdomain_threshold=heur.get("subdomain_threshold", 3),
        entropy_threshold=heur.get("entropy_threshold", 4),
        max_path_depth=heur.get("max_path_depth", 4),
        date_received_drift_minutes=heur.get("date_received_drift_minutes", 30),
        max_redirects=heur.get("max_redirects", 10),
        threshold_young=heur.get("threshold_young", 30),
        threshold_expiring=heur.get("threshold_expiring", 10),
        cert_recent_issue_days_threshold=heur.get(
            "cert_recent_issue_days_threshold", 30
        ),
        ssl_default_port=heur.get("ssl_default_port", 443),
        http_total_timeout=net.get("total_timeout", 30),
        http_connect_timeout=net.get("connect_timeout", 5),
        cache_dir=Path(os.path.expanduser(cache.get("dir", "~/.cache/phishsage"))),
        cache_ttl_vt=cache.get("ttl_vt", 86400),
        cache_ttl_whois=cache.get("ttl_whois", 604800),
        cache_ttl_redirect=cache.get("ttl_redirect", 21600),
        cache_ttl_ssl=cache.get("ttl_ssl", 43200),
        cache_ttl_mx=cache.get("ttl_mx", 86400),
        cache_ttl_spamhaus=cache.get("ttl_spamhaus", 3600),
    )
