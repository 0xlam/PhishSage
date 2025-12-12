import os
import tomllib
from pathlib import Path

# Path to config.toml inside the package
CONFIG_FILE = Path(__file__).resolve().parent / "config.toml"


def load_toml():
    """Load and parse the TOML config file."""
    try:
        with CONFIG_FILE.open("rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"Config file not found: {CONFIG_FILE}")
    except tomllib.TOMLDecodeError as e:
        raise RuntimeError(f"Invalid TOML in {CONFIG_FILE}: {e}")


# Load TOML contents
raw = load_toml()


# -------------------------------
#  API CONFIG
# -------------------------------
api = raw.get("api", {})

API_CONFIG = {
    "virustotal_api_key": os.getenv(
        "VIRUSTOTAL_API_KEY",
        api.get("virustotal_api_key", "")
    )
}


# -------------------------------
#  HEURISTICS CONFIG
# -------------------------------
HEURISTICS = raw.get("heuristics", {})

# Convert lists → sets for fast lookups
SUSPICIOUS_TLDS = set(HEURISTICS.get("suspicious_tlds", []))
SHORTENERS = set(HEURISTICS.get("shorteners", []))
FREE_EMAIL_DOMAINS = set(HEURISTICS.get("free_email_domains", []))
TRIVIAL_SUBDOMAINS = set(HEURISTICS.get("trivial_subdomains", []))
FREE_HOSTING_PROVIDERS= set(HEURISTICS.get("free_hosting_providers", []))


SUBDOMAIN_THRESHOLD = HEURISTICS.get("subdomain_threshold", 3)
ENTROPY_THRESHOLD = HEURISTICS.get("entropy_threshold", 4)
MAX_PATH_DEPTH = HEURISTICS.get("max_path_depth", 4)
DATE_RECEIVED_DRIFT_MINUTES = HEURISTICS.get("date_received_drift_minutes", 30)
MAX_REDIRECTS = HEURISTICS.get("max_redirects", 10)
THRESHOLD_YOUNG = HEURISTICS.get("threshold_young", 30)
THRESHOLD_EXPIRING = HEURISTICS.get("threshold_expiring", 10)
VIRUSTOTAL_API_KEY = API_CONFIG["virustotal_api_key"]

# Certificate analysis thresholds
CERT_RECENT_ISSUE_DAYS_THRESHOLD = HEURISTICS.get("cert_recent_issue_days_threshold", 30)
CERT_EXPIRY_SOON_DAYS_THRESHOLD = HEURISTICS.get("cert_expiry_soon_days_threshold", 10)
SSL_DEFAULT_PORT = HEURISTICS.get("ssl_default_port", 443)

