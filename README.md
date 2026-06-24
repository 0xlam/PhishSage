# PhishSage

**CLI toolkit for email phishing analysis**. Parses raw `.eml` files, runs heuristic checks against headers, links, and attachments, enriches indicators with VirusTotal, WHOIS, DNS, redirects, and SSL certificate data, optionally caches external lookups, and outputs structured JSON or Rich terminal output.

[![PyPI](https://img.shields.io/pypi/v/phishsage)](https://pypi.org/project/phishsage/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/phishsage/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status: Active](https://img.shields.io/badge/status-active-brightgreen)]()

---

## What it does

PhishSage covers three analysis surfaces, each a CLI subcommand:

**`headers`** — SPF/DKIM/DMARC extraction and alignment checks, Reply-To/Return-Path anomalies, Message-ID domain validation, free-provider detection, timestamp drift between `Date` and `Received`, optional MX record lookup, Spamhaus DBL query, and WHOIS domain-age flagging.

**`links`** — URL extraction from body and headers, raw-IP URL detection, suspicious/uncommon TLD flagging, subdomain depth and entropy scoring (detects randomly generated domains), shortened-URL detection, free hosting platform detection, SSL/TLS certificate inspection, WHOIS domain age, VirusTotal URL lookup, redirect-chain tracing, and path-depth analysis.

**`attachments`** — Listing with MIME type and size, safe attachment extraction, MD5/SHA1/SHA256 hashing, VirusTotal hash lookup, and YARA rule scanning with optional verbose string/offset output.

Enrichment is opt-in via `--enrich` and runs concurrently. Headers support `mx`, `spamhaus`, and `domain_age`; links support `domain_age`, `certificate`, `virustotal`, and `redirects`.

---

## Installation

### Base (headers + basic parsing)

```bash
pip install phishsage
```

### With extras

```bash
pip install "phishsage[attachments]"        # MIME detection
pip install "phishsage[attachments,yara]"   # + YARA scanning
pip install "phishsage[virustotal]"         # VirusTotal URL/hash lookup
pip install "phishsage[ssl]"                # SSL/TLS certificate checks
pip install "phishsage[cache]"              # Disk caching for external enrichment lookups
pip install "phishsage[all]"                # Everything
```

### From source

```bash
git clone https://github.com/0xlam/PhishSage.git
cd PhishSage
python3 -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\Activate.ps1
pip install -e ".[all]"
```

### VirusTotal API key (optional)

Required only if you use `--vt-scan` or `--enrich virustotal`.

```bash
export VIRUSTOTAL_API_KEY="your_key_here"
```

---

## Caching

External enrichment lookups can be cached to reduce repeated API calls and network requests. Requires the `cache` extra.

```bash
# Enable caching with default cache directory (~/.cache/phishsage)
phishsage links -f email.eml --heuristics --enrich all --cache

# Use a custom cache directory
phishsage links -f email.eml --heuristics --enrich all --cache --cache-dir ./.phishsage-cache
```

Caching currently supports:

| Service | Cached data |
|---------|-------------|
| VirusTotal | URL and file hash lookup results |
| WHOIS | Domain age and registrar data |
| Redirects | Redirect chains and final status |
| SSL certificates | Certificate issuer, subject, and validity dates |
| MX | MX records per domain |
| Spamhaus | DBL blacklist status per domain |

Cache TTLs are configured in `config.toml`.

---

## Usage

### Header analysis

```bash
# Basic parse
phishsage headers -f email.eml

# Full heuristics + all enrichment, save JSON
phishsage headers -f email.eml --heuristics --enrich all --json -o results.json

# Selective enrichment
phishsage headers -f email.eml --heuristics --enrich mx spamhaus

# Header enrichment with cached WHOIS lookups
phishsage headers -f email.eml --heuristics --enrich domain_age --cache
```

### Link analysis

```bash
# Extract URLs
phishsage links -f email.eml --extract

# Full heuristics + enrichment
phishsage links -f email.eml --heuristics --enrich all

# Full heuristics + enrichment with cache
phishsage links -f email.eml --heuristics --enrich all --cache

# VirusTotal scan only
phishsage links -f email.eml --vt-scan --json
```

### Attachment analysis

```bash
# List attachments
phishsage attachments -f email.eml --list

# Hash + VirusTotal
phishsage attachments -f email.eml --hash --vt-scan

# YARA scan (verbose)
phishsage attachments -f email.eml --yara ./rules/ --yara-verbose

# Extract to directory
phishsage attachments -f email.eml --extract ./output/
```

### Batch processing

Pass multiple files in one run:

```bash
phishsage headers -f mail1.eml mail2.eml mail3.eml --heuristics --json -o batch.json
```

---

## Example Workflow

```bash
phishsage headers -f examples/sample-phish.eml --heuristics --enrich all --json -o reports/headers.json
phishsage links -f examples/sample-phish.eml --heuristics --enrich all --cache --json -o reports/links.json
phishsage attachments -f examples/sample-phish.eml --list --hash --json -o reports/attachments.json
```

Run all three subcommands on the same email for full coverage. Use `--cache` when scanning multiple emails to avoid redundant external lookups.

---

## Output

Without `--json`, PhishSage renders Rich terminal output with color-coded alerts. With `--json`, it outputs a structured object keyed by file path.

```json
{
  "test.eml": {
    "flags": true,
    "results": {
      "auth": {
        "spf":  { "value": "softfail", "passed": false },
        "dkim": { "value": "fail",     "passed": false },
        "dmarc":{ "value": null,       "passed": null  }
      },
      "address_alignment": { "from_vs_reply": false, "from_vs_return": false },
      "message_id":         { "msgid_vs_from": false },
      "domain_consistency": { "from_vs_return": false, "from_vs_reply": false }
    },
    "alerts": [
      { "type": "SPF_FAIL",             "message": "SPF check failed (spf=softfail)" },
      { "type": "DKIM_FAIL",            "message": "DKIM check failed (dkim=fail)" },
      { "type": "DMARC_MISSING",        "message": "DMARC result missing from Authentication-Results header" },
      { "type": "FROM_REPLY_MISMATCH",  "message": "From domain (secure-login-verification.com) does not match Reply-To domain (gmail.com)" },
      { "type": "DATE_BEFORE_RECEIVED", "message": "Date header (2026-05-26T10:00:00+00:00) is before first Received (2026-05-26T10:35:00+00:00)" }
    ],
    "meta": { "mail_id": "bb27b099" }
  }
}
```

---

## Configuration

`config.toml` (inside the package) controls all tunable thresholds and heuristic lists. The most useful knobs:

### Heuristics

| Key | Default | Purpose |
|-----|---------|---------|
| `threshold_young` | `30` days | Flag newly registered domains |
| `threshold_expiring` | `10` days | Flag soon-to-expire domains |
| `entropy_threshold` | `4.0` | Entropy cutoff for flagging randomly generated domain labels |
| `subdomain_threshold` | `3` | Max non-trivial subdomain labels before flagging |
| `max_path_depth` | `4` | URL path depth limit |
| `date_received_drift_minutes` | `30` | Max drift between `Date` and first `Received` hop |
| `max_redirects` | `10` | Redirect-chain follow limit |
| `cert_recent_issue_days_threshold` | `30` | Flag recently issued certificates |

### Cache

| Key | Default | Purpose |
|-----|---------|---------|
| `ttl_vt` | `86400` seconds | Cache TTL for VirusTotal results |
| `ttl_whois` | `604800` seconds | Cache TTL for WHOIS results |
| `ttl_redirect` | `21600` seconds | Cache TTL for redirect results |
| `ttl_ssl` | `43200` seconds | Cache TTL for SSL certificate results |
| `ttl_mx` | `86400` seconds | Cache TTL for MX record lookups |
| `ttl_spamhaus` | `3600` seconds | Cache TTL for Spamhaus DBL lookups |


Lists (`suspicious_tlds`, `shorteners`, `free_email_domains`, `abusable_platform_domains`, `trivial_subdomains`) are all editable in the same file.

---

## Scope & limitations

- **Triage tool, not a mail gateway.** Not designed for inline enforcement or production email filtering.
- **Network-dependent enrichment.** WHOIS, DNS, VirusTotal, and SSL checks require connectivity and may hit rate limits.
- **Attachment coverage.** Attachment analysis currently covers listing, extraction, hashing, VirusTotal hash lookup, and YARA scanning. Deeper content inspection is planned.
- **False positives.** Default thresholds are set strictly and may produce false positives depending on your environment — adjust `config.toml` as needed.
- **Cached enrichment may become stale.** Use `--cache-dir` to isolate cache data per investigation, or clear the cache when fresh lookups are required.

---

## Contributing

Bug reports, heuristic improvements, new TLD/shortener/platform entries, and additional enrichment modules are all welcome. Open an issue or PR on [GitHub](https://github.com/0xlam/PhishSage).

---

## License

MIT — see [LICENSE](LICENSE).
