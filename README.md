# PhishSage

PhishSage is a lightweight phishing-analysis toolkit that parses raw emails, inspects headers, analyzes links and domains with multi-layer heuristics, and outputs structured JSON findings for fast, automated investigation

<!-- Badges go here -->

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)]()
[![Status: Active](https://img.shields.io/badge/Project%20Status-Active-brightgreen.svg)]()


## 1. Core functionality

PhishSage is intentionally minimal and concentrates on these essential capabilities:

* **Header analysis**

  * Extracts normalized sender-related headers (From, Reply-To, Return-Path, Message-ID)
  * Parses SPF, DKIM, and DMARC results from Authentication-Results
  * Performs alignment checks across From, Reply-To, and Return-Path
  * Validates Message-ID domain consistency
  * Checks timestamp sanity: Date header vs first Received hop
  * Looks up WHOIS domain age and flags newly registered domains
  * Validates MX records for the From domain
  * Queries Spamhaus DBL for sender-related domains
  * Aggregates all findings into structured JSON with merged alerts


* **Attachment processing**

  * List attachments with MIME and size
  * Extract attachments safely (avoid overwrites)
  * Compute hashes (MD5, SHA1, SHA256)
  * Optional VirusTotal scan by SHA256
  * Scan attachments with YARA rules (single files, multiple files, or directories; recursive and filtered for valid .yar/.yara files)
  * Verbose mode shows matched strings with offsets and hex data


* **Link / URL analysis**

  * Extracts URLs from email bodies or headers
  * Detects URLs using raw IP addresses instead of domains
  * Flags suspicious or uncommon top-level domains (TLDs)
  * Identifies excessive or nested subdomains, ignoring trivial ones (e.g., "www")
  * Recognizes shortened URLs (bit.ly, tinyurl.com, etc.)
  * Calculates Shannon entropy for domain and subdomain to spot obfuscation
  * Performs SSL/TLS certificate inspection (issuer, validity, domain match, expiration)
  * Looks up domain age via WHOIS and flags newly registered or expiring domains
  * VirusTotal URL lookup for threat intelligence
  * Optional redirect-chain tracing to uncover hidden destinations
  * Checks for numeric-only registrable domains
  * Detects URLs hosted on free or cheap hosting platforms
  * Flags URLs with excessively deep paths


---

## 2. Environment Setup

```bash
# 1. (Optional) Create and activate a virtual environment
python3 -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows (PowerShell)
venv\Scripts\Activate.ps1

# 2. Install PhishSage from PyPI
pip install phishsage

# 3. (Optional) Set VirusTotal API key
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"     # Linux/macOS

# Windows (PowerShell)
# setx VIRUSTOTAL_API_KEY "your_virustotal_api_key"
```

## 3. CLI Usage

PhishSage provides a command-line interface with three main modes: `headers`, `attachment`, and `links`. The `headers` and `links` modes output results in JSON format, while the `attachment` mode produces human-readable summaries only.


### Main Help

```bash
phishsage -h
```

**Output:**

```
usage: phishsage [-h] {headers,attachment,links} ...

PhishSage

positional arguments:
  {headers,attachment,links}
    headers             Analyze email headers for anomalies or indicators
    attachment          Analyze or extract attachments
    links               Analyze links in email content

options:
  -h, --help            show this help message and exit
```

---

### Header Analysis

```bash
phishsage headers -h
```

**Options:**

```
usage: phishsage headers [-h] -f FILE [--heuristics] [--json]

options:
  -h, --help       show this help message and exit
  -f, --file FILE  Email file to analyze (.eml)
  --heuristics     Run heuristic header analysis for anomalies
  --json           Output results in raw JSON format
```

---

### Attachment Processing

```bash
phishsage attachment -h
```

**Options:**

```
usage: phishsage attachment -f FILE [--list] [--extract DIR] [--hash] [--scan] [--yara PATH [PATH ...]] [--yara-verbose] [--json]

options:
  -h, --help              show this help message and exit
  -f, --file FILE         Email file to analyze (.eml)
  --list                  List attachments only
  --extract DIR           Extract attachments to specified directory
  --hash                  Compute hashes (MD5, SHA1, SHA256) for each attachment
  --scan                  Check attachments against VirusTotal by SHA256
  --yara PATH [PATH ...]  Scan attachments with YARA rules. Paths can be files or directories; directories are scanned recursively for .yar/.yara files.
  --json                  Output results in raw JSON format
```

---

### Link / URL Analysis

```bash
phishsage links -h
```

**Options:**

```
usage: phishsage links [-h] -f FILE [--extract] [--scan]  [--check-redirects | --heuristics] [--include-redirects] [--json]

options:
  -h, --help           show this help message and exit
  -f, --file FILE      Email file to analyze (.eml)
  --extract            Extract all URLs found in the email body or headers
  --scan               Submit extracted links to VirusTotal for analysis
  --check-redirects    Follow and display final redirect destinations for each URL
  --heuristics         Run phishing heuristics on extracted URLs
  --include-redirects  Include redirect chain when running heuristics (ignored if --heuristics not used)
  --json               Output results in raw JSON format
```

---

## 4. Configuration

PhishSage stores configuration values in the project config (`config.toml`) or environment variables. The main items you may safely adjust are:

  * `VIRUSTOTAL_API_KEY` — API key for VirusTotal scans.
  * `MAX_REDIRECTS` — Maximum number of redirects to follow when checking redirect chains.
  * `THRESHOLD_YOUNG`, `THRESHOLD_EXPIRING` — Domain age/expiry thresholds (in days). Domains younger than `THRESHOLD_YOUNG` or expiring within `THRESHOLD_EXPIRING` days are flagged as potentially suspicious.
  * `FREE_HOSTING_PROVIDERS`, `SUSPICIOUS_TLDS`, `SHORTENERS` — Heuristic lists used in URL/link analysis.
  * `SUBDOMAIN_THRESHOLD`, `TRIVIAL_SUBDOMAINS` — Used for subdomain heuristics to identify excessive or meaningful subdomains.
  * `FREE_EMAIL_DOMAINS` — Free email providers that may indicate disposable or less-trusted addresses.
  * `DATE_RECEIVED_DRIFT_MINUTES` — Maximum allowed difference between the `Date` header and the first `Received` hop in email headers.

 *Note: Only modify thresholds or heuristic lists if you understand the potential impact on false positives and overall detection accuracy.*


---

## 5. Scope & Limitations

  * **Focused functionality:** PhishSage is not a full mail forensic suite. It prioritizes heuristics, quick triage, and enrichment over deep forensic analysis.
  * **Network-dependent checks:** WHOIS, VirusTotal, MX, and SSL inspections rely on external services; results may vary or fail due to connectivity issues or API limits.
  * **Attachment processing:** Currently limited to listing, extraction, hashing, and optional VirusTotal scans. Full heuristic attachment analysis will be introduced in a future release.
  * **Output formats:** JSON output is available for all  modes. 
  * **Intended use:** Designed for investigative support and enrichment. Not intended for automated blocking or enforcement in production email systems.
  * **Evolving coverage:** Current checks under each section are limited; additional heuristics and enhanced analyses will be added in future releases.


---

## 6. Contributing

Contributions to PhishSage are welcome! You can help improve the project by:

* Adding or refining heuristic checks for headers, attachments, and links.
* Expanding the lists in `config.toml`.
* Improving parsing, normalization, or output handling.
* Reporting bugs or suggesting enhancements.

Before submitting changes, please ensure they are well-tested and maintain the code’s clarity, security, and reliability. Contributions that enhance detection coverage, reduce false positives, or improve usability are particularly appreciated.
