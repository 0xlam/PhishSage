## [1.1.0] – 2026-01-06

### Fixed
- Corrected flag assignment for non-success statuses in the `scan_with_virustotal` function.

### Changed
- Renamed `free_hosting_providers` to `abusable_platform_domains` in `config.toml` and `loader.py` for improved accuracy.
- Renamed the `uses_free_hosting` heuristic to `uses_abusable_platform` for clearer semantics.
- Renamed CLI subcommand `attachment` to `attachments` for naming consistency.
- Updated `free_email_domains` and `abusable_platform_domains` datasets.


## [1.2.0] - 2026-02-10

### Breaking Changes
- Consolidated header heuristics into a class-based interface
- Consolidated link heuristics into a class-based interface

### Added
- `url_parser.py` module for shared URL parsing utilities


## [1.2.1] - 2026-02-14

### Fixed
- Prevent KeyError in JSON output when VirusTotal scan results are added.


## [1.3.0] - 2026-02-15

### Improved
- Consolidated `scan_with_virustotal` logic in `LinkHeuristics`.
- Aligned VirusTotal data structure across attachments, links, and API client modules.
- Cleaned up output formatting and added `last_analysis_date` and `first_submission_date`.



## [2.0.0] – 2026-04-01

### Breaking Changes
* Header & Link heuristics are now fully asynchronous
* **Enrichment checks are no longer enabled by default** – use the `--enrich` flag to include optional threat-intel (MX, Spamhaus, domain age, etc.) for headers and links.
* The `--include_redirects` CLI option has been **removed**. Use `--enrich redirects` (or `--enrich all`) instead.

### Added
* `yara_engine.py` module for YARA scanning.
* **`--enrich` flag** for `headers` and `links` subcommands to selectively enable extra checks:
  * Headers: `mx`, `spamhaus`, `domain_age`, `all`
  * Links: `domain_age`, `certificate`, `virustotal`, `redirects`, `all`
* Modularized `main.py` into smaller components.
* Added `outputs/printer.py` for formatted console output.

### Changed
* Renamed `--scan` to `--vt-scan` for attachments and links subcommands.
* Updated help descriptions.


## [2.1.0] – 2026-04-03

### Changed
- Replaced exact version pins (`==`) with bounded ranges in `pyproject.toml`.
- Removed transitive dependencies from `pyproject.toml`.

### Added
- Optional dependency groups: `[attachments]`, `[links]`, `[all]`.
- Import guards with install hints for missing optional dependencies.