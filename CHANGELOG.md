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

