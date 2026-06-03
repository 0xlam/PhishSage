import argparse


def get_parser():
    parser = argparse.ArgumentParser(description="PhishSage")

    # ---- COMMON FLAGS (shared by all subcommands) ----
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-f",
        "--file",
        required=True,
        nargs="+",
        metavar="FILE",
        help="Email file(s) to analyze (.eml). Pass multiple for batch mode.",
    )
    common.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Save JSON results to file (use with --json)",
    )

    common.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )

    common.add_argument(
        "--cache",
        action="store_true",
        help="Cache external lookup results to disk (default: ~/.cache/phishsage)",
    )

    common.add_argument(
        "--cache-dir",
        metavar="DIR",
        help="Custom cache directory (use with --cache)",
    )

    # ---- SUBCOMMANDS ----
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # ----HEADERS----
    headers_parser = subparsers.add_parser(
        "headers",
        parents=[common],
        help="Analyze email headers for anomalies or indicators",
    )
    headers_parser.add_argument(
        "--heuristics",
        action="store_true",
        help="Analyze headers for suspicious patterns and anomalies",
    )

    headers_parser.add_argument(
        "--enrich",
        nargs="*",
        choices=["mx", "spamhaus", "domain_age", "all"],
        help="Add threat-intel enrichment to header analysis (mx, spamhaus, domain_age). Requires --heuristics.",
    )

    # ----ATTACHMENTS----
    attach_parser = subparsers.add_parser(
        "attachments", parents=[common], help="Analyze or extract attachments"
    )
    attach_parser.add_argument(
        "--list", action="store_true", help="List attachments only"
    )
    attach_parser.add_argument(
        "--extract", metavar="DIR", help="Extract attachments to specified directory"
    )
    attach_parser.add_argument(
        "--hash",
        action="store_true",
        help="Compute hashes (MD5, SHA1, SHA256) for each attachment",
    )
    attach_parser.add_argument(
        "--vt-scan",
        action="store_true",
        help="Check attachments against VirusTotal by SHA256",
    )
    attach_parser.add_argument(
        "--yara",
        type=str,
        nargs="+",
        metavar="PATH",
        help="Scan attachments with YARA rules. Paths can be files or directories; directories are scanned recursively for .yar/.yara files.",
    )
    attach_parser.add_argument(
        "--yara-verbose",
        action="store_true",
        help="Show detailed string matches and offsets when YARA rules hit",
    )

    # ----LINKS----
    link_parser = subparsers.add_parser(
        "links", parents=[common], help="Analyze links in email content"
    )
    link_parser.add_argument(
        "--extract", action="store_true", help="Extract URLs from the email body"
    )
    link_parser.add_argument(
        "--vt-scan",
        action="store_true",
        help="Query VirusTotal for URL reputation",
    )
    link_parser.add_argument(
        "--check-redirects",
        action="store_true",
        help="Follow HTTP redirects and show chain",
    )
    link_parser.add_argument(
        "--heuristics",
        action="store_true",
        help="Run phishing detection heuristics (use --enrich to add extra data)",
    )
    link_parser.add_argument(
        "--enrich",
        nargs="*",
        choices=["all", "domain_age", "certificate", "virustotal", "redirects"],
        help="Add extra analysis to heuristics (requires --heuristics)",
    )

    return parser
