import argparse

def get_parser():
    parser = argparse.ArgumentParser(description="PhishSage")

    # ---- COMMON FLAGS (shared by all subcommands) ----  
    common = argparse.ArgumentParser(add_help=False)  
    common.add_argument(  
        "-f", "--file",  
        required=True,  
        help="Email file to analyze (.eml)"  
    )  
 
    # ---- SUBCOMMANDS ----  
    subparsers = parser.add_subparsers(dest="mode", required=True)

    #----HEADERS----
    headers_parser = subparsers.add_parser("headers", 
    	parents=[common],
    	help='Analyze email headers for anomalies or indicators'
    	)
    headers_parser.add_argument('--heuristics', action='store_true', help='Run heuristic header analysis for anomalies')
    headers_parser.add_argument( "--json", action="store_true", help='Output results in raw JSON format')

    #----ATTACHMENTS----
    attach_parser = subparsers.add_parser('attachment',
        parents=[common],
        help='Analyze or extract attachments')
    attach_parser.add_argument('--list', action='store_true', help='List attachments only')
    attach_parser.add_argument('--extract', metavar='DIR', help='Extract attachments to specified directory')
    attach_parser.add_argument('--hash', action='store_true', help='Compute hashes (MD5, SHA1, SHA256) for each attachment')
    attach_parser.add_argument('--scan', action='store_true', help='Check attachments against VirusTotal by SHA256')
    attach_parser.add_argument('--yara', type=str, nargs="+", metavar='PATH',
                              help='Scan attachments with YARA rules. Paths can be files or directories; directories are scanned recursively for .yar/.yara files.')
    attach_parser.add_argument('--yara-verbose',action='store_true',
                              help='Show detailed string matches and offsets when YARA rules hit')
    attach_parser.add_argument( "--json", action='store_true', help='Output results in raw JSON format')

    #----LINKS----
    link_parser = subparsers.add_parser('links',
    	parents=[common],
        help='Analyze links in email content')
    link_parser.add_argument('--extract', action='store_true', help='Extract all URLs found in the email body or headers')
    link_parser.add_argument('--scan', action='store_true', help='Submit extracted links to VirusTotal for analysis')
    

    mode_group = link_parser.add_mutually_exclusive_group()
    mode_group.add_argument('--check-redirects', action='store_true',
        help='Follow and display final redirect destinations for each URL')
    mode_group.add_argument('--heuristics', action='store_true',
        help='Run phishing heuristics on extracted URLs')

    link_parser.add_argument('--include-redirects', action='store_true',
        help='Include redirect chain when running heuristics (ignored if --heuristics not used)')
    link_parser.add_argument( "--json", action="store_true", help='Output results in raw JSON format')

    
    
    return parser

