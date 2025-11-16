import argparse

def get_parser():
    parser = argparse.ArgumentParser(description="PhishSage")

    subparsers = parser.add_subparsers(dest="mode", required=True)

    #----HEADERS----
    headers_parser = subparsers.add_parser("headers", help='Analyze email headers for anomalies or indicators')
    headers_parser.add_argument('-f', '--file', required=True, help='Email file to analyze (.eml)')
    headers_parser.add_argument('--heuristics', action='store_true', help='Run heuristic header analysis for anomalies')

    #----ATTACHMENTS----
    attach_parser = subparsers.add_parser('attachment', help='Analyze or extract attachments')
    attach_parser.add_argument('-f', '--file', required=True, help='Email file to process')
    attach_parser.add_argument('--list', action='store_true', help='List attachments only')
    attach_parser.add_argument('--extract', metavar='DIR', help='Extract to directory')
    attach_parser.add_argument('--hash', action='store_true', help='Hash each file')
    attach_parser.add_argument('--scan', action='store_true', help='Check VirusTotal')

    #----LINKS----
    link_parser = subparsers.add_parser('links', help='Analyze links in email content')
    link_parser.add_argument('-f', '--file', required=True, help='Email file to analyze')
    link_parser.add_argument('--extract', action='store_true', help='Extract all URLs found in the email body or headers')
    link_parser.add_argument('--scan', action='store_true', help='Submit extracted links to VirusTotal for analysis')
    

    mode_group = link_parser.add_mutually_exclusive_group()
    mode_group.add_argument('--check-redirects', action='store_true',
        help='Follow and display final redirect destinations for each URL')
    mode_group.add_argument('--heuristics', action='store_true',
        help='Run phishing heuristics on extracted URLs')

    link_parser.add_argument('--include-redirects', action='store_true',
        help='Include redirect chain when running heuristics (ignored if --heuristics not used)')

    
    
    return parser
