import re
import ipaddress


def extract_sender_ip(mail):
    """
    Extracts the sender IP from the 'Received' headers of an email.
    Returns the first valid IPv4 or IPv6 address found, or None if none found.
    """
    if not hasattr(mail, "received") or not mail.received:
        return None

    # Regex patterns for IPv4 and IPv6
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b'

    for hop in mail.received:
        header_from = hop.get("from", "")
        if not header_from:
            continue

        # Find all candidate IPs
        candidate_ips = re.findall(f"{ipv4_pattern}|{ipv6_pattern}", header_from)
        for ip in candidate_ips:
            try:
                # Validate the IP
                ip_obj = ipaddress.ip_address(ip)
                return str(ip_obj)
            except ValueError:
                continue  # invalid IP, skip it

    return None
