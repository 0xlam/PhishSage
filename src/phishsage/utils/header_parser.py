from dataclasses import dataclass
from typing import Any

from phishsage.utils.header_helpers import (
    normalize_header_value,
    get_domain,
    extract_email,
    generate_email_id,
    extract_display_name,
)
from phishsage.utils.dirty_parser import dirty_extract_email
from phishsage.utils.ip_analysis import extract_sender_ip


#------------------------------------------

@dataclass
class EmailHeaderInfo:
    display_name:str
    from_address: str
    from_email: str
    from_domain: str
    to_email: list[str]
    cc_email: list[str]
    bcc_email: list[str]
    reply_to_address: str
    reply_to_email: str
    reply_to_domain: str
    return_path: str
    return_path_email: str
    return_path_domain: str
    message_id: str
    message_id_domain: str
    auth_results: str
    date: str
    subject: str
    received_chain: list[str]
    mail_id: str
    sender_ip: str 


def parse_recipients(to_field):
    """Normalize recipient list to a comma-separated string"""
    if not to_field:
        return ""

    addresses = {normalize_header_value(addr.strip()) for _, addr in to_field if addr and addr.strip()}
    return ",".join(sorted(addresses))


def extract_mail_headers(mail: Any, raw_mail_bytes: Any) -> EmailHeaderInfo:
    headers = getattr(mail, "headers", {}) or {}

     # --- FROM ---
    from_address = normalize_header_value(headers.get("From", ""))
    from_email = extract_email(from_address) or dirty_extract_email(raw_mail_bytes)
    from_domain = get_domain(from_email)
    display_name = extract_display_name(from_address)

    # --- TO / CC / BCC ---
    to_email = parse_recipients(headers.get("To", ""))
    cc_email = parse_recipients(headers.get("Cc", ""))
    bcc_email = parse_recipients(headers.get("Bcc", ""))


    # --- REPLY-TO ---
    reply_to_address = normalize_header_value(headers.get("Reply-To", ""))
    reply_to_email = extract_email(reply_to_address)
    reply_to_domain = get_domain(reply_to_email)

    # --- RETURN-PATH ---
    return_path = normalize_header_value(getattr(mail, "return_path", "") or "")
    return_path_email = extract_email(return_path)
    return_path_domain = get_domain(return_path_email)

    # --- MESSAGE-ID ---
    message_id = getattr(mail, "message-id", "")
    message_id_domain = ""
    if isinstance(message_id, str) and "@" in message_id:
        _, domain = message_id.strip('<>').rsplit("@", 1)
        message_id_domain = get_domain(f"user@{domain}")

    # --- AUTH RESULTS ---
    auth_results = headers.get("Authentication-Results", "")

    # --- DATE & SUBJECT ---
    date = normalize_header_value(getattr(mail, "date", "") or "")
    subject = normalize_header_value(getattr(mail, "subject", "") or "")

    # --- RECEIVED CHAIN ---
    if hasattr(headers, "get_all"):  # email.message.Message
        received_values = headers.get_all("Received", [])
    else:  # dict-like fallback
        received_values = headers.get("Received", [])
        if isinstance(received_values, str):
            received_values = [received_values]
    received_chain = [normalize_header_value(h) for h in received_values]
    #print(received_chain)

    # --- SENDER IP ---
    sender_ip = extract_sender_ip(mail)

    # --- MAIL ID (unique identifier for logs/analysis) ---
    mail_id = generate_email_id(message_id, raw_mail_bytes, length=8)

    return EmailHeaderInfo(
        display_name=display_name,
        from_address=from_address,
        from_email=from_email,
        from_domain=from_domain,
        to_email=to_email,
        cc_email=cc_email,
        bcc_email=bcc_email,
        reply_to_address=reply_to_address,
        reply_to_email=reply_to_email,
        reply_to_domain=reply_to_domain,
        return_path=return_path,
        return_path_email=return_path_email,
        return_path_domain=return_path_domain,
        message_id=message_id,
        message_id_domain=message_id_domain,
        auth_results=auth_results,
        date=date,
        subject=subject,
        received_chain=received_chain,
        mail_id=mail_id,
        sender_ip=sender_ip
    )
