from typing import Any
from phishsage.models.email import EmailHeaderContext

from phishsage.utils import (
    normalize_header_value,
    get_domain,
    extract_email,
    generate_email_id,
    extract_display_name,
)
from .dirty_parser import dirty_extract_email
from .ip_extractor import extract_sender_ip

# ------------------------------------------


def parse_recipients(field) -> list[str]:
    """Normalize recipient list to a list of emails"""
    if not field:
        return []

    if isinstance(field, str):
        field = [(None, field)]

    if not isinstance(field, (list, tuple)):
        return []

    addresses = set()

    for item in field:
        addr = None

        if isinstance(item, tuple) and len(item) == 2:
            _, addr = item
        else:
            addr = item

        if addr and str(addr).strip():
            addresses.add(normalize_header_value(str(addr).strip()))

    return sorted(addresses)


def extract_mail_headers(mail: Any, raw_mail_bytes: Any) -> EmailHeaderContext:
    headers = getattr(mail, "headers", None) or {}

    # --- FROM ---
    from_address = normalize_header_value(headers.get("From", ""))
    from_email = extract_email(from_address) or dirty_extract_email(raw_mail_bytes)
    from_domain = get_domain(from_email or "")
    display_name = extract_display_name(from_address)

    # --- TO / CC / BCC ---
    to_email = parse_recipients(headers.get("To"))
    cc_email = parse_recipients(headers.get("Cc"))
    bcc_email = parse_recipients(headers.get("Bcc"))

    # --- REPLY-TO ---
    reply_to_address = normalize_header_value(headers.get("Reply-To", ""))
    reply_to_email = extract_email(reply_to_address)
    reply_to_domain = get_domain(reply_to_email or "")

    # --- RETURN-PATH ---
    return_path = normalize_header_value(getattr(mail, "return_path", "") or "")
    return_path_email = extract_email(return_path)
    return_path_domain = get_domain(return_path_email or "")

    # --- MESSAGE-ID ---
    message_id = getattr(mail, "message-id", "") or ""

    message_id_domain = ""
    cleaned_mid = message_id.strip("<>")

    if "@" in cleaned_mid:
        try:
            message_id_domain = cleaned_mid.rsplit("@", 1)[1].lower()
        except Exception:
            message_id_domain = ""

    # --- AUTH RESULTS ---
    auth_results = headers.get("Authentication-Results", "")

    # --- DATE & SUBJECT ---
    date = normalize_header_value(getattr(mail, "date", "") or "")
    subject = normalize_header_value(getattr(mail, "subject", "") or "")

    # --- RECEIVED CHAIN ---
    if hasattr(headers, "get_all"):
        received_values = headers.get_all("Received", [])
    else:
        received_values = headers.get("Received", [])
        if isinstance(received_values, str):
            received_values = [received_values]

    received_chain = [
        normalize_header_value(h)
        for h in received_values
        if h
    ]

    # --- SENDER IP ---
    sender_ip = extract_sender_ip(mail)

    # --- MAIL ID ---
    mail_id = generate_email_id(message_id, raw_mail_bytes, length=8)

    return EmailHeaderContext(
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
        sender_ip=sender_ip,
    )