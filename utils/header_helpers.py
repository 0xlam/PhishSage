import re
import os
import io
import hashlib
from pathlib import Path

import idna
import tldextract
import email
from email.utils import parseaddr
from email.header import decode_header
from email_validator import validate_email, EmailNotValidError


def normalize_domain(domain):
    """Normalize domain: lowercase, strip trailing dot, IDNA-encode."""
    if not domain:
        return None
    domain = domain.strip().lower().rstrip('.')
    try:
        domain_ascii = idna.encode(domain).decode('ascii')
    except idna.IDNAError:
        return None
    return domain_ascii


def normalize_header_value(value):
    """
    Normalize header value by
    """
    if value is None:
        return ""

    if isinstance(value, (list, tuple)):
        value = " ".join(str(v).strip() for v in value if v)
    else:
        value = str(value).strip()

    return value.strip(",;<>\"' \t\r\n")


def validate_and_normalize_email(email):
    """Validate email with email_validator and return normalized email or None."""
    if not email or '@' not in email:
        return None
    try:
        v = validate_email(email, allow_smtputf8=True, check_deliverability=False)
        return v.email
    except EmailNotValidError:
        return None


def extract_email(value):
    """
    Extract a valid email from input string or list/tuple of strings.
    Attempts parseaddr first, then regex fallback.
    Returns normalized, validated email or None.
    """
    if not value:
        return None

    if isinstance(value, (list, tuple)):
        value = " ".join(str(x) for x in value if x)
    else:
        value = str(value)

    _, email_addr = parseaddr(value)
    email_addr = validate_and_normalize_email(email_addr)
    if email_addr:
        return email_addr

    regex = re.compile(
        r'([a-zA-Z0-9._%+-]{1,64})@([a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63})+)',
        re.ASCII
    )
    match = regex.search(value)
    if not match:
        return None

    candidate = f"{match.group(1)}@{match.group(2)}"
    return validate_and_normalize_email(candidate)


def get_domain(email):
    """Extract and normalize domain part from a validated email."""
    if not email or '@' not in email:
        return None
    try:
        domain = email.split('@')[1]
        return normalize_domain(tldextract.extract(domain).top_domain_under_public_suffix)
    except IndexError:
        return None


def is_domain_match(parent_domain, child_domain):
    """Check if child domain belongs to the same base domain as parent."""
    parent_norm = normalize_domain(parent_domain)
    child_norm = normalize_domain(child_domain)

    if not parent_norm or not child_norm:
        return False

    try:
        parent_sld = tldextract.extract(parent_norm).top_domain_under_public_suffix
        child_sld = tldextract.extract(child_norm).top_domain_under_public_suffix
    except Exception:
        return False

    if not parent_sld or not child_sld:
        return False

    return parent_sld == child_sld


def extract_display_name(raw_from):
    """
    Extract a display name from an email From header.
    """
    pass


def generate_email_id(msg_id, raw_mail_bytes, length=8):
    """Generate a short deterministic email ID."""
    if msg_id:
        normalized = msg_id.strip().lower().encode("utf-8")
        digest = hashlib.sha256(normalized).hexdigest()
        return digest[:length]

    if raw_mail_bytes:
        digest = hashlib.sha256(raw_mail_bytes).hexdigest()
        return digest[:length]

    raise ValueError("Either msg_id or raw_mail_bytes must be provided")


DATE_PATTERN = r"""
    (?:Mon|Tue|Wed|Thu|Fri|Sat|Sun,)?
    \s*\d{1,2}\s
    (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s
    \d{4}\s
    \d{2}:\d{2}:\d{2}\s[+-]\d{4}
"""


def earliest_received_date(received_headers):
    """
    Takes a list of Received headers (top to bottom in the email)
    and returns the datetime closest to the sender.
    """
    for header in reversed(received_headers):
        while '(' in header:
            header = re.sub(r'\([^()]*\)', '', header)
        match = re.search(DATE_PATTERN, header, re.VERBOSE)
        if match:
            date_str = match.group(0).strip()
            try:
                return date_str
            except Exception:
                return None
    return None



