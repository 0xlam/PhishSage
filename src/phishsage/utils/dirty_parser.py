import re
from email.header import decode_header, make_header
from email.utils import parseaddr
from phishsage.utils.header_helpers import validate_and_normalize_email

_ADDR_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+")

def _decode_header_value(value):
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value

def dirty_extract_email(raw_email_bytes):
    # Isolate headers
    match = re.split(rb"\r?\n\r?\n", raw_email_bytes, 1)
    header_bytes = match[0] if match else b""
    headers = re.sub(r"\r?\n[ \t]+", " ", header_bytes.decode("utf-8", "replace"))

    # Try key headers
    for name in ("From", "Sender"):
        m = re.search(fr"(?im)^{re.escape(name)}\s*:\s*(.+)$", headers)
        if not m:
            continue
        decoded = _decode_header_value(m.group(1).strip())
        _, email = parseaddr(decoded)
        if not email:
            m2 = _ADDR_RE.search(decoded)
            if m2:
                email = m2.group(0)
        if email:
            return validate_and_normalize_email(email.strip())

    return ""
