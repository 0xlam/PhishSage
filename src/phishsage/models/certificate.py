from dataclasses import dataclass

@dataclass(frozen=True)
class CertificateResult:
    issuer: str | None
    subject: str | None
    valid_from: str
    valid_to: str
    days_since_issued: int
    days_until_expiry: int