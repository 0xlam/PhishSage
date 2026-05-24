from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class WhoisResult:
    domain: str
    created_at: datetime | None
    expires_at: datetime | None
    age_days: int | None
    expiry_days: int | None
    registrar: str | None = None