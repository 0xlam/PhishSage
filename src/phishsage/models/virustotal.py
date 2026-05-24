from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class VirusTotalStats:
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0


@dataclass(frozen=True)
class VirusTotalResult:
    status: str
    resource: str
    stats: VirusTotalStats | None
    last_analysis_date: datetime | None = None
    first_submission_date: datetime | None = None
    error: str | None = None