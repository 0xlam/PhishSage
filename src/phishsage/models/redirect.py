from dataclasses import dataclass
from typing import List


@dataclass
class RedirectResult:
    original_url: str
    chain: List[str]
    status_codes: List[int]
    final_url: str
    final_status: int
    redirect_count: int
    redirected: bool