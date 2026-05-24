from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass(frozen=True)
class LinkHeuristicResult:
    name: str
    flags: str
    reasons: List[str]
    meta: Dict[str, Any]


@dataclass
class HeaderHeuristicResult:
    flags: bool
    result: dict
    alerts: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
