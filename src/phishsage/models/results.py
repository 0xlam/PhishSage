from dataclasses import dataclass, field
from typing import Any, Dict, List

@dataclass
class HeaderHeuristicResult:
    flags: bool
    result: dict
    alerts: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
