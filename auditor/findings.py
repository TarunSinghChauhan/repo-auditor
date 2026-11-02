from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str  # "low" | "medium" | "high"
    path: str  # repo-relative, "" for repo-level findings
    message: str
    line: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def sort_key(self) -> tuple:
        return (-SEVERITY_RANK[self.severity], self.path, self.line or 0, self.check)
