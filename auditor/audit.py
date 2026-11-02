from __future__ import annotations

from auditor.checks import CHECKS
from auditor.findings import Finding
from auditor.repo import Repo


def audit(root) -> list:
    """Run every check on the repository at `root`; most severe findings first."""
    repo = Repo(root)
    findings = [f for check in CHECKS for f in check(repo)]
    return sorted(findings, key=Finding.sort_key)
