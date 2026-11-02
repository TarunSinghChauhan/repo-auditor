from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from auditor.audit import audit
from auditor.findings import SEVERITY_RANK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditor", description="Audit a repository for problems a reviewer would notice.")
    parser.add_argument("path", nargs="?", default=".", help="repository to audit (default: .)")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument(
        "--fail-on", choices=sorted(SEVERITY_RANK),
        help="exit with status 1 if any finding is at least this severe")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not Path(args.path).is_dir():
        print(f"auditor: no such directory: {args.path}", file=sys.stderr)
        return 2

    findings = audit(args.path)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif not findings:
        print("No findings.")
    else:
        for f in findings:
            where = f.path + (f":{f.line}" if f.line else "")
            print(f"[{f.severity.upper():6}] {f.check}: {where + ' - ' if where else ''}{f.message}")
        print(f"\n{len(findings)} finding(s).")

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] >= threshold for f in findings):
            return 1
    return 0
