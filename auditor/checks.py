"""Deterministic checks. Each takes a Repo and returns a list of Findings."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from auditor.findings import Finding
from auditor.repo import Repo

_PLACEHOLDER = re.compile(
    r"your[-_]?username|<your[-_ ]|\byour[-_]repo\b|lorem ipsum|TODO: ?(?:write|add|fill)",
    re.IGNORECASE,
)

_JUNK_NAMES = {".ds_store", "thumbs.db", ".coverage"}
_JUNK_SUFFIXES = {".pyc", ".log", ".swp", ".bak", ".orig"}
_JUNK_DIRS = {"__pycache__", ".pytest_cache", "node_modules"}
_SCRATCH_STEMS = {"notes", "daily-notes", "scratch", "todo", "tmp", "temp", "untitled"}

_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("API key (sk-...)", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
]

_ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

_METRIC_HEADING = re.compile(
    r"performance|metric|result|benchmark|evaluation|accuracy|latency", re.IGNORECASE)
_NUMBER_CLAIM = re.compile(
    r"\d+(?:\.\d+)?\s?%|\d+(?:\.\d+)?\s?(?:ms|req/s|qps|x)|(?<![\d.])0\.\d{2,}",
    re.IGNORECASE)
_HEDGE = re.compile(
    r"not (?:yet )?(?:been )?measured|illustrative|placeholder|example numbers|synthetic|to be measured",
    re.IGNORECASE)
_EVIDENCE_DIRS = {"results", "benchmarks", "evals", "eval", "reports", "metrics", "mlruns", "runs"}
_EVIDENCE_FILE = re.compile(
    r"(\.ipynb$)|((result|metric|benchmark|eval)[^/]*\.(json|csv|md|txt|html)$)", re.IGNORECASE)
_SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java"}
_TEST_FILE = re.compile(r"(^test_.*\.py$)|(_test\.py$)|(\.(test|spec)\.[jt]sx?$)|(_test\.go$)")


def _name(path: str) -> str:
    return PurePosixPath(path).name


def _readmes(repo: Repo) -> list:
    return [p for p in repo.files() if "/" not in p and _name(p).lower().startswith("readme")]


def check_readme(repo: Repo) -> list:
    readmes = _readmes(repo)
    if not readmes:
        return [Finding("readme", "medium", "", "No README at the repository root")]
    findings = []
    for path in readmes:
        text = repo.read_text(path) or ""
        if len(text.strip()) < 200:
            findings.append(Finding(
                "readme", "low", path, "README is nearly empty (under 200 characters)"))
    return findings


def check_placeholders(repo: Repo) -> list:
    findings = []
    for path in _readmes(repo):
        for number, line in enumerate((repo.read_text(path) or "").splitlines(), 1):
            match = _PLACEHOLDER.search(line)
            if match:
                findings.append(Finding(
                    "placeholder-text", "medium", path,
                    f"Placeholder left in the README: {match.group(0)!r}", number))
    return findings


def check_junk_files(repo: Repo) -> list:
    findings = []
    for path in repo.files():
        pure = PurePosixPath(path)
        name = pure.name.lower()
        reason = None
        if name in _JUNK_NAMES or pure.suffix.lower() in _JUNK_SUFFIXES:
            reason = "generated or editor file"
        elif _JUNK_DIRS.intersection(pure.parts[:-1]):
            reason = "generated directory"
        elif pure.stem.lower() in _SCRATCH_STEMS:
            reason = "looks like a scratch file"
        if reason:
            findings.append(Finding(
                "junk-file", "medium", path, f"Committed file that should not be tracked ({reason})"))
    return findings


def check_secrets(repo: Repo) -> list:
    findings = []
    for path in repo.files():
        name = _name(path).lower()
        if name == ".env" or (name.startswith(".env.") and not name.endswith(_ENV_TEMPLATE_SUFFIXES)):
            findings.append(Finding("secret", "high", path, "Environment file is tracked in git"))
            continue
        text = repo.read_text(path)
        if text is None:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for label, pattern in _SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Never echo the secret itself, only its first characters.
                    shown = match.group(0)[:4] + "..."
                    findings.append(Finding(
                        "secret", "high", path, f"Possible {label} ({shown})", number))
    return findings


def check_tests(repo: Repo) -> list:
    files = repo.files()
    has_source = any(PurePosixPath(p).suffix in _SOURCE_SUFFIXES for p in files)
    if not has_source:
        return []
    for path in files:
        pure = PurePosixPath(path)
        if {"tests", "test", "__tests__"}.intersection(pure.parts[:-1]) or _TEST_FILE.search(pure.name):
            return []
    return [Finding("tests", "medium", "", "Source code but no tests found")]


def check_pinned_requirements(repo: Repo) -> list:
    findings = []
    for path in repo.files():
        name = _name(path).lower()
        if not (name.startswith("requirements") and name.endswith(".txt")):
            continue
        unpinned = []  # (line number, requirement)
        for number, raw in enumerate((repo.read_text(path) or "").splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "http://", "https://", "git+")):
                continue
            if not re.search(r"[=<>!~@]", line):
                unpinned.append((number, line))
        if unpinned:
            # One finding per file, not one per line, so a bare requirements.txt
            # does not drown out everything else.
            names = ", ".join(name for _, name in unpinned[:3])
            more = f", ... ({len(unpinned)} in total)" if len(unpinned) > 3 else ""
            findings.append(Finding(
                "unpinned-dependency", "low", path,
                f"{len(unpinned)} requirement(s) have no version constraint: {names}{more}",
                unpinned[0][0]))
    return findings


def _metric_sections(text: str) -> list:
    """(heading, first line number, body lines) for each README section whose
    title suggests it reports measurements. A section ends at the next heading
    of the same or a higher level."""
    lines = text.splitlines()
    sections = []
    for index, line in enumerate(lines):
        match = re.match(r"(#{1,6})\s+(.*)", line)
        if not match or not _METRIC_HEADING.search(match.group(2)):
            continue
        level = len(match.group(1))
        if level == 1:
            continue  # the README title covers the whole file, not one section
        body = []
        for later in lines[index + 1:]:
            nxt = re.match(r"(#{1,6})\s", later)
            if nxt and len(nxt.group(1)) <= level:
                break
            body.append(later)
        sections.append((match.group(2).strip(), index + 1, body))
    return sections


def check_unsupported_metrics(repo: Repo) -> list:
    """Numbers in a results-style README section with nothing in the repo to back them."""
    files = repo.files()
    has_results = any(
        _EVIDENCE_DIRS.intersection(PurePosixPath(p).parts[:-1]) or _EVIDENCE_FILE.search(p)
        for p in files
    )
    findings = []
    for path in _readmes(repo):
        for heading, number, body in _metric_sections(repo.read_text(path) or ""):
            text = "\n".join(body)
            claims = [ln for ln in body if _NUMBER_CLAIM.search(ln)]
            if len(claims) < 2 or _HEDGE.search(text):
                continue
            if has_results or any(f in text for f in files if "/" in f or f.endswith((".py", ".json"))):
                continue
            findings.append(Finding(
                "unsupported-metrics", "medium", path,
                f"Section {heading!r} reports {len(claims)} figures, but the repo has no "
                "results file, notebook or script reference that produces them", number))
    return findings


def check_license(repo: Repo) -> list:
    for path in repo.files():
        if "/" not in path and _name(path).lower().startswith(("license", "licence", "copying")):
            return []
    return [Finding("license", "low", "", "No LICENSE file")]


CHECKS = [
    check_readme,
    check_placeholders,
    check_junk_files,
    check_secrets,
    check_tests,
    check_pinned_requirements,
    check_unsupported_metrics,
    check_license,
]
