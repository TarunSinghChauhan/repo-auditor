# repo-auditor

Audits a repository for the problems a reviewer notices in the first five minutes: placeholder text left in the README, committed scratch files, tracked secrets, no tests, unpinned dependencies, no license.

Status: early. The deterministic checks work and are tested. An LLM review layer (claims in the README that nothing in the repo supports) and an evaluation set of repos with known problems are planned.

## Usage

    python -m auditor path/to/repo
    python -m auditor path/to/repo --json
    python -m auditor path/to/repo --fail-on high    # exit 1 if any high finding

It reads `git ls-files` when the path is a git repository (so ignored files are not reported) and walks the directory otherwise. Secrets are never printed in full, only their first characters.

## Checks

| Check | Severity | Finds |
|---|---|---|
| secret | high | tracked `.env` files; AWS, GitHub, Slack and `sk-` keys; private keys |
| readme | medium / low | missing README; README under 200 characters |
| placeholder-text | medium | placeholder clone URLs and filler text left in the README |
| junk-file | medium | `.DS_Store`, `.log`, `.pyc`, `__pycache__`, `daily-notes.md`-style scratch files |
| unsupported-metrics | medium | a results-style README section full of figures (accuracy, latency, %) with no results file, notebook or script in the repo to back them |
| tests | medium | source code with no tests |
| unpinned-dependency | low | `requirements*.txt` lines with no version constraint |
| license | low | no LICENSE file |

## Tests

    pip install -e ".[dev]"
    python -m pytest
