import subprocess

import pytest

from auditor.audit import audit
from auditor.checks import (
    check_junk_files, check_license, check_pinned_requirements,
    check_placeholders, check_readme, check_secrets, check_tests,
)
from auditor.repo import Repo
from tests.conftest import GOOD_README


def _checks(findings):
    return {f.check for f in findings}


def test_missing_readme_is_reported(make_repo):
    assert _checks(check_readme(Repo(make_repo({"a.py": "x = 1\n"})))) == {"readme"}


def test_tiny_readme_is_reported_and_good_one_is_not(make_repo):
    assert check_readme(Repo(make_repo({"README.md": "# hi\n"})))[0].severity == "low"


def test_good_readme_is_clean(make_repo):
    assert check_readme(Repo(make_repo({"README.md": GOOD_README}))) == []


def test_placeholder_clone_url_is_found_with_line_number(make_repo):
    text = GOOD_README + "\n```\ngit clone https://github.com/your-username/app.git\n```\n"
    findings = check_placeholders(Repo(make_repo({"README.md": text})))
    assert len(findings) == 1
    assert findings[0].line == text.splitlines().index("git clone https://github.com/your-username/app.git") + 1


def test_placeholders_only_looked_for_in_readmes(make_repo):
    repo = Repo(make_repo({"README.md": GOOD_README, "docs/x.md": "your-username"}))
    assert check_placeholders(repo) == []


@pytest.mark.parametrize("path", [
    ".DS_Store", "app.log", "m.pyc", ".coverage",
    "daily-notes.md", "notes.txt", "scratch.py", "Thumbs.db", "x.py.bak",
])
def test_junk_files_are_flagged(make_repo, path):
    findings = check_junk_files(Repo(make_repo({path: "x"})))
    assert [f.path for f in findings] == [path]


@pytest.mark.parametrize("path", ["README.md", "src/notes_parser.py", "docs/todo_list.md", "main.py"])
def test_normal_files_are_not_junk(make_repo, path):
    assert check_junk_files(Repo(make_repo({path: "x"}))) == []


def test_tracked_env_file_is_a_high_finding(make_repo):
    findings = check_secrets(Repo(make_repo({".env": "A=1\n", ".env.example": "A=\n"})))
    assert [(f.path, f.severity) for f in findings] == [(".env", "high")]


def test_secret_patterns_are_found_and_never_echoed(make_repo):
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    openai = "sk-" + "a" * 30
    repo = Repo(make_repo({
        "config.py": f'AWS = "{key}"\nOPENAI = "{openai}"\n',
        "k.pem": "-----BEGIN RSA " + "PRIVATE KEY-----\nabc\n",
    }))
    findings = check_secrets(repo)
    assert {(f.path, f.line) for f in findings} == {("config.py", 1), ("config.py", 2), ("k.pem", 1)}
    for f in findings:
        assert key not in f.message and openai not in f.message


def test_secrets_ignores_binary_files(make_repo, tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"\0AKIAABCDEFGHIJKLMNOP")
    assert check_secrets(Repo(tmp_path)) == []


def test_source_without_tests_is_flagged(make_repo):
    assert _checks(check_tests(Repo(make_repo({"app.py": "x = 1\n"})))) == {"tests"}


@pytest.mark.parametrize("test_path", ["tests/test_a.py", "a_test.py", "src/a.test.ts", "web/__tests__/x.js"])
def test_any_test_layout_counts(make_repo, test_path):
    assert check_tests(Repo(make_repo({"app.py": "x = 1\n", test_path: "x"}))) == []


def test_docs_only_repo_does_not_need_tests(make_repo):
    assert check_tests(Repo(make_repo({"README.md": GOOD_README}))) == []


def test_unpinned_requirements(make_repo):
    text = "# deps\nflask\nrequests>=2\n\n-r other.txt\nnumpy==1.26  # pinned\nfoo @ https://x/y.whl\n"
    findings = check_pinned_requirements(Repo(make_repo({"requirements.txt": text})))
    assert [(f.line, f.message.startswith("1 requirement(s)"), "flask" in f.message) for f in findings] == [(2, True, True)]


def test_unpinned_requirements_are_one_finding_per_file(make_repo):
    text = "".join(f"pkg{i}\n" for i in range(10))
    findings = check_pinned_requirements(Repo(make_repo({"requirements.txt": text})))
    assert len(findings) == 1
    assert "10 in total" in findings[0].message


def test_license_present(make_repo):
    assert check_license(Repo(make_repo({"LICENSE": "MIT"}))) == []


def test_license_missing(make_repo):
    assert _checks(check_license(Repo(make_repo({"a.py": "x"})))) == {"license"}


def test_audit_sorts_most_severe_first(make_repo):
    root = make_repo({".env": "A=1\n", "app.py": "x = 1\n", "README.md": GOOD_README})
    severities = [f.severity for f in audit(root)]
    assert severities[0] == "high"
    assert severities == sorted(severities, key=["high", "medium", "low"].index)


def test_uses_git_tracked_files_when_available(make_repo, tmp_path):
    make_repo({"tracked.py": "x = 1\n", "ignored.log": "noise\n", ".gitignore": "*.log\n"})
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "tracked.py", ".gitignore"], check=True)
    assert Repo(tmp_path).files() == [".gitignore", "tracked.py"]
    assert check_junk_files(Repo(tmp_path)) == []  # ignored.log is not tracked


def test_tracked_pycache_is_flagged_in_a_git_repo(make_repo, tmp_path):
    make_repo({"pkg/__pycache__/m.cpython-312.pyc": "x", "pkg/m.py": "x = 1\n"})
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-f", "."], check=True)
    paths = [f.path for f in check_junk_files(Repo(tmp_path))]
    assert paths == ["pkg/__pycache__/m.cpython-312.pyc"]


def test_this_repository_audits_clean():
    from pathlib import Path

    assert audit(Path(__file__).resolve().parents[1]) == []


def test_clean_repo_has_no_findings(make_repo):
    root = make_repo({
        "README.md": GOOD_README, "LICENSE": "MIT", "app.py": "x = 1\n",
        "tests/test_app.py": "def test_x():\n    pass\n", "requirements.txt": "flask==3.0\n",
    })
    assert audit(root) == []
