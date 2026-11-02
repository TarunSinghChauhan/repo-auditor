import json

from auditor.cli import main
from tests.conftest import GOOD_README


def test_missing_directory_is_an_error(tmp_path, capsys):
    assert main([str(tmp_path / "nope")]) == 2
    assert "no such directory" in capsys.readouterr().err


def test_clean_repo_prints_no_findings(make_repo, capsys):
    root = make_repo({"README.md": GOOD_README, "LICENSE": "MIT"})
    assert main([str(root)]) == 0
    assert "No findings." in capsys.readouterr().out


def test_text_output_lists_findings(make_repo, capsys):
    assert main([str(make_repo({".env": "A=1\n"}))]) == 0
    out = capsys.readouterr().out
    assert "[HIGH  ] secret: .env" in out
    assert "finding(s)." in out


def test_json_output_is_valid(make_repo, capsys):
    main([str(make_repo({".env": "A=1\n"})), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["check"] == "secret" and data[0]["severity"] == "high"


def test_fail_on_sets_exit_status(make_repo):
    root = make_repo({"README.md": GOOD_README, "app.py": "x = 1\n"})  # medium: no tests
    assert main([str(root), "--fail-on", "high"]) == 0
    assert main([str(root), "--fail-on", "medium"]) == 1
