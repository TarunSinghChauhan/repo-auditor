from auditor.audit import audit
from auditor.checks import check_secrets, check_unsupported_metrics
from auditor.repo import Repo
from tests.conftest import GOOD_README

TABLE = """## Performance Metrics
| Model | Metric | Result |
|---|---|---|
| ViT | Top-1 Accuracy | 89.2% |
| Search | p99 Latency | 42ms |
| RAG | Groundedness | 0.94 |
"""


def _run(make_repo, files):
    return check_unsupported_metrics(Repo(make_repo(files)))


def test_numbers_with_nothing_behind_them_are_flagged(make_repo):
    findings = _run(make_repo, {"README.md": GOOD_README + "\n" + TABLE, "app.py": "x = 1\n"})
    assert len(findings) == 1
    f = findings[0]
    assert (f.check, f.severity, f.path) == ("unsupported-metrics", "medium", "README.md")
    assert "3 figures" in f.message
    assert f.line == (GOOD_README + "\n" + TABLE).splitlines().index("## Performance Metrics") + 1


def test_a_results_directory_counts_as_evidence(make_repo):
    assert _run(make_repo, {"README.md": TABLE, "results/run1.json": "{}"}) == []


def test_a_notebook_counts_as_evidence(make_repo):
    assert _run(make_repo, {"README.md": TABLE, "analysis.ipynb": "{}"}) == []


def test_naming_the_script_that_produces_the_numbers_counts(make_repo):
    readme = TABLE + "\nReproduce with `scripts/evaluate.py`.\n"
    assert _run(make_repo, {"README.md": readme, "scripts/evaluate.py": "x = 1\n"}) == []


def test_mentioning_a_file_that_does_not_exist_does_not_count(make_repo):
    readme = TABLE + "\nReproduce with `scripts/evaluate.py`.\n"
    assert len(_run(make_repo, {"README.md": readme})) == 1


def test_an_honest_not_measured_note_is_respected(make_repo):
    readme = TABLE + "\nThese figures are illustrative and have not been measured.\n"
    assert _run(make_repo, {"README.md": readme}) == []


def test_a_single_number_in_prose_is_not_enough(make_repo):
    readme = "## Results\nThe cache hit rate was 75% on repeated queries.\n"
    assert _run(make_repo, {"README.md": readme}) == []


def test_percentages_outside_a_results_section_are_ignored(make_repo):
    readme = "## Features\n- 100% offline\n- 0.5x memory\n- 99% typed\n"
    assert _run(make_repo, {"README.md": readme}) == []


def test_section_ends_at_the_next_heading_of_the_same_level(make_repo):
    readme = "## Results\nSee the paper.\n\n## Notes\n- 10%\n- 20%\n"
    assert _run(make_repo, {"README.md": readme}) == []


def test_subsections_belong_to_their_results_section(make_repo):
    readme = "## Results\n### Search\n- p95 80ms\n- p99 120ms\n"
    assert len(_run(make_repo, {"README.md": readme})) == 1


def test_a_title_that_mentions_evaluation_is_not_a_results_section(make_repo):
    readme = "# Evaluation Harness\n- 99%\n- 98%\n- 97ms\n"
    assert _run(make_repo, {"README.md": readme}) == []


def test_it_runs_as_part_of_a_normal_audit(make_repo):
    root = make_repo({"README.md": GOOD_README + "\n" + TABLE, "LICENSE": "MIT"})
    assert [f.check for f in audit(root)] == ["unsupported-metrics"]


def test_env_template_variants_are_not_secrets(make_repo):
    files = {
        ".env.example": "A=\n", ".env.local.example": "A=\n", ".env.sample": "A=\n",
        ".env.template": "A=\n", ".env.production.dist": "A=\n",
    }
    assert check_secrets(Repo(make_repo(files))) == []


def test_real_env_variants_are_still_flagged(make_repo):
    findings = check_secrets(Repo(make_repo({".env.local": "A=1\n", ".env.production": "A=1\n"})))
    assert sorted(f.path for f in findings) == [".env.local", ".env.production"]
