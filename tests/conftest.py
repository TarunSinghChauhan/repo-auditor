import pytest


@pytest.fixture
def make_repo(tmp_path):
    """Build a throwaway directory from {relative_path: text}."""

    def _make(files):
        for rel, text in files.items():
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return tmp_path

    return _make


GOOD_README = "# Project\n\n" + "A real description of what this project does and how to run it. " * 5
