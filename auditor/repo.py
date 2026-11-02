from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional

MAX_TEXT_BYTES = 1_000_000
_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
}


class Repo:
    """A directory to audit. Uses `git ls-files` when it can, else walks the tree."""

    def __init__(self, root):
        self.root = Path(root).resolve()
        self._files: Optional[list] = None

    def files(self) -> list:
        """Repo-relative POSIX paths of the files an audit should look at."""
        if self._files is None:
            self._files = sorted(self._git_files() or self._walk_files())
        return self._files

    def _git_files(self) -> Optional[list]:
        try:
            out = subprocess.run(
                ["git", "-C", str(self.root), "ls-files", "-z"],
                capture_output=True, check=True, timeout=30,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        names = [n for n in out.decode("utf-8", "replace").split("\0") if n]
        # An empty list means "not a git repo" (or nothing tracked): fall back.
        return [n for n in names if (self.root / n).is_file()] or None

    def _walk_files(self) -> list:
        found = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                full = Path(dirpath) / name
                found.append(full.relative_to(self.root).as_posix())
        return found

    def read_text(self, rel: str) -> Optional[str]:
        """File contents, or None if it is binary, huge or unreadable."""
        path = self.root / rel
        try:
            if path.stat().st_size > MAX_TEXT_BYTES:
                return None
            data = path.read_bytes()
        except OSError:
            return None
        if b"\0" in data:
            return None
        return data.decode("utf-8", "replace")
