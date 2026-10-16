from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARDS = ROOT / "guards"


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    """No guard switch from the developer's shell leaks into a test, and all
    state goes to a temporary plugin data dir."""
    for name in list(os.environ):
        if name.startswith("PREFLIGHT"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "plugin-data"))
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)


def run_guard(guard: str, payload: dict, env: dict | None = None, cwd: Path | None = None):
    """Run a guard as Claude Code does: a process with the payload on stdin."""
    full_env = {**os.environ, **(env or {})}
    return subprocess.run(
        [sys.executable, "-X", "utf8", str(GUARDS / f"{guard}.py")],
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
        env=full_env,
        cwd=str(cwd) if cwd else None,
        timeout=60,
    )


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, timeout=60)


@pytest.fixture
def repo(tmp_path):
    """A fresh git repository with one commit, isolated from global config."""
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q")
    git(path, "config", "user.email", "t@example.com")
    git(path, "config", "user.name", "t")
    (path / "README.md").write_text("hello\n", encoding="utf-8")
    git(path, "add", "README.md")
    git(path, "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "init")
    return path
