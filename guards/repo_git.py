"""Attack signs inside `.git`: executable config, active hooks, worm commits.

Scanning must not become the infection. A folder from an archive or a client
carries a `.git/config` written by the attacker: `log.showSignature = true`
plus `gpg.program = payload.exe`, or `core.fsmonitor`, turns a plain
`git log` into code execution. So the config is read as text first; a key that
runs a program is a `high` finding and git is then not started at all. With a
clean config, git still runs with the dangerous keys overridden on the command
line, which wins over the repository config.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from findings import HIGH, MEDIUM, Finding, finding
from repo_files import Unreadable, is_link, read_text

# Commit signature reported for the 2026 Shai-Hulud / ChainDrop npm worm wave.
WORM_AUTHOR, WORM_SUBJECT = "claude", "chore: update config"
GIT_TIMEOUT_S = 10
# Config keys whose value is a program or a path to one. A fresh clone's
# `.git/config` has only core/remote/branch sections and none of these.
# `[ \t]` rather than `\s`: `\s*` crosses newlines, and a config of blank lines
# made the search quadratic. A key may share its line with the section header
# (`[core] fsmonitor = x`), which git accepts.
_KEY_START = r"^[ \t]*(?:\[[^\]\n]*\][ \t]*)?"
EXEC_KEYS = re.compile(
    _KEY_START + r"(fsmonitor|hookspath|sshcommand|pager|editor|askpass|program|showsignature"
    r"|textconv|external|clean|smudge|process|helper|gitproxy|packobjectshook|path)[ \t]*=",
    re.I | re.M,
)
SHELL_ALIAS = re.compile(_KEY_START + r"[\w.-]+[ \t]*=[ \t]*!", re.M)
CONFIGS = (".git/config", ".git/config.worktree")
HARDENED = (
    "-c", "core.fsmonitor=false", "-c", "log.showSignature=false",
    "-c", "core.pager=cat",
)  # fmt: skip


def _config_keys(text: str) -> list[str]:
    keys = sorted({m.group(1).lower() for m in EXEC_KEYS.finditer(text)})
    if SHELL_ALIAS.search(text):
        keys.append("alias = !command")
    return keys


def check_git_config(root: Path) -> list[Finding]:
    git_dir = root / ".git"
    if is_link(git_dir):
        return [finding(HIGH, ".git", "`.git` is a link to somewhere else, not followed")]
    if git_dir.is_file():
        return [
            finding(
                MEDIUM, ".git", "`.git` is a file pointing at another gitdir; config not checked"
            )
        ]
    found = []
    for rel in CONFIGS:
        try:
            keys = _config_keys(read_text(root, rel) or "")
        except Unreadable as exc:
            found.append(finding(HIGH, rel, f"{exc}; git is not run"))
            continue
        if keys:
            found.append(finding(HIGH, rel, f"keys that run a program: {', '.join(keys)}"))
    return found


def check_git_hooks(root: Path) -> list[Finding]:
    """An active hook in `.git/hooks` runs on the next git command in the folder."""
    hooks = root / ".git" / "hooks"
    if not hooks.is_dir():
        return []
    active = sorted(
        p.name for p in hooks.iterdir() if p.is_file() and not p.name.endswith(".sample")
    )
    if not active:
        return []
    return [finding(HIGH, ".git/hooks", f"active git hooks: {', '.join(active)}")]


def _git_log(root: Path) -> str:
    cmd = [
        "git",
        *HARDENED,
        "-C",
        str(root),
        "log",
        "--no-show-signature",
        "-n",
        "500",
        "--format=%an%x1f%s",
    ]
    try:
        done = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GIT_TIMEOUT_S,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout


def check_history(root: Path, config_found: list[Finding]) -> list[Finding]:
    """Worm commits; git is not started when the config is already suspicious."""
    if config_found or not (root / ".git").is_dir():
        return []
    rows = [line.split("\x1f", 1) for line in _git_log(root).splitlines() if "\x1f" in line]
    hits = [r for r in rows if r[0].strip().lower() == WORM_AUTHOR and r[1].strip() == WORM_SUBJECT]
    if not hits:
        return []
    return [
        finding(
            HIGH,
            ".git",
            f"{len(hits)} commit(s) by author 'claude' titled 'chore: update config', a known worm signature",
        )
    ]


def check_git(root: Path) -> list[Finding]:
    config = check_git_config(root)
    return config + check_git_hooks(root) + check_history(root, config)
