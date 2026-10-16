"""PreToolUse on Bash and PowerShell: block a git commit that carries a secret.

`.env` in `.gitignore` is not enough. Secrets leak through hardcoded tokens in
one-off scripts, test fixtures and copied configs, and once a commit is pushed
the secret lives in history even after the file is fixed.

The guard reads exactly what each `git commit` in the command will record:

* the staged diff;
* unstaged changes to tracked files for `commit -a` and for paths named on the
  commit line;
* whatever a `git add` earlier in the same command will stage, including the
  content of untracked files, because `git add -A && git commit` is the most
  common way an agent commits and the guard runs before either half.

The diff runs with the repository's own diff programs switched off
(`core.fsmonitor`, external diff, textconv): scanning must not execute code
from the repository's config. Binary-looking and UTF-16 files are read as text.
Matches are shown masked: the guard must not copy the secret into the
transcript it is trying to keep it out of.

A line that is a deliberate fake (a test fixture, an example) is skipped when
it carries `pragma: allowlist secret`, the convention detect-secrets uses.
Off switch: PREFLIGHT_SECRETS=0.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import _common as c
from git_commands import Commit, find_commits
from secret_patterns import PRAGMA, find_secrets

GUARD = "secrets"
GIT_TIMEOUT_S = 8
MAX_UNTRACKED_FILES = 500
MAX_FILE_BYTES = 1_000_000
# Repository config that would otherwise run a program during `git diff`.
SAFE_GIT = ("git", "-c", "core.fsmonitor=false")


def _git(repo: Path, *args: str) -> str:
    """Output of a git command in `repo`; empty on any failure (fail open).

    Read as bytes and decoded by hand: text mode turns a lone "\\r" into a line
    break, and the rest of that line would lose its "+" and its secret.
    """
    try:
        done = subprocess.run(
            [*SAFE_GIT, "-C", str(repo), *args],
            capture_output=True,
            timeout=GIT_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout.decode("utf-8", errors="replace") if done.returncode == 0 else ""


def _git_diff(repo: Path, *args: str) -> str:
    flags = ("--unified=0", "--no-color", "--no-ext-diff", "--no-textconv", "--text")
    return _git(repo, "diff", *flags, *args)


def untracked_as_diff(repo: Path, pathspecs: tuple[str, ...]) -> str:
    """Untracked, non-ignored files under the pathspecs, shaped as added lines."""
    top = _git(repo, "rev-parse", "--show-toplevel").strip()
    listed = _git(
        repo, "ls-files", "-z", "-o", "--exclude-standard", "--full-name", "--", *pathspecs
    )
    if not top or not listed:
        return ""
    parts = []
    for rel in [p for p in listed.split("\0") if p][:MAX_UNTRACKED_FILES]:
        path = Path(top) / rel
        try:
            if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            continue
        body = "\n".join("+" + line for line in text.split("\n"))
        parts.append(f"diff --git a/{rel} b/{rel}\n+++ b/{rel}\n@@ untracked @@\n{body}")
    return "\n".join(parts)


def commit_diff(commit: Commit) -> str:
    """What this commit will record, as diff text."""
    diff = [_git_diff(commit.repo, "--cached")]
    if commit.all_tracked:
        diff.append(_git_diff(commit.repo))
    elif commit.paths:
        diff.append(_git_diff(commit.repo, "--", *commit.paths))
    if commit.added:
        diff.append(_git_diff(commit.repo, "--", *commit.added))
        diff.append(untracked_as_diff(commit.repo, commit.added))
    return "\n".join(diff)


def main() -> int:
    if c.off_switch(GUARD):
        return 0
    payload = c.read_payload()
    command = str(c.tool_input(payload).get("command") or "")
    if "commit" not in command:
        return 0
    base = c.base_dir(payload)
    commits = find_commits(command, base, payload.get("tool_name") == "PowerShell")
    if commits is None:  # unparseable: scan the obvious place rather than none
        commits = [Commit(base, "-a" in command, ())]
    hits = [hit for commit in commits for hit in find_secrets(commit_diff(commit))]
    if not hits:
        return 0
    c.log(GUARD, {"hits": [h.split(": ")[0] for h in hits]})
    return c.block(
        "preflight/secrets: the commit would record what looks like a secret.",
        hits[:10],
        "Move the value to an untracked .env (or a secret store) and unstage the "
        "file with `git restore --staged <file>`. If the line is a deliberate fake, "
        f"mark it with `{PRAGMA}` in a comment.",
    )


if __name__ == "__main__":
    c.run(GUARD, main)
