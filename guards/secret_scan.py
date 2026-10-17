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

import functools
import os
import subprocess
from pathlib import Path

import _common as c
from git_commands import Commit, find_commits
from secret_patterns import PRAGMA, find_secrets

GUARD = "secrets"
GIT_TIMEOUT_S = 8
MAX_UNTRACKED_FILES = 500
MAX_FILE_BYTES = 1_000_000
# Repository config that would otherwise run a program during `git diff`
# (filters are switched off per scan, see `_filter_overrides`). Without
# `core.quotepath=false` a non-ASCII path (`проект/.env`) came back as octal
# escapes, and the finding named a file nobody could recognise.
SAFE_GIT = ("git", "-c", "core.fsmonitor=false", "-c", "core.quotepath=false")


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
    except (OSError, ValueError, subprocess.SubprocessError):  # ValueError: a NUL in a path
        return ""
    return done.stdout.decode("utf-8", errors="replace") if done.returncode == 0 else ""


@functools.lru_cache(maxsize=32)
def _filter_overrides(repo: Path) -> tuple[str, ...]:
    """`-c` for every filter in the repository's config: `clean` becomes `cat`,
    `process` empty.

    `git diff` of the working tree runs files through `filter.<name>.clean`, and
    neither `--no-ext-diff` nor `--no-textconv` turns that off: a filter from a
    hostile `.git/config` would run inside the scan. Reading the config runs
    nothing; `--attr-source` does not help, `.git/info/attributes` still applies.
    """
    listed = _git(repo, "config", "--name-only", "--get-regexp", r"^filter\..*\.(clean|process)$")
    names = {key[len("filter.") :].rsplit(".", 1)[0] for key in listed.split("\n") if key}
    out: list[str] = []
    for name in sorted(names):
        out += ["-c", f"filter.{name}.clean=cat", "-c", f"filter.{name}.process="]
    return tuple(out)


def _git_diff(repo: Path, *args: str) -> str:
    flags = ("--unified=0", "--no-color", "--no-ext-diff", "--no-textconv", "--text")
    return _git(repo, *_filter_overrides(repo), "diff", *flags, *args)


def untracked_as_diff(
    repo: Path, pathspecs: tuple[str, ...], ignored: bool = False
) -> tuple[str, list[str]]:
    """(untracked files under the pathspecs shaped as added lines, what was not read).

    `ignored`: `git add -f` stages ignored files too. What is not read (over
    `MAX_FILE_BYTES`, beyond `MAX_UNTRACKED_FILES`) comes back as a finding, not
    as silence: silence would read as "no secrets".
    """
    top = _git(repo, "rev-parse", "--show-toplevel").strip()
    standard = () if ignored else ("--exclude-standard",)
    listed = _git(repo, "ls-files", "-z", "-o", *standard, "--full-name", "--", *pathspecs)
    if not top or not listed:
        return "", []
    names = [n for n in listed.split("\0") if n]
    notes = []
    if len(names) > MAX_UNTRACKED_FILES:
        notes.append(f"{len(names) - MAX_UNTRACKED_FILES} more untracked files were not read")
    parts = []
    for rel in names[:MAX_UNTRACKED_FILES]:
        path = Path(top) / rel
        try:
            if path.is_symlink():
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                notes.append(f"{rel}: larger than {MAX_FILE_BYTES} bytes, not read")
                continue
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            continue
        body = "\n".join("+" + line for line in text.split("\n"))
        parts.append(f"diff --git a/{rel} b/{rel}\n+++ b/{rel}\n@@ untracked @@\n{body}")
    return "\n".join(parts), notes


@functools.lru_cache(maxsize=64)
def toplevel(where: Path) -> str:
    """Root of the repository the directory is in; empty when it is not one."""
    return os.path.normcase(_git(where, "rev-parse", "--show-toplevel").strip())


def staged_for(commit: Commit) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(pathspecs of every `git add` into this repository, those of them with `-f`)."""
    top = toplevel(commit.repo)
    mine = [s for s in commit.staged if top and toplevel(s.where) == top]
    every = tuple(dict.fromkeys(s.pathspec for s in mine))
    return every, tuple(dict.fromkeys(s.pathspec for s in mine if s.forced))


def commit_diff(commit: Commit) -> tuple[str, list[str]]:
    """(what this commit will record, as diff text; what could not be read)."""
    diff, notes = [_git_diff(commit.repo, "--cached")], []
    if commit.all_tracked:
        diff.append(_git_diff(commit.repo))
    elif commit.paths:
        diff.append(_git_diff(commit.repo, "--", *commit.paths))
    added, forced = staged_for(commit)
    if added:
        diff.append(_git_diff(commit.repo, "--", *added))
    for specs, ignored in ((added, False), (forced, True)):
        if specs:
            text, skipped = untracked_as_diff(commit.repo, specs, ignored=ignored)
            diff.append(text)
            notes += skipped
    return "\n".join(diff), notes


def commits_of(command: str, payload: dict) -> list[Commit]:
    """The commits of the command; an unparseable command commits where it runs.

    `cd "$REPO"` and `git -C "$(...)"` are taken literally and do not exist:
    then the commit most likely happens here, so scan the working directory
    rather than nothing.
    """
    base = c.base_dir(payload)
    commits = find_commits(command, base, payload.get("tool_name") == "PowerShell")
    if commits is None:
        commits = [Commit(base, "-a" in command, ())]
    found = [cm if cm.repo.is_dir() else cm._replace(repo=base) for cm in commits]
    return list(dict.fromkeys(found))  # 50 identical commits are one scan


def main() -> int:
    if c.off_switch(GUARD):
        return 0
    payload = c.read_payload()
    command = str(c.tool_input(payload).get("command") or "")
    if "commit" not in command:
        return 0
    hits = []
    for commit in commits_of(command, payload):
        diff, skipped = commit_diff(commit)
        hits += find_secrets(diff) + skipped
    if not hits:
        return 0
    c.log(GUARD, {"hits": [h.split(": ")[0] for h in hits][:20]})
    return c.block(
        "preflight/secrets: the commit would record what looks like a secret.",
        hits[:10],
        "Move the value to an untracked .env (or a secret store) and unstage the "
        "file with `git restore --staged <file>`. If the line is a deliberate fake, "
        f"mark it with `{PRAGMA}` in a comment.",
    )


if __name__ == "__main__":
    c.run(GUARD, main)
