"""Which `git commit`s a shell command makes, and what it stages on the way.

Parsing, not regexes: `git -C other commit` and `cd other && git commit` commit
in another repository, and the words "git commit" inside a message or heredoc
commit nothing. The most common agent idiom stages and commits in one command
(`git add -A && git commit -m ...`), and the guard runs before either happens,
so the `git add` pathspecs are carried over to the commit that follows.

Commands wrapped in `bash -c '...'`, `powershell -Command "..."` or
`cmd /c ...` are unwrapped and parsed too.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

import _common as c
import shell_words as sw
import wrappers

# `git commit` options that take the next word as their value.
COMMIT_VALUE_OPTS = frozenset(
    {"-m", "--message", "-F", "--file", "-c", "-C", "--reuse-message",
     "--reedit-message", "--author", "--date", "--cleanup", "-t", "--template",
     "--fixup", "--squash", "--trailer", "--pathspec-from-file"}
)  # fmt: skip
# Short flags of `git commit` that take a value (attached, or the next word).
VALUE_SHORT = "mFcCt"
GIT_VALUE_OPTS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"})
ADD_VALUE_OPTS = frozenset({"--chmod", "--pathspec-from-file"})
ALL = ":/"  # pathspec for the whole working tree, from any subdirectory
MAX_DEPTH = 3


class Commit(NamedTuple):
    repo: Path
    all_tracked: bool  # -a / --all
    paths: tuple[str, ...]  # pathspec on the commit command line
    added: tuple[str, ...] = ()  # pathspecs `git add`ed earlier in the same command


def git_subcommand(words: list[str], here: Path) -> tuple[str, list[str], Path] | None:
    """(subcommand, its arguments, directory it runs in) for a git command."""
    if not words or sw.command_name(words[0]) != "git":
        return None
    repo, i = here, 1
    while i < len(words) and words[i].startswith("-"):
        if words[i] == "-C" and i + 1 < len(words):
            repo = c.resolve_path(repo, words[i + 1])
        i += 2 if words[i] in GIT_VALUE_OPTS else 1
    if i >= len(words):
        return None
    return words[i], words[i + 1 :], repo


def _short_cluster(word: str) -> tuple[bool, bool]:
    """(has -a, takes the next word as a value) for a cluster like `-am`."""
    for k, flag in enumerate(word[1:], start=1):
        if flag in VALUE_SHORT:
            return "a" in word[1:k], k == len(word) - 1
    return "a" in word[1:], False


def commit_args(rest: list[str]) -> tuple[bool, list[str]]:
    """(-a/--all given, pathspec words) from the arguments after `commit`."""
    all_tracked, paths, j = False, [], 0
    while j < len(rest):
        word = rest[j]
        j += 1
        if word == "--":
            return all_tracked, paths + rest[j:]
        if word in COMMIT_VALUE_OPTS:
            j += 1
        elif word == "--all":
            all_tracked = True
        elif re.fullmatch(r"-[a-zA-Z]+", word):
            has_all, takes_value = _short_cluster(word)
            all_tracked = all_tracked or has_all
            j += takes_value
        elif not word.startswith("-"):
            paths.append(word)
    return all_tracked, paths


def add_args(rest: list[str]) -> list[str]:
    """Pathspecs `git add` stages; `-A`, `--all` and `-u` mean the whole tree."""
    paths, j = [], 0
    while j < len(rest):
        word = rest[j]
        j += 1
        if word == "--":
            return paths + rest[j:]
        if word in ADD_VALUE_OPTS:
            j += 1
        elif word in ("-A", "--all", "-u", "--update", "--no-ignore-removal"):
            paths.append(ALL)
        elif not word.startswith("-"):
            paths.append(word)
    return paths


def find_commits(
    command: str, base: Path, powershell: bool, depth: int = 0, added: dict | None = None
) -> list[Commit] | None:
    """Every `git commit` in the command, following `cd`; None if unparseable."""
    commands = sw.walk_commands(command, base, powershell)
    if commands is None:
        return None
    found: list[Commit] = []
    added = {} if added is None else added
    for words, here in commands:
        # A commit over ssh is the remote host's, not this repository's: ssh=False.
        inner = wrappers.inner_command(words) if depth < MAX_DEPTH else None
        if inner is not None:
            found += find_commits(inner[0], here, inner[1], depth + 1, added) or []
        else:
            _record(words, here, found, added)
    return found


def _record(words: list[str], here: Path, found: list[Commit], added: dict) -> None:
    """Note a `git add` for later commits, or append a `git commit`."""
    parsed = git_subcommand(words, here)
    if parsed is None:
        return
    sub, rest, repo = parsed
    if sub in ("add", "stage"):
        added.setdefault(repo, []).extend(add_args(rest))
    elif sub == "commit":
        all_tracked, paths = commit_args(rest)
        found.append(Commit(repo, all_tracked, tuple(paths), tuple(added.get(repo, ()))))
