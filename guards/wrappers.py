"""The command hidden inside another one: `bash -c '...'`, `pwsh -Command ...`,
`cmd /c ...`, `docker exec c ...`, `wsl ...` and, on request, `ssh host '...'`.

A guard that reads only the outer command misses what the inner one does: to
a shell parser, `ssh prod "rm -rf /var/www"` is one word in quotes, but on the
server it is a recursive delete.
"""

from __future__ import annotations

import re
import shlex

from shell_words import command_name

POSIX_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
POWERSHELLS = frozenset({"powershell", "pwsh"})
# Commands that run their arguments on another host.
REMOTE = frozenset({"ssh", "autossh", "mosh"})
# ssh options that take the next word as their value (autossh adds -M).
SSH_VALUE_OPTS = frozenset(
    "-b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w -B -M --ssh".split()
)
# Launchers whose arguments after their own options are the command:
# name -> options that take a value.
LAUNCHERS = {
    "sshpass": frozenset({"-p", "-f", "-d", "-P"}),
    "wsl": frozenset({"-d", "--distribution", "-u", "--user", "--cd"}),
}
EXEC_VALUE_OPTS = frozenset({"-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file", "-c"})


def _after_options(words: list[str], start: int, values: frozenset) -> int:
    """Index of the first word after the options that start at `start`; `--` ends them."""
    i = start
    while i < len(words) and words[i].startswith("-"):
        if words[i] == "--":
            return i + 1
        i += 2 if words[i] in values else 1
    return i


def _remote(words: list[str]) -> str | None:
    """The remote command of `ssh [options] host [options] [--] command...`."""
    host = _after_options(words, 1, SSH_VALUE_OPTS)
    rest = words[_after_options(words, host + 1, SSH_VALUE_OPTS) :]
    return " ".join(rest) if rest else None  # ssh itself joins the words with spaces


def _exec(words: list[str], head: str) -> str | None:
    """The command of `docker exec [opts] container cmd...` or `kubectl exec pod -- cmd...`."""
    if words[1:2] != ["exec"]:
        return None
    if head == "kubectl":
        rest = words[words.index("--") + 1 :] if "--" in words else []
    else:
        rest = words[_after_options(words, 2, EXEC_VALUE_OPTS) + 1 :]
    return shlex.join(rest) if rest else None


def _launched(words: list[str], head: str) -> str | None:
    """The command of `sshpass -p x ssh ...`, `wsl -d Ubuntu rm ...`, `su user -c '...'`."""
    if head == "su":
        at = next((i for i, w in enumerate(words[:-1]) if w in ("-c", "--command")), -1)
        return words[at + 1] if at >= 0 else None
    # `wsl -e rm ...`: -e takes no value, so it is skipped with the other options.
    rest = words[_after_options(words, 1, LAUNCHERS[head]) :]
    return shlex.join(rest) if rest else None


def _posix_shell(words: list[str]) -> tuple[str, bool] | None:
    """The `-c` command of `bash [options] -c '...'`; `bash deploy.sh -c x` is not one."""
    i = 1
    while i < len(words) - 1 and words[i][:1] in "-+":
        if re.fullmatch(r"-[a-zA-Z]*c", words[i]):
            return words[i + 1], False
        i += 2 if words[i] in ("-o", "+o", "-O", "+O") else 1  # `-o pipefail`
    return None


def _shell(words: list[str], head: str) -> tuple[str, bool] | None:
    """The `-c` command of a shell, PowerShell or cmd."""
    if head in POSIX_SHELLS:
        return _posix_shell(words)
    for i, word in enumerate(words[1:-1], start=1):
        flag = word.lower()
        if head in POWERSHELLS and flag in ("-c", "-command"):
            return " ".join(words[i + 1 :]), True
        if head == "cmd" and flag in ("/c", "/k"):
            return " ".join(words[i + 1 :]), True
    return None


def inner_command(words: list[str], ssh: bool = False) -> tuple[str, bool] | None:
    """(inner command, is PowerShell) for a wrapper command; None if it is not one.

    Commands that run elsewhere (`ssh`, `mosh`, `autossh`, `sshpass` around
    them, `docker exec`, `kubectl exec`) are opt-in with `ssh=True`: a commit
    made there is not this repository's commit, but a delete is still a delete.
    """
    if not words:
        return None
    head = command_name(words[0])
    if head in REMOTE or head in ("sshpass", "docker", "kubectl"):
        if not ssh:
            return None
        if head in REMOTE:
            inner = _remote(words)
        else:
            inner = _launched(words, head) if head == "sshpass" else _exec(words, head)
        return (inner, False) if inner else None
    if head in ("su", "wsl"):
        inner = _launched(words, head)
        return (inner, False) if inner else None
    return _shell(words, head)


def is_remote(words: list[str]) -> bool:
    """True for a command that runs its arguments on another host."""
    return bool(words) and command_name(words[0]) in REMOTE
