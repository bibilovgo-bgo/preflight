"""PreToolUse on Bash and PowerShell: stop commands that destroy work or data.

Covers the irreversible classics: recursive delete of a root, home, current,
parent or system directory or a bare wildcard; SQL DROP / TRUNCATE /
unconditional DELETE through a database client; force push; hard reset to a
remote or older commit; `git clean` of untracked files; disk formatters and
the fork bomb.

False positives are the real enemy of a guard like this: one that blocks
`git commit -m "guard against rm -rf /"` gets switched off within a day. So:

* a dangerous command only counts in command position: start of input, or
  after `;`, `&`, `|`, `(`, `{`, a backtick or a newline, optionally behind
  `sudo`, `env`, `command`, `time`, `then`, `do` and the like;
* a delete target only counts as a whole argument word (`rm -rf build/` passes);
* SQL only counts on the same line as a database client;
* heredoc and here-string bodies are data (a commit message, a file being
  written), unless the heredoc feeds a shell (`bash <<EOF`, `ssh host <<EOF`).

Every pattern is linear in the command length: a guard that a long command can
push past the hook timeout lets that command through.

Commands wrapped in `bash -c '...'`, `pwsh -Command ...`, `cmd /c ...` and
`ssh host '...'` are unwrapped and read too. Over ssh the delete rule is
stricter: any absolute path except /tmp and `__pycache__` (see `scan`).

It reads the command text, so it is a seatbelt against mistakes, not a
sandbox: a script file, `eval "$cmd"` or `find / -delete` are not covered.
There is no bypass marker on purpose: if the command is really intended,
narrow its target or let the human run it. Off switch: PREFLIGHT_SAFETY=0.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import _common as c
import shell_words as sw
import wrappers

GUARD = "safety"

_SEP = r"(?:^|[\n;&|`(){])[ \t]*"
# Words that can stand in front of the real command, each with its options.
_PREFIX = (
    r"(?:(?:sudo|env|command|builtin|time|nohup|exec|then|do|else|!|[A-Za-z_]\w*=\S*)"
    r"[ \t]+(?:-\S+[ \t]+)*)*"
)
CMD = _SEP + _PREFIX
# Stays inside one simple command. `{` is excluded too: it is a separator, and
# with it a run of `{rm -r {rm -r ...` was scanned to the end from every brace.
_SEGMENT = r"(?:\$\{[^}\n]*\}|[^\n;&|(){])"  # `${VAR}` is a word, not a brace group
_END = r"['\"]?(?=[\s;&|)]|$)"
_SYSTEM = r"/(?:bin|boot|dev|etc|home|lib\w*|opt|root|sbin|srv|usr|var|Users|System)"
# Starts of a catastrophic target; each one is non-empty on its own.
_BASE = r"~|\$HOME|\$\{HOME\}|\.{1,2}|" + _SYSTEM + r"|/[a-zA-Z]|[A-Za-z]:"
RISKY = r"(?<!\S)['\"]?(?:(?:" + _BASE + r")[/\\]?\*?|/\*?|\*)" + _END
_PS_BASE = r"[A-Za-z]:|~|\$HOME|\$env:USERPROFILE|\.{1,2}"
PS_RISKY = r"(?<!\S)['\"]?(?:(?:" + _PS_BASE + r")[\\/]?\*?|[\\/]\*?|\*)" + _END
RECURSIVE = r"(?=" + _SEGMENT + r"*\s(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)(?=\s|$))"
RM = r"(?:[^\s;&|()`{]*/)?\\?rm\b"
PS_DELETE = r"(?:Remove-Item|ri|rm|del|rd|rmdir)\b"
# PowerShell accepts unambiguous prefixes: -r for -Recurse, -fo for -Force.
PS_FLAGS = r"(?=" + _SEGMENT + r"*\s-r[a-z]*\b)(?=" + _SEGMENT + r"*\s-fo[a-z]*\b)"
# A line that mentions a database client anywhere (`echo "DROP ..." | psql`
# too), checked once per line so a long line costs linear time.
DB_CLIENT = r"(?m)^(?=[^\n]*\b(?:sqlite3|psql|mysql|mariadb)\b)[^\n]*?"
# `git` with its global options: `git -C dir push`, `git -c k=v reset`.
GIT = r"git(?:\s+(?:-[Cc]\s+\S+|--[\w-]+(?:=\S+)?))*\s+"
# Disks, not `/dev/null` or `/dev/stdout`.
_BLOCK_DEVICE = r"(?:sd|nvme|hd|vd|xvd|disk|mmcblk)"
DB_IN_COMMAND = re.compile(CMD + r"(?:[^\s;&|()`{]*/)?(?:sqlite3|psql|mysql|mariadb)\b")
QUOTED = re.compile(r"'[^']*'|\"(?:\\.|[^\"\\])*\"")
# A heredoc whose body runs as commands rather than being stored as text.
SHELL_FED = re.compile(r"\b(?:sh|bash|zsh|dash|ksh|ssh|su|sudo|eval|source|xargs)\b")

RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "rm -r on a root, home, current, parent or system directory, or a bare wildcard",
        re.compile(CMD + RM + RECURSIVE + _SEGMENT + r"*?\s" + RISKY),
    ),
    (
        "Remove-Item -Recurse -Force on a drive root, home, current directory or wildcard",
        re.compile(CMD + PS_DELETE + PS_FLAGS + _SEGMENT + r"*?\s" + PS_RISKY, re.I),
    ),
    (
        "DROP / TRUNCATE through a database client",
        re.compile(DB_CLIENT + r"\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE)\b", re.I),
    ),
    (
        "DELETE without WHERE through a database client",
        re.compile(DB_CLIENT + r"\bDELETE\s+FROM\s+[\w.\"`]+\s*(?:;|\"|'|$)", re.I),
    ),
    (
        "git push --force (use --force-with-lease)",
        re.compile(
            CMD
            + GIT
            + r"push\b"
            + _SEGMENT
            + r"*(?:--force(?![-\w])|\s-[a-zA-Z]*f[a-zA-Z]*\b|\s\+\S)"
        ),
    ),
    (
        "git reset --hard to a remote or older commit",
        re.compile(CMD + GIT + r"reset\s+--hard\s+(?:origin/|upstream/|HEAD~|HEAD\^|@~|--)"),
    ),
    (
        "git clean deleting untracked files",
        re.compile(
            CMD
            + GIT
            # -n / --dry-run only lists; -X removes only ignored build output.
            + r"clean\b(?!"
            + _SEGMENT
            + r"*(?:\s-[a-zA-Z]*[nX]|--dry-run))"
            + _SEGMENT
            + r"*\s(?:-[a-zA-Z]*f|--force)"
        ),
    ),
    (
        "disk formatter or raw write to a block device",
        re.compile(
            CMD
            + r"(?:mkfs(?:\.\w+)?\s"
            + _SEGMENT
            + r"*/dev/|dd\s"
            + _SEGMENT
            + r"*\bof=/dev/"
            + _BLOCK_DEVICE
            + r")|>\s*/dev/"
            + _BLOCK_DEVICE
        ),
    ),
    ("fork bomb", re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")),
    (
        "rd /s or del /s on a drive root, home or wildcard (cmd)",
        re.compile(
            CMD + r"(?:rd|rmdir|del|erase)\b(?=" + _SEGMENT + r"*\s/[sS]\b)" + _SEGMENT + r"*?\s"
            r"(?<!\S)\"?(?:[A-Za-z]:\\?\*?|%USERPROFILE%\\?|\\\*?|\*|\.{1,2}\\?)\"?(?=[\s;&|)]|$)",
            re.I,
        ),
    ),
]
DB_RULES = frozenset({RULES[2][0], RULES[3][0]})
MAX_DEPTH = 3
REMOTE_LABEL = "rm -r on an absolute path on a remote host (ssh)"
# Any absolute target except /tmp and bytecode caches, which deploys clear
# routinely; `/tmp/../etc` climbs out of the exemption, so `..` voids it.
_PATH_CHAR = r"[^\s'\";&|]"
_EXEMPT = r"(?:tmp(?:[/'\"]|\s|$)|" + _PATH_CHAR + r"*__pycache__)"
_REMOTE_TARGET = (
    r"(?<!\S)['\"]?/(?!(?!" + _PATH_CHAR + r"*\.\.)" + _EXEMPT + r")" + _PATH_CHAR + r"+"
)
REMOTE_DELETE = re.compile(CMD + RM + RECURSIVE + _SEGMENT + r"*?\s" + _REMOTE_TARGET)
# Cheap pre-check: only commands that mention a wrapper or a prefix are parsed.
WRAPPER_HINT = re.compile(
    r"\b(?:ssh|autossh|mosh|sshpass|sh|bash|zsh|dash|ksh|pwsh|powershell|cmd|docker|kubectl"
    r"|su|wsl|sudo|doas|nice|ionice|xargs|stdbuf|env|timeout)(?:\.exe)?\b",
    re.I,
)


def code_only(command: str) -> str:
    """The command with heredoc and here-string bodies removed, unless a shell runs them."""
    out, pos = [], 0
    for doc in sw.heredocs(command):
        head = command[command.rfind("\n", 0, doc.start) + 1 : doc.start]
        if SHELL_FED.search(head):
            continue  # `bash <<EOF`: the body is commands, keep it
        out.append(command[pos : doc.start] + " " + doc.tail)
        pos = doc.end
    out.append(command[pos:])
    return sw.strip_herestrings("".join(out))


def blank_quoted(text: str) -> str:
    """Quoted strings with spaces (a commit message, an echo) become one placeholder word.

    Short quoted words stay, so `rm -rf "/"` and `rm -rf "$HOME"` are still read.
    """
    return QUOTED.sub(lambda m: '"_"' if re.search(r"\s", m.group(0)) else m.group(0), text)


def scan_text(command: str) -> list[str]:
    """Labels of the rules the command's own text trips.

    Shell rules read the command with quoted text blanked. SQL lives inside
    quotes, so the database rules read the full text, but only when a database
    client is really run (in command position, not mentioned in a message).
    """
    text = code_only(command or "")
    bare = blank_quoted(text)
    hits = []
    for label, pattern in RULES:
        if label in DB_RULES:
            found = DB_IN_COMMAND.search(bare) and pattern.search(text)
        else:
            found = pattern.search(bare)
        if found:
            hits.append(label)
    return hits


def scan(command: str, powershell: bool = False, depth: int = 0, remote: bool = False) -> list[str]:
    """Labels of every rule the command trips, including commands wrapped inside it.

    Blanking quoted text keeps commit messages from tripping the rules, but it
    also hides the quoted command of `ssh host "rm -rf /var/www"` and
    `bash -c '...'`. Those are unwrapped and scanned as commands of their own.

    On a remote host the delete rule is stricter: there, a recursive delete of
    any absolute path is usually the site or its data, while locally
    `rm -rf /tmp/build` is routine.
    """
    hits = _scan_one(command, remote)
    if depth >= MAX_DEPTH or not WRAPPER_HINT.search(command or ""):
        return hits
    for words, _here in sw.walk_commands(command, Path("."), powershell) or []:
        # `sudo -u www rm -rf /`: the parser has dropped the prefix the regexes trip on.
        hits += _scan_one(shlex.join(words), remote)
        inner = wrappers.inner_command(words, ssh=True)
        if inner is not None:
            hits += scan(inner[0], inner[1], depth + 1, remote or wrappers.is_remote(words))
    for doc in sw.heredocs(command):
        head = command[command.rfind("\n", 0, doc.start) + 1 : doc.start]
        if _feeds_remote(head):  # `ssh host <<'EOF'`: the body runs on the host
            hits += scan(doc.body, False, depth + 1, True)
    return list(dict.fromkeys(hits))


def _feeds_remote(head: str) -> bool:
    """The command a heredoc is fed to runs on another host (`ssh host bash <<EOF`).

    By its name, not by the word anywhere on the line: `cat > ssh-deploy.sh <<EOF`
    writes a file here.
    """
    commands = sw.walk_commands(head, Path(".")) or []
    return bool(commands) and wrappers.is_remote(commands[-1][0])


def _scan_one(command: str, remote: bool) -> list[str]:
    """Rules one command's own text trips, plus the stricter delete rule on a remote host.

    The remote rule keeps a quoted path even with a space in it (`'/srv/my app'`).
    """
    hits = scan_text(command)
    text = QUOTED.sub(
        lambda m: m.group(0) if m.group(0)[1:2] == "/" else '"_"', code_only(command or "")
    )
    if remote and REMOTE_DELETE.search(text):
        hits.append(REMOTE_LABEL)
    return hits


def main() -> int:
    if c.off_switch(GUARD):
        return 0
    payload = c.read_payload()
    command = str(c.tool_input(payload).get("command") or "")
    hits = scan(command, payload.get("tool_name") == "PowerShell")
    if not hits:
        return 0
    c.log(GUARD, {"rules": hits})
    return c.block(
        "preflight/safety: this command destroys work or data and cannot be undone.",
        hits,
        "Narrow the target to exactly what must go, or ask the human to run it "
        "themselves after they confirm.",
    )


if __name__ == "__main__":
    c.run(GUARD, main)
