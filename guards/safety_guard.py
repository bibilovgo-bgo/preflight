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

It reads the command text, so it is a seatbelt against mistakes, not a
sandbox: `bash -c '...'`, a script file or `find / -delete` are not covered.
There is no bypass marker on purpose: if the command is really intended,
narrow its target or let the human run it. Off switch: PREFLIGHT_SAFETY=0.
"""

from __future__ import annotations

import re

import _common as c
import shell_words as sw

GUARD = "safety"

_SEP = r"(?:^|[\n;&|`(){])[ \t]*"
# Words that can stand in front of the real command, each with its options.
_PREFIX = (
    r"(?:(?:sudo|env|command|builtin|time|nohup|exec|then|do|else|!|[A-Za-z_]\w*=\S*)"
    r"[ \t]+(?:-\S+[ \t]+)*)*"
)
CMD = _SEP + _PREFIX
_SEGMENT = r"[^\n;&|()]"  # stays inside one simple command
_END = r"['\"]?(?=[\s;&|)]|$)"
_SYSTEM = r"/(?:bin|boot|dev|etc|home|lib\w*|opt|root|sbin|srv|usr|var|Users|System)"
# Starts of a catastrophic target; each one is non-empty on its own.
_BASE = r"~|\$HOME|\$\{HOME\}|\.{1,2}|" + _SYSTEM + r"|/[a-zA-Z]|[A-Za-z]:"
RISKY = r"(?<!\S)['\"]?(?:(?:" + _BASE + r")[/\\]?\*?|/\*?|\*)" + _END
_PS_BASE = r"[A-Za-z]:|~|\$HOME|\$env:USERPROFILE|\.{1,2}"
PS_RISKY = r"(?<!\S)['\"]?(?:(?:" + _PS_BASE + r")[\\/]?\*?|[\\/]\*?|\*)" + _END
RECURSIVE = r"(?=" + _SEGMENT + r"*\s(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)(?=\s|$))"
RM = r"(?:\S*/)?\\?rm\b"
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
DB_IN_COMMAND = re.compile(CMD + r"(?:\S*/)?(?:sqlite3|psql|mysql|mariadb)\b")
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
]
DB_RULES = frozenset({RULES[2][0], RULES[3][0]})


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


def scan(command: str) -> list[str]:
    """Labels of every rule the command trips.

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


def main() -> int:
    if c.off_switch(GUARD):
        return 0
    payload = c.read_payload()
    command = str(c.tool_input(payload).get("command") or "")
    hits = scan(command)
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
