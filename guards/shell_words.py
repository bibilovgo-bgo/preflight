"""Shell command -> words of its simple commands, the way the shell reads them.

Heredoc bodies and PowerShell here-strings are data, not commands; a quoted
string is one word; comments and line continuations become a space. Regexes
over the raw text cannot tell `git commit` from the words "git commit" inside
a commit message, which is why the guards that care parse first.

Every scan is linear: an early version searched for the heredoc label again
from every `<<`, and a few thousand unclosed `<<A` took longer than the hook
timeout.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import NamedTuple

from _common import resolve_path

# Label is a word, as in bash: `<<EOF`, `<<'EOF'`, `<<\EOF`, `<<E"OF"`.
# Unquoted it must start with a letter or `_`, so `$((1 << 3))` is not one.
_LABEL = re.compile(r"-?[ \t]*(?P<word>(?:[^\s'\"<>;&|()\\]|\\.|'[^'\n]*'|\"[^\"\n]*\")+)")
_CODE_STOP = re.compile(r"[\\'\"#<()]")
_DQUOTE_STOP = re.compile(r'[\\"$]')
_HERESTRING_OPEN = re.compile(r"@(['\"])[ \t]*\r?\n")
_WORD_START = frozenset({"", " ", "\t", "\n", ";", "&", "|", "(", ")"})


class Heredoc(NamedTuple):
    start: int  # position of `<<`
    end: int  # end of the closing label line, or end of input
    label: str
    tail: str  # rest of the opening line: `python - <<'EOF' > out.txt`
    body: str


def heredocs(cmd: str):
    """Heredocs of the command in order, in one pass, as bash sees them.

    `<<` inside quotes, a comment or after `\\` is text; inside `"$(...)"` it is
    an operator again, which is exactly how commit messages are written:
    `-m "$(cat <<'EOF' ... EOF)"`. A body without its closing label runs to the
    end of input, and there are no heredocs after it.
    """
    stack: list[str] = []  # '"' inside double quotes, '(' inside parentheses
    i: int | None = 0
    while i is not None and i < len(cmd):
        if stack and stack[-1] == '"':
            i = _dquote_step(cmd, i, stack)
            continue
        i, doc = _code_step(cmd, i, stack)
        if doc is not None:
            yield doc


def _dquote_step(cmd: str, i: int, stack: list[str]) -> int | None:
    m = _DQUOTE_STOP.search(cmd, i)
    if not m:
        return None
    i = m.start()
    if cmd[i] == "\\":
        return i + 2
    if cmd[i] == '"':
        stack.pop()
    elif cmd.startswith("$(", i):  # substitution inside quotes is code again
        stack.append("(")
        return i + 2
    return i + 1


def _code_step(cmd: str, i: int, stack: list[str]):
    """One step in code: (next position or None at the end, heredoc or None)."""
    m = _CODE_STOP.search(cmd, i)
    if not m:
        return None, None
    i, ch = m.start(), m.group()
    if ch == "\\":
        return i + 2, None
    if ch == "'":  # unclosed runs to the end of input, as in bash
        close = cmd.find("'", i + 1)
        return (close + 1 if close >= 0 else None), None
    if ch == "#" and cmd[i - 1 : i] in _WORD_START:
        eol = cmd.find("\n", i)  # a comment starts a word; `$#` and `a#b` do not
        return (eol if eol >= 0 else None), None
    if ch in '"(':
        stack.append(ch)
    elif ch == ")" and stack:
        stack.pop()
    elif ch == "<" and _is_heredoc_op(cmd, i):
        doc = _heredoc_at(cmd, i)
        if doc:
            return doc.end, doc
    return i + 1, None


def _is_heredoc_op(cmd: str, i: int) -> bool:
    """`<<`, but not the `<<<` here-string or its tail."""
    return cmd.startswith("<<", i) and not cmd.startswith("<<<", i) and cmd[i - 1 : i] != "<"


def _heredoc_at(cmd: str, i: int) -> Heredoc | None:
    m = _LABEL.match(cmd, i + 2)
    if not m:
        return None
    word = m.group("word")
    label = re.sub(r"['\"\\]", "", word)
    if not label or not (word[0] in "'\"\\" or label[0].isalpha() or label[0] == "_"):
        return None
    eol = cmd.find("\n", m.end())
    if eol < 0:
        return None  # the body starts on the next line and there is none
    close = re.compile(rf"^\t*{re.escape(label)}[ \t\r]*$", re.M).search(cmd, eol + 1)
    stop, end = (close.start(), close.end()) if close else (len(cmd), len(cmd))
    return Heredoc(i, end, label, cmd[m.end() : eol], cmd[eol + 1 : stop])


def strip_heredocs(cmd: str) -> str:
    """Replace each heredoc by the tail of its opening line."""
    out, pos = [], 0
    for doc in heredocs(cmd):
        out.append(cmd[pos : doc.start] + " " + doc.tail)
        pos = doc.end
    out.append(cmd[pos:])
    return "".join(out)


def strip_herestrings(text: str) -> str:
    """PowerShell here-strings (`@'...'@`, `@"..."@`) become one placeholder word.

    An apostrophe inside (`don't`) would otherwise close a quote early and the
    rest of a commit message would be read as flags.
    """
    out, pos = [], 0
    while True:
        m = _HERESTRING_OPEN.search(text, pos)
        if not m:
            break
        out.append(text[pos : m.start()] + " _ ")
        close = text.find("\n" + m.group(1) + "@", m.end() - 1)
        if close < 0:
            return "".join(out)
        pos = close + 3
    out.append(text[pos:])
    return "".join(out)


_TEXT = re.compile(
    # Quoted strings stay for shlex; an unclosed one takes the rest, otherwise
    # the search restarts at every quote and turns quadratic.
    r"'[^']*(?:'|$)"
    r'|"(?:\\(?:.|$)|[^"\\])*(?:"|$)'
    r"|\\\r?\n|`\r?\n"  # line continuation: bash `\`, PowerShell backtick
    r"|<#.*?(?:#>|$)"  # PowerShell block comment
    r"|(?<![^\s;&|()])#[^\n]*",  # comment at the start of a word
    re.S,
)
_PUNCT = ";&|()<>\n"
# shlex grows a word one character at a time; beyond this size parsing would
# outlast the hook timeout, so the command counts as unparseable.
MAX_PARSE = 100_000


def _drop_comments(text: str) -> str:
    """Comments and line continuations become a space, quoted strings stay."""

    def keep(m: re.Match) -> str:
        found = m.group(0)
        return found if found[0] in "'\"" else " "

    return _TEXT.sub(keep, text)


def is_punct(token: str) -> bool:
    return bool(token) and set(token) <= set(_PUNCT)


def tokens(cmd: str, powershell: bool) -> list[str] | None:
    """Shell tokens of the command; None if it cannot be parsed."""
    text = strip_herestrings(strip_heredocs(cmd))
    if len(text) > MAX_PARSE:
        return None
    lex = shlex.shlex(_drop_comments(text), posix=True, punctuation_chars=_PUNCT)
    lex.whitespace, lex.whitespace_split, lex.commenters = " \t\r", True, ""
    if powershell:
        lex.escape = ""
    try:
        return list(lex)
    except ValueError:
        return None


def simple_commands(cmd: str, powershell: bool = False) -> list | None:
    """Command -> in order: word lists of simple commands and subshell parens.

    A redirection (`2>&1`, `> log`) does not end the command and its target is
    not a word of it. None means the command cannot be parsed (unclosed quote,
    longer than MAX_PARSE); what to do then is the caller's decision.

    In PowerShell the backslash is a path character, not an escape (the escape
    is the backtick): POSIX parsing would turn `C:\\Users\\x` into `C:Usersx`.
    """
    found = tokens(cmd, powershell)
    if found is None:
        return None
    events: list = []
    words: list[str] = []
    target = False
    for token in found:
        if is_punct(token):
            if ("<" in token or ">" in token) and not set(token) & set("()"):
                if words and words[-1].isdigit():
                    words.pop()  # `2>&1`: the digit is a stream number
                target = True
                continue
            events.append(words)
            words, target = [], False
            events += [ch for ch in token if ch in "()"]
            continue
        if target:
            target = False
            continue
        words.append(token)
    events.append(words)
    return events


_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
# Words in front of the real command: `if git commit`, `time git`, `! git`.
_PREFIX = frozenset(
    {"if", "then", "elif", "else", "while", "until", "do", "!", "{",
     "time", "command", "builtin", "exec", "nohup", "sudo", "doas", "nice",
     "ionice", "stdbuf", "xargs"}
)  # fmt: skip
# Options of a prefix that take the next word: in `sudo -u www rm`, `www` is the
# user, not the command. Per prefix: `sudo -n` is a flag, `nice -n 5` is not.
_PREFIX_VALUE = {
    "sudo": frozenset("-u -g -C -D -h -p -r -t -U -T --user --group --chdir --host "
                      "--prompt --role --type --other-user --close-from".split()),
    "doas": frozenset({"-u", "-C"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "-n", "-p", "--class", "--classdata", "--pid"}),
    "xargs": frozenset("-I -L -n -P -d -s -E -a --max-args --max-procs --arg-file "
                       "--delimiter --max-lines --max-chars --eof".split()),
}  # fmt: skip
_ENV_VALUE = frozenset({"-u", "--unset", "-S", "--split-string"})
_TIMEOUT_VALUE = frozenset({"-k", "--kill-after", "-s", "--signal"})


def command_head(words: list[str]) -> tuple[list[str], list[str], str]:
    """(assignments, words of the command itself, directory from `env -C`).

    `FOO=0 git commit`, `env -C dir git commit`, `timeout 60 git commit`,
    `time git commit`, `if git commit` all have git as the real command.
    """
    assigns: list[str] = []
    chdir, i = "", 0
    while i < len(words):
        word = words[i]
        i += 1
        if _ASSIGN.match(word):
            assigns.append(word)
        elif word in _PREFIX:
            values = _PREFIX_VALUE.get(word, frozenset())
            while i < len(words) and words[i].startswith("-"):
                i += 2 if words[i] in values else 1
        elif word == "env":
            while i < len(words) and (words[i].startswith("-") or _ASSIGN.match(words[i])):
                option = words[i]
                i += 1
                name, eq, value = option.partition("=")
                if _ASSIGN.match(option):
                    assigns.append(option)
                elif name in ("-C", "--chdir"):
                    chdir = value if eq else (words[i] if i < len(words) else "")
                    i += not eq
                elif option in _ENV_VALUE:
                    i += 1
        elif word == "timeout":
            while i < len(words) and words[i].startswith("-"):
                i += 2 if words[i] in _TIMEOUT_VALUE else 1
            i += 1  # the duration
        else:
            return assigns, words[i - 1 :], chdir
    return assigns, [], chdir


CD_WORDS = frozenset({"cd", "pushd", "set-location", "sl", "chdir"})


def command_name(word: str) -> str:
    """`/usr/bin/git`, `C:/Git/cmd/GIT.EXE` -> `git`."""
    return Path(word).name.lower().removesuffix(".exe")


def walk_commands(command: str, base: Path, powershell: bool = False):
    """(words, directory it runs in) for each simple command, following `cd`.

    Returns None when the command cannot be parsed. A directory that is a shell expansion (`cd $REPO`) is taken literally and
    will simply not exist: the callers then find nothing, which fails open.
    """
    events = simple_commands(command, powershell=powershell)
    if events is None:
        return None
    here, out = base, []
    for event in events:
        if not isinstance(event, list):
            continue  # a subshell parenthesis
        _assigns, words, chdir = command_head(event)
        if not words:
            continue
        if command_name(words[0]) in CD_WORDS and len(words) > 1:
            here = resolve_path(here, words[-1])
            continue
        out.append((words, resolve_path(here, chdir) if chdir else here))
    return out
