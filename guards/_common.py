"""Shared plumbing for every preflight guard.

A guard is a helper, not a participant: when anything goes wrong inside it
(unreadable payload, missing file, broken state), it lets the tool call through.
The only way a guard stops a call is a deliberate block with a reason and a
recipe the model can act on.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

# Windows consoles default to a legacy code page; hook I/O is UTF-8 JSON.
for _stream in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

_SESSION_RE = re.compile(r"[^A-Za-z0-9_-]")


def read_payload() -> dict:
    """Hook payload from stdin; an empty dict instead of an exception."""
    try:
        data = json.load(sys.stdin)
    except (ValueError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def tool_input(payload: dict) -> dict:
    value = payload.get("tool_input")
    return value if isinstance(value, dict) else {}


def base_dir(payload: dict) -> Path:
    """Directory the command runs in: payload `cwd`, project dir, process cwd."""
    for value in (payload.get("cwd"), os.environ.get("CLAUDE_PROJECT_DIR")):
        if isinstance(value, str) and value.strip():
            return Path(value)
    return Path.cwd()


_MSYS_DRIVE = re.compile(r"^/([a-zA-Z])(?=/|$)")


def resolve_path(base: Path, word: str) -> Path:
    """A path word from a command -> a path on disk.

    Handles `~`, relative paths and the Git Bash drive form `/d/work`, which
    Path would otherwise glue onto the current drive as `D:/d/work`.
    """
    word = os.path.expanduser(word)
    if os.name == "nt":
        word = _MSYS_DRIVE.sub(lambda m: m.group(1).upper() + ":", word)
        if re.fullmatch(r"[A-Za-z]:", word):
            word += "/"
    return base / word


def off_switch(guard: str) -> str:
    """Name of the variable that turned the guard off, or an empty string.

    `PREFLIGHT=0` silences every guard, `PREFLIGHT_<GUARD>=0` one of them.
    The name is returned rather than a bool so a silenced guard can say what
    silenced it: a switch left in a shell profile otherwise looks exactly like
    a guard with nothing to say.
    """
    for name in ("PREFLIGHT", f"PREFLIGHT_{guard.upper()}"):
        if os.environ.get(name, "").strip() == "0":
            return name
    return ""


def data_dir() -> Path:
    """Where guards keep state: the plugin data dir, or ~/.claude/preflight."""
    raw = os.environ.get("CLAUDE_PLUGIN_DATA", "").strip()
    base = Path(raw) if raw else Path.home() / ".claude" / "preflight"
    return base


def session_file(folder: str, session: str) -> Path | None:
    """Per-session state file; None when the session id is unusable.

    A shared fallback file would mix the state of unrelated sessions.
    """
    name = _SESSION_RE.sub("", session or "")[:96]
    return data_dir() / folder / f"{name}.json" if name else None


def log(guard: str, record: dict) -> None:
    """Append a line to `<data dir>/log/<guard>.jsonl` when PREFLIGHT_LOG=1.

    Off by default: a guard should not write anything about your work to disk
    unless you asked it to. Write errors are swallowed on purpose; the log is
    never a reason to break a tool call.
    """
    if os.environ.get("PREFLIGHT_LOG", "").strip() != "1":
        return
    try:
        folder = data_dir() / "log"
        folder.mkdir(parents=True, exist_ok=True)
        line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **record}
        with (folder / f"{guard}.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(line, ensure_ascii=False) + "\n")
    except OSError:
        pass


def run(guard: str, main) -> None:
    """Run a guard's main and exit with its code; any crash lets the call through.

    Without this a stray exception (a NUL byte in `cwd`, an unexpected payload
    shape) ends the hook with a traceback and exit code 1. Claude Code treats
    that as a non-blocking error, but it shows the traceback every time.
    """
    try:
        code = main()
    except Exception as exc:
        log(guard, {"crash": repr(exc)[:300]})
        code = 0
    sys.exit(code)


def block(title: str, problems: list[str], hint: str = "") -> int:
    """Block the call: reason on stderr, exit code 2 (Claude Code's contract)."""
    lines = [title, *(f"  - {p}" for p in problems)]
    if hint:
        lines += ["", hint]
    print("\n".join(lines), file=sys.stderr)
    return 2


def tell_model(event: str, text: str, user_line: str = "") -> int:
    """Non-blocking note the model will actually read (`additionalContext`).

    Plain stdout with exit 0 only reaches the debug log, so a note printed that
    way is invisible to the model. `systemMessage` is shown to the human only.
    """
    out: dict = {"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}}
    if user_line:
        out["systemMessage"] = user_line
    print(json.dumps(out, ensure_ascii=False))
    return 0
