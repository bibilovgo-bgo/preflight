"""Reading files of a foreign repository without letting the repository steer the reader.

The repository controls every file the scanner opens. A symlink can point at a
huge tree, at `/dev/zero` or at a FIFO that blocks forever; a 200 KB JSON file
of nested brackets raises RecursionError; a huge file eats the hook timeout.
So symlinks are never followed, only regular files are read, reads are capped,
and every problem surfaces as an `Unreadable` with a reason the caller turns
into a finding, never as a crash or a silent skip.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

MAX_BYTES = 1_000_000
MAX_WALK = 2_000  # entries visited under one directory

# Payload techniques, not tools. `node`, `npx` or `curl` alone are what honest
# projects run every day (a formatter hook, a postinstall build, a health
# check); calling them attack signs would make every JS repository "infected"
# and the warning worthless. What is high: a download fed straight to an
# interpreter, an encoded or hidden PowerShell, decoding base64 to run it, a
# reverse shell.
ATTACK = re.compile(
    r"\b(?:curl|wget)\b[^|\n]{0,300}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python\d?|node|perl)\b"
    r"|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]{0,300}\|\s*(?:iex|Invoke-Expression)\b"
    r"|\b(?:iex|Invoke-Expression)\b\s*\(?\s*\(?\s*(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|New-Object)\b"
    r"|\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,200}\s-(?:e|ec|enc|encodedcommand)\s"
    r"|-w(?:indowstyle)?\s+hidden"
    r"|FromBase64String|\bbase64\s+(?:-d|--decode)\b|b64decode"
    r"|/dev/tcp/|\bbash\s+-i\b|\bnc(?:at)?\s+(?:-\S+\s+)*-[ec]\b",
    re.I,
)
# A JavaScript runtime started at session start is the worm's handwriting.
JS_RUNTIME = re.compile(r"\b(?:node|bun|deno|npx)(?![-\w])", re.I)


class Unreadable(Exception):
    """The file exists but is not read: the message says why."""


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except OSError:
        return None


def read_text(root: Path, rel: str) -> str | None:
    """Text of a regular file inside the repository; None if it does not exist."""
    path = root / rel
    info = _lstat(path)
    if info is None:
        return None
    if stat.S_ISLNK(info.st_mode):
        raise Unreadable(f"symlink to {os.readlink(path)!r}, not followed")
    if not stat.S_ISREG(info.st_mode):
        raise Unreadable("not a regular file, not read")
    if info.st_size > MAX_BYTES:
        raise Unreadable(f"{info.st_size} bytes, too large to scan")
    try:
        return path.read_bytes().decode("utf-8-sig", errors="replace")
    except OSError as exc:
        raise Unreadable(f"cannot be read ({exc.__class__.__name__})") from exc


def read_json(root: Path, rel: str) -> dict | None:
    """A JSON object from the repository; None if the file does not exist."""
    text = read_text(root, rel)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise Unreadable(f"not valid JSON ({exc.__class__.__name__}), read it by eye") from exc
    if not isinstance(data, dict):
        raise Unreadable("JSON is not an object, read it by eye")
    return data


def is_link(path: Path) -> bool:
    """A symlink, or a Windows directory junction (which `is_symlink` does not report)."""
    isjunction = getattr(os.path, "isjunction", None)  # Python 3.12+
    return path.is_symlink() or bool(isjunction and isjunction(path))


def walk(base: Path) -> tuple[list[Path], list[str]]:
    """Regular files under `base` without following links, and notes on what was skipped."""
    files: list[Path] = []
    notes: list[str] = []
    seen = 0
    for top, dirs, names in os.walk(base, followlinks=False):
        here = Path(top)
        for name in list(dirs):
            if is_link(here / name):
                notes.append(f"{(here / name)} is a directory link, not followed")
                dirs.remove(name)
        for name in names:
            seen += 1
            if seen > MAX_WALK:
                notes.append(f"more than {MAX_WALK} entries, the rest were not scanned")
                return files, notes
            path = here / name
            info = _lstat(path)
            if info is not None and stat.S_ISREG(info.st_mode):
                files.append(path)
            elif info is not None and stat.S_ISLNK(info.st_mode):
                notes.append(f"{path} is a symlink, not followed")
    return files, notes
