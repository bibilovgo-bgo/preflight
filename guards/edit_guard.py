"""PreToolUse on Edit: check the anchor against the file on disk before the call.

Most failed edits fail for a reason that is visible on disk:

* the anchor is no longer in the file, usually because a formatter rewrote it
  right after the previous edit and the model aims at what it remembers;
* the anchor occurs several times and `replace_all` is not set, so Edit
  refuses to pick one;
* `old_string` equals `new_string`: the anchor was copied to both sides and
  the actual change was forgotten.

Each costs a wasted tool call and often a second one. The guard reads the file,
names the problem and, for a missing anchor, shows the closest line in the file
so the model does not have to hunt for the drift.

Deliberate bypass: put `#edit-ok` in new_string. Off switch: PREFLIGHT_EDIT=0.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path

import _common as c

GUARD = "edit"
BYPASS = "#edit-ok"
MAX_HINT_LINES = 5_000
# Typographic quotes -> straight ones (built from code points: the source stays ASCII).
QUOTES = str.maketrans({chr(0x2018): "'", chr(0x2019): "'", chr(0x201C): '"', chr(0x201D): '"'})


def read_text(path: str) -> str | None:
    """File content with universal newlines; None if it cannot be read as text."""
    try:
        return Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError):
        return None


def nearest_line(text: str, anchor: str) -> str:
    """The file line most similar to the first non-empty line of the anchor."""
    first = next((ln.strip() for ln in anchor.splitlines() if ln.strip()), "")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) > MAX_HINT_LINES:
        # difflib over 100k lines outlasts the hook timeout: keep the lines
        # that share the anchor's first word, then cap.
        word = next(iter(re.findall(r"\w{3,}", first)), first)
        lines = [ln for ln in lines if word in ln][:MAX_HINT_LINES]
    best = difflib.get_close_matches(first, lines, cutoff=0.6)
    return best[0] if best else ""


def occurrences(text: str, old: str) -> int:
    """How many times Edit will find `old`, curly quotes counted as straight ones.

    Edit matches `say "hi"` against `say “hi”`, so a guard that
    counts only exact matches would block an edit that works.
    """
    old = old.replace("\r\n", "\n")
    return text.count(old) or text.translate(QUOTES).count(old.translate(QUOTES))


def check_edit(tool_input: dict) -> list[str]:
    """Problems that will make this Edit fail; an empty list means let it run."""
    path = str(tool_input.get("file_path") or "")
    old = tool_input.get("old_string")
    new = tool_input.get("new_string")
    if not path or not isinstance(old, str) or not old:
        return []
    if BYPASS in str(new or ""):
        return []
    if old == new:
        return [
            "old_string and new_string are identical, so the edit changes "
            "nothing. Usually the anchor was copied to both sides and the "
            "change itself was left out."
        ]

    text = read_text(path)
    if text is None:
        return []  # missing or binary file: Edit will report it itself
    count = occurrences(text, old)
    if count == 1:
        return []
    if count == 0:
        msg = (
            "old_string is not in the file. The file most likely changed "
            "after you read it (a formatter or another edit). Read the target "
            "region again and aim at the current text, not at memory."
        )
        hint = nearest_line(text, old)
        if hint:
            msg += f"\n    Closest line in the file: {hint[:120]!r}"
        return [msg]
    if tool_input.get("replace_all"):
        return []
    return [
        f"old_string occurs {count} times and replace_all is not set, so Edit "
        "will refuse to choose. Widen the anchor with neighbouring lines "
        "until it is unique, or set replace_all: true on purpose."
    ]


def main() -> int:
    if c.off_switch(GUARD):
        return 0
    payload = c.read_payload()
    if payload.get("tool_name") != "Edit":
        return 0
    tool_input = c.tool_input(payload)
    problems = check_edit(tool_input)
    if not problems:
        return 0
    c.log(
        GUARD,
        {
            "file": Path(str(tool_input.get("file_path"))).name,
            "problems": [p[:80] for p in problems],
        },
    )
    return c.block(
        "preflight/edit: this Edit will not hit its target.",
        problems,
        f"Fix the anchor and retry. If this is deliberate, add {BYPASS} to new_string.",
    )


if __name__ == "__main__":
    c.run(GUARD, main)
