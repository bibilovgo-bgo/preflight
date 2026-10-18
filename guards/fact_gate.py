"""PreToolUse on Edit, Write and NotebookEdit: facts before the first edit of a risky file.

Asking a model "are you sure?" gets "yes". Asking it to list every file that
imports the one it is about to change makes it run a search, and the search
changes what it does next. This guard denies the first edit of a file in one
of four classes — money, auth, schema, check configuration (see
`fact_classes.py`) — with a short list of facts to show, and lets the retry
through once the transcript holds a search of the tree for that file in the
current turn (`search_credit.py`). Every other file passes untouched, and
no state is read or written about it.

Two denials per file and session are the cap: after that the edit passes
with a note, because a guard is a helper, not a warden. Credited and capped
files are remembered per session for 8 idle hours; two hook processes of
one session merge their memory instead of overwriting each other.

There is no bypass marker: anything typed into the edit would land in the
file. Off switch: PREFLIGHT_FACTS=0; exemptions: PREFLIGHT_FACTS_EXEMPT
(file globs separated by `;`); the cap: PREFLIGHT_FACTS_MAX_DENIALS.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import NamedTuple

import _common as c
import fact_classes as fc
import search_credit as sc
import transcript_turn as tt

GUARD = "facts"
EVENT = "PreToolUse"
IDLE_SECONDS = 8 * 3600
KEEP_SECONDS = 3 * 24 * 3600
DEFAULT_CAP = 2
COMMON = "quote the user's current instruction verbatim"
QUESTIONS = {
    "money": [
        "who reads {stem}: search the tree for its importers and callers (Grep/rg)",
        "where every amount comes from, its currency and rounding, and which store it is written to",
        "which test pins the current numbers (search tests/ for {stem}), or say there is none",
    ],
    "auth": [
        "who calls {stem}: search the tree for its importers and callers (Grep/rg)",
        "which check this adds, removes or bypasses, and what happens on the unhappy path "
        "(expired token, missing permission, second login)",
        "which test covers the unhappy path (search tests/ for {stem}), or say there is none",
    ],
    "schema": [
        "which earlier migration or model touches {table}: search migrations/ and models for it",
        "who reads and writes the changed column: search the tree for its name",
        "the one-line rollback for this change",
    ],
    "config": [
        "which check this weakens or changes (rule code, test path, workflow step)",
        "the code that currently fails it: search for the rule code or the test name",
        "why that code is not fixed instead",
    ],
}
TITLES = {
    "money": "first edit of a money path",
    "auth": "first edit of an auth path",
    "schema": "first edit of a schema",
    "config": "first edit of a check configuration",
}
HINT = "Then retry the edit. Reading the file does not count; a search does."


class Verdict(NamedTuple):
    kind: str  # "pass" | "note" | "deny"
    title: str  # the note, or the denial's title
    problems: list[str]  # the denial's questions


PASS = Verdict("pass", "", [])


def target_path(tool_name: str, tool_input: dict) -> str:
    key = "notebook_path" if tool_name == "NotebookEdit" else "file_path"
    value = tool_input.get(key)
    return value if isinstance(value, str) else ""


def edit_text(tool_input: dict) -> str:
    """Everything the edit touches: the old text and the new, or a file's whole content.

    The old text matters as much as the new: an edit that removes a check is
    the one to ask about.
    """
    edits = tool_input.get("edits")  # MultiEdit, where older Claude Code still has it
    sources = (
        [tool_input, *(e for e in edits if isinstance(e, dict))]
        if isinstance(edits, list)
        else [tool_input]
    )
    parts = []
    for source in sources:
        for key in ("old_string", "new_string", "content", "new_source"):
            value = source.get(key)
            if isinstance(value, str) and value:
                parts.append(value)
    return "\n".join(parts)


def fresh() -> dict:
    return {"checked": [], "denials": {}}


def load_state(session: str) -> dict:
    """{checked: [...], denials: {rel: n}}; fresh after 8 idle hours or on any damage."""
    path = c.session_file(GUARD, session)
    if path is None or not path.exists():
        return fresh()
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        idle = time.time() - float(state.get("last_active") or 0)
        checked, denials = state.get("checked"), state.get("denials")
        if idle > IDLE_SECONDS or not isinstance(checked, list) or not isinstance(denials, dict):
            return fresh()
        return {
            "checked": [p for p in checked if isinstance(p, str)],
            "denials": {str(k): int(v) for k, v in denials.items()},
        }
    except (OSError, ValueError, TypeError, AttributeError):
        return fresh()


def merged(session: str, state: dict) -> dict:
    """`state` joined with what another hook process of the session wrote meanwhile."""
    other = load_state(session)
    checked = list(dict.fromkeys(other["checked"] + state["checked"]))
    denials = dict(other["denials"])
    for rel, count in state["denials"].items():
        denials[rel] = max(count, denials.get(rel, 0))
    return {"checked": checked, "denials": denials}


def save_state(session: str, state: dict) -> None:
    path = c.session_file(GUARD, session)
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            prune(path.parent)
        tmp = path.with_name(f"{path.stem}.{os.getpid()}.tmp")
        payload = {**merged(session, state), "last_active": time.time()}
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass  # memory is a convenience; the decision was already made


def prune(folder: Path) -> None:
    """Drop state of sessions untouched for three days."""
    now = time.time()
    for old in folder.glob("*.json"):
        try:
            if now - old.stat().st_mtime > KEEP_SECONDS:
                old.unlink()
        except OSError:
            pass


def cap() -> int:
    raw = os.environ.get("PREFLIGHT_FACTS_MAX_DENIALS", "").strip()
    return int(raw) if raw.isdigit() else DEFAULT_CAP


def questions(target: fc.Target, condensed: bool) -> list[str]:
    words = {"stem": target.stem or target.symbol or target.rel, "table": target.table or "it"}
    items = [q.format(**words) for q in QUESTIONS[target.cls]] + [COMMON]
    return [", ".join(items)] if condensed else items


def credit_words(target: fc.Target) -> list[str]:
    """What a search must have looked for: the stem, the symbol, the table; the
    folder name when the file has neither a usable stem nor a symbol."""
    words = [target.stem, target.symbol, target.table]
    if not target.stem and not target.symbol:
        words.append(target.parent)
    return words


def credit(payload: dict, target: fc.Target) -> str | None:
    """Label of the search that credits the target; "" when none; None when no
    transcript could be read at all."""
    transcript = payload.get("transcript_path")
    if not isinstance(transcript, str) or not transcript:
        return None
    records = tt.tail_records(transcript)
    if not records:
        return None
    turn = tt.current_turn(records)
    if turn is None:
        return ""
    calls = tt.completed_calls(turn)
    # With no id at all (older Claude Code), the newest assistant message is the edit's batch.
    # With an id that is not in the tail yet, its siblings are not in the tail either.
    call_id = str(payload.get("tool_use_id") or "")
    batch = tt.batch_of(turn, call_id) if call_id else tt.last_batch(turn)
    return sc.crediting_label(calls, credit_words(target), target.rel, batch)


def decide(
    payload: dict, tool_name: str, tool_input: dict, session: str
) -> tuple[Verdict, dict | None]:
    """The guard's decision and the session state it changed (None: nothing read or changed)."""
    root = c.base_dir(payload)
    path = target_path(tool_name, tool_input)
    target = fc.classify(path, edit_text(tool_input), root)
    if not target.cls:
        return PASS, None
    state = load_state(session)
    if target.rel in state["checked"]:
        return PASS, None
    state["checked"].append(target.rel)  # every verdict below settles the file, except a denial
    if target.cls == "config" and tool_name == "Write" and not _exists(root / path):
        return Verdict(
            "note", f"facts: new check configuration {target.rel}, nothing to weaken yet", []
        ), state
    label = credit(payload, target)
    denials = state["denials"].get(target.rel, 0)
    if label or (label is None and denials) or denials >= cap():
        return Verdict("note", _why_through(target.rel, label, denials), []), state
    state["checked"].pop()
    state["denials"][target.rel] = denials + 1
    title = f"preflight facts: {TITLES[target.cls]} ({target.rel}), show the facts first"
    return Verdict("deny", title, questions(target, condensed=denials >= 1)), state


def _exists(path: Path) -> bool:
    if fc.sf.is_network_path(str(path)):
        return True  # never stat a network path (NTLM); classify() already passed it by
    try:
        return path.exists()
    except (OSError, ValueError):  # a NUL byte, a path too long for the platform
        return False


def _why_through(rel: str, label: str | None, denials: int) -> str:
    if label:
        return f"facts: {rel} credited by {label}"
    if label is None:
        return f"facts: no transcript to check for {rel}, letting the retry through"
    return f"facts: {denials} denials for {rel} and no search seen, letting it through"


def main() -> int:
    if c.off_switch(GUARD):
        return 0
    payload = c.read_payload()
    tool_name = str(payload.get("tool_name") or "")
    tool_input = c.tool_input(payload)
    session = str(payload.get("session_id") or "")
    verdict, state = decide(payload, tool_name, tool_input, session)
    if verdict.kind == "pass":
        return 0
    if state is not None:
        save_state(session, state)
    c.log(GUARD, {"verdict": verdict.kind, "file": target_path(tool_name, tool_input)})
    if verdict.kind == "note":
        return c.tell_model(EVENT, verdict.title)
    return c.block(verdict.title, verdict.problems, HINT)


if __name__ == "__main__":
    c.run(GUARD, main)
