"""The current human turn of a Claude Code transcript, and the tool calls in it.

The facts guard credits an edit when the model searched the tree for the
file earlier in the same turn. The evidence is the transcript (`.jsonl`, one
record per line) the hook payload points to. Only the tail is read: a
session file grows to megabytes, and a search from an hour ago proves
nothing about this edit anyway.

A turn starts at the latest record a human wrote, or at a compaction
boundary; tool results, meta records and sidechain records never start one.
When the tail holds no start at all, the whole window counts as the turn
only if every user record in it carries the same `promptId`; two prompt ids
mean a turn started through a record this reader does not recognise, and
then nothing is credited.

Only the model's own `tool_use` blocks are read. The text of a `tool_result`
is foreign (a file, a web page, a command's output) and is never a source of
evidence: it is only looked at to know that the call completed.
"""

from __future__ import annotations

import json
import os
from typing import NamedTuple

TAIL_BYTES = 256 * 1024
MAX_LINES = 2000


class Call(NamedTuple):
    id: str
    name: str
    input: dict
    batch: str  # the assistant message the call was sent in ("" when unknown)


def tail_records(path: str) -> list[dict]:
    """The last records of the transcript; an empty list when it cannot be read."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - TAIL_BYTES))
            data = handle.read()
    except (OSError, ValueError):
        return []
    # The window usually starts inside a record; that fragment is not JSON and is skipped.
    lines = data.decode("utf-8", errors="replace").rstrip("\n").split("\n")
    records = []
    for line in lines[-MAX_LINES:]:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _content(record: dict) -> object:
    message = record.get("message")
    return message.get("content") if isinstance(message, dict) else None


def _blocks(record: dict, kind: str) -> list[dict]:
    content = _content(record)
    if not isinstance(content, list):
        return []
    return [b for b in content if isinstance(b, dict) and b.get("type") == kind]


def starts_turn(record: dict) -> bool:
    """A human message or a compaction boundary; never a tool result or a meta record."""
    if record.get("type") == "system":
        return record.get("subtype") == "compact_boundary"
    if record.get("type") != "user" or record.get("isSidechain") or record.get("isMeta"):
        return False
    content = _content(record)  # a compaction summary is a human-shaped record too
    if isinstance(content, str):
        return True
    return isinstance(content, list) and not _blocks(record, "tool_result")


def current_turn(records: list[dict]) -> list[dict] | None:
    """Records of the current turn; None when the window cannot be trusted."""
    for index in range(len(records) - 1, -1, -1):
        if starts_turn(records[index]):
            return records[index:]
    prompts = {r.get("promptId") for r in records if r.get("type") == "user"}
    return list(records) if len(prompts) == 1 else None


def completed_calls(turn: list[dict]) -> list[Call]:
    """Tool calls of the turn whose result came back without an error.

    A call id seen twice is never trusted; a result is an error when it says
    so (`is_error`) or starts with `<tool_use_error>`.
    """
    results: dict[str, bool | None] = {}
    for record in turn:
        if record.get("type") != "user" or record.get("isSidechain"):
            continue
        for block in _blocks(record, "tool_result"):
            call_id = str(block.get("tool_use_id") or "")
            results[call_id] = None if call_id in results else _ok(block)
    calls: list[Call] = []
    seen: set[str] = set()
    for record in turn:
        if record.get("type") != "assistant" or record.get("isSidechain"):
            continue
        batch = _batch(record)
        for block in _blocks(record, "tool_use"):
            call_id = str(block.get("id") or "")
            if not call_id or call_id in seen:
                results[call_id] = None  # never trusted, so the check below skips it
            seen.add(call_id)
            if results.get(call_id) and isinstance(block.get("input"), dict):
                calls.append(Call(call_id, str(block.get("name") or ""), block["input"], batch))
    # A second block with the same id arrives after the first was appended: drop both.
    return [call for call in calls if results.get(call.id)]


def _ok(block: dict) -> bool:
    error = block.get("is_error")
    if error is True or str(error).lower() == "true":
        return False
    content = block.get("content")
    if isinstance(content, list):
        content = " ".join(str(b.get("text", "")) for b in content if isinstance(b, dict))
    return not str(content or "").lstrip().startswith("<tool_use_error>")


def _batch(record: dict) -> str:
    message = record.get("message")
    message_id = message.get("id") if isinstance(message, dict) else None
    return str(message_id or record.get("requestId") or "")


def batch_of(turn: list[dict], call_id: str) -> str:
    """The assistant message that sent `call_id`, or "" when it is not in the turn."""
    for record in turn:
        if record.get("type") == "assistant":
            if any(str(b.get("id") or "") == call_id for b in _blocks(record, "tool_use")):
                return _batch(record)
    return ""


def last_batch(turn: list[dict]) -> str:
    """The newest assistant message of the turn: where a gated call with an unknown id came from."""
    for record in reversed(turn):
        if record.get("type") == "assistant" and not record.get("isSidechain"):
            return _batch(record)
    return ""
