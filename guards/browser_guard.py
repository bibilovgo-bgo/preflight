"""PreToolUse on Claude's browser tools: the two mistakes that waste most calls.

Browser automation was the largest class of wasted tool calls in our own logs,
and the worst at self-correcting. Two patterns dominate and both are visible
before the call runs:

* reading a page right after navigating: the page is still loading, the
  read returns a half-rendered DOM or fails, and the next script hits a null;
* a script that reads a property straight off `querySelector(...)`: when the
  node is missing, it dies with "Cannot read properties of null" instead of
  reporting that the element is not there.

The guard remembers, per session, when the last navigation happened, and
blocks a read that comes sooner than PREFLIGHT_BROWSER_SETTLE seconds (3 by
default) after it, unless a `wait` came in between. Inside one
`browser_batch` it checks the same order: navigate, then wait, then read.

Covers Claude in Chrome (`mcp__claude-in-chrome__*`) and the desktop app's
built-in browser (`mcp__Claude_Browser__*`).

Deliberate bypass: `#browser-ok` in any string field of the call.
Off switch: PREFLIGHT_BROWSER=0.
"""

from __future__ import annotations

import json
import os
import re
import time

import _common as c

GUARD = "browser"
BYPASS = "#browser-ok"
# Only calls that load a page. A click may or may not navigate, and switching
# to a tab shows a page that is already loaded: counting those blocked
# ordinary "click, then read" work, so they are left out.
NAVIGATORS = frozenset({"navigate", "tabs_create", "preview_start"})
# Reading console messages right after a load is how load errors are caught.
READERS = frozenset({"get_page_text", "read_page", "find"})
KEEP_SECONDS = 3 * 24 * 3600

# Only the lookups that can return null. querySelectorAll and getElementsBy*
# return collections, never null, so reading `.length` off them is safe. The
# argument is bounded so a long script costs linear time.
_DOM_ACCESS = re.compile(r"\b(?:querySelector|getElementById|closest)\s*\([^)]{0,500}\)\s*\.(?!\.)")
_GUARDED = re.compile(r"\?\.|&&|\bif\s*\(|\btry\s*\{|\?\?")


def settle_seconds() -> float:
    try:
        return max(0.0, float(os.environ.get("PREFLIGHT_BROWSER_SETTLE", "3")))
    except ValueError:
        return 3.0


def tool_kind(tool_name: str) -> str:
    """`mcp__claude-in-chrome__navigate` -> `navigate`."""
    return (tool_name or "").rsplit("__", 1)[-1]


def is_browser_tool(tool_name: str) -> bool:
    low = (tool_name or "").lower()
    return low.startswith("mcp__") and ("claude-in-chrome__" in low or "claude_browser__" in low)


def navigates(kind: str, _tool_input: dict) -> bool:
    return kind in NAVIGATORS


def is_wait(kind: str, tool_input: dict) -> bool:
    return kind == "computer" and tool_input.get("action") == "wait"


def premature_read(kind: str, last_nav: float, now: float) -> str:
    if kind not in READERS or not last_nav:
        return ""
    gap = now - last_nav
    if gap >= settle_seconds():
        return ""
    return (
        f"reading the page {gap:.1f}s after a navigation: it is most likely still "
        'loading. Put a `computer` call with action="wait" (2-3 s) before the '
        "read, or do navigate -> wait -> read in one browser_batch."
    )


def unguarded_dom(kind: str, tool_input: dict) -> str:
    if kind != "javascript_tool":
        return ""
    code = str(tool_input.get("text") or tool_input.get("code") or "")
    if not _DOM_ACCESS.search(code) or _GUARDED.search(code):
        return ""
    return (
        "the script reads a property straight off querySelector(...) and friends. "
        'If the element is missing that throws "Cannot read properties of null". '
        "Check first: `const el = document.querySelector(...); if (!el) return "
        "'not found';` or use `el?.innerText`."
    )


def steps(tool_name: str, tool_input: dict) -> list[tuple[str, dict]]:
    """(kind, input) of each step: the call itself, or each action of a batch."""
    kind = tool_kind(tool_name)
    if kind != "browser_batch":
        return [(kind, tool_input)]
    actions = tool_input.get("actions")
    out = []
    for action in actions if isinstance(actions, list) else []:
        if isinstance(action, dict):
            params = action.get("input")
            out.append(
                (
                    tool_kind(str(action.get("name") or "")),
                    params if isinstance(params, dict) else {},
                )
            )
    return out


BATCH_NO_WAIT = (
    "this batch reads the page ({kind}) right after a navigation with no wait in "
    'between. Insert {{"name": "computer", "input": {{"action": "wait", "duration": 2}}}} '
    "before the read."
)


def walk(tool_name: str, tool_input: dict, last_nav: float, now: float) -> tuple[list[str], float]:
    """Problems of this call, and when the last navigation happened after it.

    Steps are replayed in order: a navigation earlier in the same batch makes a
    later read premature unless a wait comes between them.
    """
    problems: list[str] = []
    navigated_here = False
    for kind, params in steps(tool_name, tool_input):
        if kind in READERS:
            if navigated_here:
                problems.append(BATCH_NO_WAIT.format(kind=kind))
            else:
                problems.append(premature_read(kind, last_nav, now))
        problems.append(unguarded_dom(kind, params))
        if navigates(kind, params):
            navigated_here, last_nav = True, now
        elif is_wait(kind, params):
            navigated_here, last_nav = False, 0.0
    return [p for p in dict.fromkeys(problems) if p], last_nav


def load(session: str) -> float:
    path = c.session_file("browser", session)
    if path is None:
        return 0.0
    try:
        return float(json.loads(path.read_text(encoding="utf-8")).get("last_navigation_at") or 0)
    except (OSError, ValueError, TypeError, AttributeError):
        return 0.0


def save(session: str, last_nav: float) -> None:
    path = c.session_file("browser", session)
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            prune(path.parent)
        tmp = path.with_name(f"{path.stem}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"last_navigation_at": last_nav}), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass


def prune(folder) -> None:
    """Drop state of sessions untouched for three days."""
    now = time.time()
    for old in folder.glob("*.json"):
        try:
            if now - old.stat().st_mtime > KEEP_SECONDS:
                old.unlink()
        except OSError:
            pass


def main() -> int:
    if c.off_switch(GUARD):
        return 0
    payload = c.read_payload()
    tool_name = str(payload.get("tool_name") or "")
    if not is_browser_tool(tool_name):
        return 0
    tool_input = c.tool_input(payload)
    session = str(payload.get("session_id") or "")
    last_nav = load(session)
    problems, updated = walk(tool_name, tool_input, last_nav, time.time())
    if BYPASS in json.dumps(tool_input, ensure_ascii=False):
        problems = []  # deliberate: let it run, but still remember what it does
    if not problems:
        if updated != last_nav:  # a blocked call did not run: nothing to remember
            save(session, updated)
        return 0
    c.log(GUARD, {"tool": tool_kind(tool_name), "problems": [p[:80] for p in problems]})
    return c.block(
        "preflight/browser: this call repeats a known browser-automation mistake.",
        problems,
        f"Rework the call as suggested. If this is deliberate, add {BYPASS} to a string field.",
    )


if __name__ == "__main__":
    c.run(GUARD, main)
