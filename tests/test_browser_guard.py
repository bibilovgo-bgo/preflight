from __future__ import annotations

import json
import os
import time

import pytest

import _common as c
import browser_guard as bg
from conftest import run_guard

CHROME = "mcp__claude-in-chrome__"
PANE = "mcp__Claude_Browser__"
NOW = 1_000_000.0


def walk(tool: str, tool_input: dict, last_nav: float = 0.0, now: float = NOW):
    return bg.walk(tool, tool_input, last_nav, now)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (CHROME + "navigate", True),
        (PANE + "read_page", True),
        ("mcp__remote-devices__Claude_Browser__find", True),
        ("mcp__playwright__browser_navigate", False),
        ("Bash", False),
        ("", False),
        ("claude_browser__navigate", False),
    ],
)
def test_is_browser_tool(name, expected):
    assert bg.is_browser_tool(name) is expected


def test_tool_kind():
    assert bg.tool_kind(CHROME + "get_page_text") == "get_page_text"
    assert bg.tool_kind("navigate") == "navigate"


# --- reading too soon after a navigation --------------------------------------


@pytest.mark.parametrize("reader", sorted(bg.READERS))
def test_read_right_after_navigation_blocks(reader):
    problems, _ = walk(PANE + reader, {}, last_nav=NOW - 1)
    assert len(problems) == 1 and "1.0s after a navigation" in problems[0]


def test_read_after_settle_time_passes():
    assert walk(PANE + "read_page", {}, last_nav=NOW - 3)[0] == []


def test_read_without_any_navigation_passes():
    assert walk(PANE + "read_page", {}, last_nav=0.0)[0] == []


def test_settle_time_is_configurable(monkeypatch):
    monkeypatch.setenv("PREFLIGHT_BROWSER_SETTLE", "10")
    assert walk(PANE + "read_page", {}, last_nav=NOW - 5)[0]
    monkeypatch.setenv("PREFLIGHT_BROWSER_SETTLE", "0")
    assert walk(PANE + "read_page", {}, last_nav=NOW - 0.1)[0] == []


@pytest.mark.parametrize("raw", ["abc", "-5"])
def test_bad_settle_value_falls_back_or_clamps(monkeypatch, raw):
    monkeypatch.setenv("PREFLIGHT_BROWSER_SETTLE", raw)
    assert bg.settle_seconds() == (3.0 if raw == "abc" else 0.0)


# --- what counts as a navigation -----------------------------------------------


@pytest.mark.parametrize("kind", sorted(bg.NAVIGATORS))
def test_navigators_set_the_clock(kind):
    assert walk(PANE + kind, {}, last_nav=0.0)[1] == NOW


@pytest.mark.parametrize(
    "action", ["left_click", "double_click", "key", "type", "screenshot", "scroll"]
)
def test_computer_actions_do_not_count_as_navigation(action):
    """A click may or may not load a page; counting it blocked ordinary click-then-read work."""
    assert walk(CHROME + "computer", {"action": action}, last_nav=0.0)[1] == 0.0


@pytest.mark.parametrize("kind", ["tabs_select", "read_console_messages"])
def test_tab_switch_and_console_read_are_neither_navigation_nor_read(kind):
    assert walk(PANE + kind, {}, last_nav=NOW - 0.5) == ([], NOW - 0.5)


def test_wait_resets_the_clock():
    assert walk(CHROME + "computer", {"action": "wait", "duration": 2}, last_nav=NOW - 1)[1] == 0.0


def test_other_tools_keep_the_clock():
    assert walk(CHROME + "javascript_tool", {"text": "1"}, last_nav=NOW - 1)[1] == NOW - 1


# --- inside a batch ---------------------------------------------------------------


def batch(*names_and_inputs):
    return {"actions": [{"name": n, "input": i} for n, i in names_and_inputs]}


def test_batch_navigate_then_read_blocks():
    problems, last = walk(
        PANE + "browser_batch", batch(("navigate", {"url": "x"}), ("get_page_text", {}))
    )
    assert (
        len(problems) == 1
        and "no wait in between" in problems[0]
        and "get_page_text" in problems[0]
    )
    assert last == NOW


def test_batch_navigate_wait_read_passes():
    actions = batch(
        ("navigate", {"url": "x"}),
        ("computer", {"action": "wait", "duration": 2}),
        ("read_page", {}),
    )
    problems, last = walk(PANE + "browser_batch", actions)
    assert problems == [] and last == 0.0


def test_batch_click_then_find_passes():
    actions = batch(("computer", {"action": "left_click"}), ("find", {"query": "x"}))
    assert walk(CHROME + "browser_batch", actions)[0] == []


def test_batch_new_tab_then_read_blocks():
    actions = batch(("tabs_create", {}), ("read_page", {}))
    assert walk(CHROME + "browser_batch", actions)[0]


def test_batch_starting_with_read_checks_previous_navigation():
    problems, _ = walk(PANE + "browser_batch", batch(("read_page", {})), last_nav=NOW - 1)
    assert problems and "after a navigation" in problems[0]


def test_batch_checks_scripts_inside():
    actions = batch(("javascript_tool", {"text": "document.querySelector('h1').innerText"}))
    assert walk(PANE + "browser_batch", actions)[0]


def test_malformed_batch_is_ignored():
    assert walk(PANE + "browser_batch", {"actions": "nope"}) == ([], 0.0)
    assert walk(
        PANE + "browser_batch", {"actions": ["x", {"name": "read_page", "input": "y"}]}
    ) == ([], 0.0)


def test_same_problem_is_reported_once():
    actions = batch(
        ("navigate", {}),
        ("read_page", {}),
        ("get_page_text", {}),
        ("javascript_tool", {"text": "document.querySelector('a').href"}),
        ("javascript_tool", {"text": "document.querySelector('b').href"}),
    )
    problems, _ = walk(PANE + "browser_batch", actions)
    assert len(problems) == 3


# --- null DOM access in scripts -------------------------------------------------


@pytest.mark.parametrize(
    "code",
    [
        "document.querySelector('h1').innerText",
        "document.getElementById('x').value",
        "el.closest('form').submit()",
        "document .querySelector ('h1') .innerText",
    ],
)
def test_unguarded_dom_blocks(code):
    problems, _ = walk(PANE + "javascript_tool", {"text": code})
    assert problems and "Cannot read properties of null" in problems[0]


@pytest.mark.parametrize(
    "code",
    [
        "document.querySelector('h1')?.innerText",
        "const el = document.querySelector('h1'); if (!el) return 'x'; el.innerText",
        "document.querySelector('h1') && document.querySelector('h1').innerText",
        "try { document.querySelector('h1').innerText } catch (e) {}",
        "(document.querySelector('h1') ?? {}).innerText",
        "document.title",
        "const el = document.querySelector('h1')",
        # These return collections, never null: reading off them is safe.
        "document.querySelectorAll('a').length",
        "document.getElementsByClassName('c').length",
        "[...document.querySelectorAll('a')].map(a => a.href)",
    ],
)
def test_guarded_dom_passes(code):
    assert walk(PANE + "javascript_tool", {"text": code})[0] == []


def test_dom_check_reads_the_code_field_too():
    assert walk(CHROME + "javascript_tool", {"code": "document.querySelector('x').id"})[0]


def test_dom_check_ignores_other_tools():
    assert walk(CHROME + "find", {"query": "document.querySelector('x').id"})[0] == []


# --- state per session --------------------------------------------------------------


def test_state_round_trip_and_isolation():
    bg.save("session-a", 123.5)
    assert bg.load("session-a") == 123.5
    assert bg.load("session-b") == 0.0
    assert bg.load("") == 0.0
    bg.save("", 1.0)
    assert not (c.data_dir() / "browser" / ".json").exists()


def test_broken_state_file_reads_as_settled():
    path = c.session_file("browser", "s")
    path.parent.mkdir(parents=True)
    for text in ("{broken", "[]", '{"last_navigation_at": "x"}'):
        path.write_text(text, encoding="utf-8")
        assert bg.load("s") == 0.0


def test_old_session_files_are_pruned_on_new_session():
    folder = c.data_dir() / "browser"
    folder.mkdir(parents=True)
    old, recent = folder / "old.json", folder / "recent.json"
    for path in (old, recent):
        path.write_text("{}", encoding="utf-8")
    stale = time.time() - bg.KEEP_SECONDS - 60
    os.utime(old, (stale, stale))
    bg.save("new-session", 1.0)
    assert not old.exists() and recent.exists()


# --- the process ----------------------------------------------------------------------


def call(tool: str, tool_input: dict, session: str = "s1", env: dict | None = None):
    payload = {"tool_name": tool, "tool_input": tool_input, "session_id": session}
    return run_guard("browser_guard", payload, env=env)


def test_process_navigate_then_read_blocks_then_wait_unblocks():
    assert call(PANE + "navigate", {"url": "https://example.com"}).returncode == 0
    blocked = call(PANE + "get_page_text", {})
    assert blocked.returncode == 2 and "preflight/browser" in blocked.stderr.decode("utf-8")
    assert call(PANE + "computer", {"action": "wait", "duration": 2}).returncode == 0
    assert call(PANE + "get_page_text", {}).returncode == 0


def test_process_sessions_do_not_share_the_clock():
    assert call(PANE + "navigate", {"url": "x"}, session="one").returncode == 0
    assert call(PANE + "read_page", {}, session="two").returncode == 0


def test_process_blocked_call_does_not_move_the_clock():
    actions = batch(("navigate", {"url": "x"}), ("read_page", {}))
    assert call(PANE + "browser_batch", actions).returncode == 2
    assert call(PANE + "read_page", {}).returncode == 0


def test_process_bypass_lets_it_run_and_still_records():
    actions = batch(("navigate", {"url": "x#browser-ok"}), ("read_page", {}))
    assert call(PANE + "browser_batch", actions).returncode == 0
    assert call(PANE + "read_page", {}).returncode == 2


def test_process_ignores_non_browser_tools():
    done = run_guard(
        "browser_guard",
        {"tool_name": "Bash", "tool_input": {"command": "x"}, "session_id": "s"},
    )
    assert done.returncode == 0
    assert not (c.data_dir() / "browser").exists()


def test_process_off_switch():
    assert call(PANE + "navigate", {"url": "x"}).returncode == 0
    assert call(PANE + "read_page", {}, env={"PREFLIGHT_BROWSER": "0"}).returncode == 0


def test_process_log(tmp_path):
    data = tmp_path / "d"
    env = {"PREFLIGHT_LOG": "1", "CLAUDE_PLUGIN_DATA": str(data)}
    call(PANE + "javascript_tool", {"text": "document.querySelector('x').id"}, env=env)
    record = json.loads((data / "log" / "browser.jsonl").read_text(encoding="utf-8"))
    assert record["tool"] == "javascript_tool" and len(record["problems"][0]) == 80


@pytest.mark.parametrize(
    "code", ["querySelector(" * 30_000, "closest(" * 40_000], ids=["qs", "closest"]
)
def test_long_hostile_script_is_checked_fast(code):
    started = time.perf_counter()
    walk(PANE + "javascript_tool", {"text": code})
    assert time.perf_counter() - started < 2
