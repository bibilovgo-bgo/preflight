"""Edge cases the mutation run showed no test was guarding, grouped by module."""

from __future__ import annotations

import io
import json
import os
import time
from pathlib import Path

import pytest

import _common as c
import browser_guard as bg
import clone_scan as cs
import repo_fixtures as fx
import repo_git
from conftest import run_guard
from findings import CLIP, clip, finding, hidden_chars
from repo_files import MAX_WALK
from repo_scan import HIGH, MEDIUM, scan

# --- _common -------------------------------------------------------------------


def test_read_payload_of_garbage_is_an_empty_dict(monkeypatch):
    monkeypatch.setattr(c.sys, "stdin", io.StringIO("not json"))
    assert c.read_payload() == {}
    monkeypatch.setattr(c.sys, "stdin", io.StringIO("[1, 2]"))
    assert c.read_payload() == {}


def test_blank_cwd_falls_back_to_the_project_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    assert c.base_dir({"cwd": "   "}) == tmp_path


@pytest.mark.skipif(os.name != "nt", reason="drive handling is Windows-only")
def test_empty_word_resolves_to_the_base():
    assert c.resolve_path(Path("C:/x"), "") == Path("C:/x")


def test_session_name_is_capped_at_96():
    assert len(c.session_file("x", "a" * 300).stem) == 96


def test_log_switch_value_is_stripped(monkeypatch):
    monkeypatch.setenv("PREFLIGHT_LOG", " 1 ")
    c.log("safety", {"a": 1})
    assert (c.data_dir() / "log" / "safety.jsonl").exists()


def test_crash_log_line_is_capped(monkeypatch):
    monkeypatch.setenv("PREFLIGHT_LOG", "1")

    def crash():
        raise ValueError("x" * 1000)

    with pytest.raises(SystemExit):
        c.run("safety", crash)
    record = json.loads((c.data_dir() / "log" / "safety.jsonl").read_text(encoding="utf-8"))
    assert len(record["crash"]) == 300


def test_block_without_hint_has_no_trailing_blank_line(capsys):
    c.block("title", ["one"])
    assert capsys.readouterr().err == "title\n  - one\n"


def test_tell_model_without_user_line_has_no_system_message(capsys):
    c.tell_model("PostToolUse", "ctx")
    assert "systemMessage" not in json.loads(capsys.readouterr().out)


# --- browser_guard -------------------------------------------------------------


def test_a_screenshot_does_not_settle_the_page():
    problems, last = bg.walk(
        "mcp__Claude_Browser__computer", {"action": "screenshot"}, 100.0, 101.0
    )
    assert last == 100.0
    assert bg.walk("mcp__Claude_Browser__read_page", {}, last, 101.0)[0]


def test_dom_check_only_reads_javascript():
    code = {"action": "type", "text": "document.querySelector('x').id"}
    assert bg.walk("mcp__Claude_Browser__computer", code, 0.0, 1.0)[0] == []


def test_state_of_an_unknown_session_is_settled():
    assert bg.load("") == 0.0


def test_read_without_navigation_writes_no_state():
    payload = {"tool_name": "mcp__Claude_Browser__find", "tool_input": {}, "session_id": "s9"}
    assert run_guard("browser_guard", payload).returncode == 0
    assert not (c.data_dir() / "browser").exists()


def test_session_files_live_three_days():
    folder = c.data_dir() / "browser"
    folder.mkdir(parents=True)
    old = folder / "old.json"
    old.write_text("{}", encoding="utf-8")
    two_days = time.time() - 2 * 24 * 3600
    os.utime(old, (two_days, two_days))
    bg.save("new", 1.0)
    assert old.exists()
    three_and_a_half_days = time.time() - 3.5 * 24 * 3600  # past three days, short of four
    os.utime(old, (three_and_a_half_days, three_and_a_half_days))
    bg.save("newer", 1.0)
    assert not old.exists()


# --- findings ------------------------------------------------------------------


@pytest.mark.parametrize("code", [0x034F, 0x061C, 0x115F, 0x17B4, 0x202A, 0xFEFF, 0xFFA0, 0xE0001])
def test_each_invisible_range_is_counted(code):
    assert hidden_chars("a" + chr(code) + "b") == 1


def test_clip_limits_and_spaces():
    assert CLIP == 160
    assert len(clip("x" * 500)) == 160
    assert clip("x" * 20, 20) == "x" * 20
    assert clip("  a    b  ") == "a b"
    assert clip("a  b") == "a b"
    assert len(finding(HIGH, "p" * 300, "w").path) == 120


# --- repo_files / repo_scan -----------------------------------------------------


def test_json_that_is_not_an_object(tmp_path):
    root = fx.make_clean(tmp_path / "j")
    (root / ".claude").mkdir()
    (root / ".claude/settings.json").write_text("[]", encoding="utf-8")
    found = scan(root)
    assert [(f.level, f.path) for f in found] == [(MEDIUM, ".claude/settings.json")]
    assert "not an object" in found[0].what


@pytest.mark.parametrize(
    ("count", "noted"), [(MAX_WALK, False), (MAX_WALK + 1, True), (MAX_WALK + 5, True)]
)
def test_walk_cap_boundary(tmp_path, count, noted):
    root = fx.make_clean(tmp_path / "w")
    hooks = root / ".claude/hooks"
    hooks.mkdir(parents=True)
    for i in range(count):
        (hooks / f"f{i}.txt").write_text("x", encoding="utf-8")
    notes = [f for f in scan(root) if "not scanned" in f.what]
    assert len(notes) == (1 if noted else 0)


def test_linked_folder_inside_hooks_is_noted(tmp_path):
    from test_clone_scan_hardening import make_link

    outside = tmp_path / "outside"
    outside.mkdir()
    root = fx.make_clean(tmp_path / "r")
    (root / ".claude/hooks").mkdir(parents=True)
    if not make_link(root / ".claude/hooks/sub", outside):
        pytest.skip("cannot create a directory link here")
    assert any("directory link, not followed" in f.what for f in scan(root))


@pytest.mark.parametrize("doc", [".claude/CLAUDE.md", "skills/x/SKILL.md"])
def test_hidden_text_in_more_agent_docs(tmp_path, doc):
    root = fx.make_clean(tmp_path / "d")
    (root / doc).parent.mkdir(parents=True, exist_ok=True)
    (root / doc).write_text("hi" + chr(0x200B) + "there\n", encoding="utf-8")
    assert [(f.level, f.path) for f in scan(root)] == [(HIGH, doc)]


@pytest.mark.parametrize("rel", [".vscode/tasks.json", ".mcp.json", "CLAUDE.md"])
def test_oversized_file_is_one_medium_finding(tmp_path, rel):
    root = fx.make_clean(tmp_path / "o")
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_bytes(b" " * 1_100_000)
    found = scan(root)
    assert [(f.level, f.path) for f in found] == [(MEDIUM, rel)] and "too large" in found[0].what


def test_mcp_server_without_command_shows_its_args_cleanly(tmp_path):
    root = fx.make_clean(tmp_path / "m")
    (root / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"s": {"args": ["x.py"]}}}), encoding="utf-8"
    )
    assert scan(root)[0].what == "MCP server s: x.py"


@pytest.mark.parametrize("url", ["http://127.0.0.1:9/h", "http://[::1]/h", "https://localhost/h"])
def test_local_http_hooks_are_medium(tmp_path, url):
    root = fx.make_clean(tmp_path / "l")
    (root / ".claude").mkdir()
    hook = {"hooks": {"PreToolUse": [{"hooks": [{"type": "http", "url": url}]}]}}
    (root / ".claude/settings.json").write_text(json.dumps(hook), encoding="utf-8")
    assert [f.level for f in scan(root)] == [MEDIUM]


# --- repo_git ------------------------------------------------------------------


def test_oversized_git_config_is_one_finding_and_git_is_not_run(tmp_path):
    root = fx.make_clean(tmp_path / "g")
    with (root / ".git/config").open("a", encoding="utf-8") as fh:
        fh.write("#" * 1_100_000 + "\n")
    found = [f for f in scan(root) if f.path.startswith(".git")]
    assert [(f.level, f.path) for f in found] == [(HIGH, ".git/config")]
    assert "git is not run" in found[0].what


def test_git_failure_reads_as_no_history(monkeypatch, tmp_path):
    def boom(*_a, **_k):
        raise OSError("git is missing")

    monkeypatch.setattr(repo_git.subprocess, "run", boom)
    assert repo_git._git_log(tmp_path) == ""


# --- clone_scan ----------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "git clone --filter blob:none https://x/o/repo",
        "git clone -j 4 https://x/o/repo",
        "git clone --template /t https://x/o/repo",
        "git clone -u /x/git-upload-pack https://x/o/repo",
        "git clone --separate-git-dir /g https://x/o/repo",
        "git clone --jobs 2 https://x/o/repo",
    ],
)
def test_clone_options_with_values(command, tmp_path):
    assert cs.clone_targets(command, tmp_path) == [tmp_path / "repo"]


def test_git_with_dangling_option_is_not_a_clone(tmp_path):
    assert cs.clone_targets("git -C", tmp_path) == []
    assert cs.clone_targets("git --no-pager", tmp_path) == []


def test_fresh_window_is_five_minutes(tmp_path):
    repo = fx.make_clean(tmp_path / "r")
    four_minutes = time.time() - 240
    os.utime(repo, (four_minutes, four_minutes))
    assert cs.fresh_repos(tmp_path) == [repo]
    six_minutes = time.time() - 360
    os.utime(repo, (six_minutes, six_minutes))
    assert cs.fresh_repos(tmp_path) == []


def test_long_names_are_clipped_in_the_report(tmp_path):
    root = tmp_path / ("n" * 100)  # longer trips MAX_PATH on Windows
    fx.make_infected(root)
    told, shown = cs.render({root: scan(root)})
    assert len(told.splitlines()[0].split(": ")[1]) <= 200
    assert shown.startswith("n" * 77 + "...")
