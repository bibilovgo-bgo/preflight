from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import _common as c


def test_off_switch_names_the_variable(monkeypatch):
    assert c.off_switch("edit") == ""
    monkeypatch.setenv("PREFLIGHT_EDIT", "0")
    assert c.off_switch("edit") == "PREFLIGHT_EDIT"
    assert c.off_switch("safety") == ""
    monkeypatch.setenv("PREFLIGHT", "0")
    assert c.off_switch("safety") == "PREFLIGHT"


def test_switch_value_is_stripped(monkeypatch):
    monkeypatch.setenv("PREFLIGHT_EDIT", " 0 ")
    assert c.off_switch("edit") == "PREFLIGHT_EDIT"


@pytest.mark.parametrize("value", ["1", "", "false", "no"])
def test_only_zero_switches_off(monkeypatch, value):
    monkeypatch.setenv("PREFLIGHT_EDIT", value)
    assert c.off_switch("edit") == ""


def test_data_dir_prefers_plugin_data(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path))
    assert c.data_dir() == tmp_path
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", "  ")
    assert c.data_dir() == Path.home() / ".claude" / "preflight"


def test_session_file_sanitizes_and_refuses_empty():
    assert c.session_file("x", "../../etc/passwd").name == "etcpasswd.json"
    assert c.session_file("x", "") is None
    assert c.session_file("x", "///") is None


def test_log_is_off_by_default(tmp_path):
    c.log("edit", {"a": 1})
    assert not (c.data_dir() / "log").exists()


def test_log_writes_when_enabled(monkeypatch):
    monkeypatch.setenv("PREFLIGHT_LOG", "1")
    c.log("edit", {"a": 1})
    line = (c.data_dir() / "log" / "edit.jsonl").read_text(encoding="utf-8")
    record = json.loads(line)
    assert record["a"] == 1 and "ts" in record


def test_base_dir_order(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path / "project"))
    assert c.base_dir({"cwd": str(tmp_path)}) == tmp_path
    assert c.base_dir({}) == tmp_path / "project"
    monkeypatch.delenv("CLAUDE_PROJECT_DIR")
    assert c.base_dir({"cwd": ""}) == Path.cwd()


@pytest.mark.skipif(os.name != "nt", reason="Git Bash drive paths exist only on Windows")
def test_resolve_msys_drive_path():
    assert c.resolve_path(Path("C:/x"), "/d/work") == Path("D:/work")
    assert c.resolve_path(Path("C:/x"), "/d") == Path("D:/")


def test_resolve_relative_and_home():
    assert c.resolve_path(Path("/base"), "sub") == Path("/base/sub")
    assert c.resolve_path(Path("/base"), "~") == Path.home()


def test_block_and_tell_model(capsys):
    assert c.block("title", ["one"], "hint") == 2
    err = capsys.readouterr().err
    assert "title" in err and "  - one" in err and "hint" in err
    assert c.tell_model("PostToolUse", "ctx", "user") == 0
    out = json.loads(capsys.readouterr().out)
    assert out["hookSpecificOutput"] == {"hookEventName": "PostToolUse", "additionalContext": "ctx"}
    assert out["systemMessage"] == "user"


def test_run_turns_a_crash_into_a_pass_and_a_log_line(monkeypatch):
    monkeypatch.setenv("PREFLIGHT_LOG", "1")

    def crash():
        raise ValueError("embedded null byte")

    with pytest.raises(SystemExit) as exit_info:
        c.run("edit", crash)
    assert exit_info.value.code == 0
    assert "embedded null byte" in (c.data_dir() / "log" / "edit.jsonl").read_text(encoding="utf-8")


def test_run_passes_the_exit_code_through():
    with pytest.raises(SystemExit) as exit_info:
        c.run("edit", lambda: 2)
    assert exit_info.value.code == 2


@pytest.mark.parametrize("guard", ["edit_guard", "safety_guard", "secret_scan", "browser_guard"])
def test_nul_byte_in_cwd_fails_open(guard):
    from conftest import run_guard

    payload = {"tool_name": "Bash", "cwd": "a\u0000b", "tool_input": {"command": "git commit -m x"}}
    done = run_guard(guard, payload)
    assert done.returncode == 0 and b"Traceback" not in done.stderr
