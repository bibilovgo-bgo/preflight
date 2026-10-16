"""hooks/run.sh: find a working Python once, remember it, step aside without one."""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from conftest import ROOT

SH = shutil.which("sh")
pytestmark = pytest.mark.skipif(SH is None, reason="no POSIX sh on PATH")


def launch(args: list[str], data, payload: dict | None = None, path: str | None = None):
    env = {
        **os.environ,
        "CLAUDE_PLUGIN_ROOT": str(ROOT),
        "CLAUDE_PLUGIN_DATA": str(data),
    }
    if path is not None:
        env["PATH"] = path
    return subprocess.run(
        [SH, str(ROOT / "hooks" / "run.sh"), *args],
        input=json.dumps(payload or {}).encode("utf-8"),
        capture_output=True,
        env=env,
        timeout=60,
    )


def test_runs_the_guard_and_keeps_its_exit_code(tmp_path):
    done = launch(
        ["safety_guard"],
        tmp_path,
        {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
    )
    assert done.returncode == 2 and b"preflight/safety" in done.stderr


def test_remembers_the_interpreter(tmp_path):
    launch(["safety_guard"], tmp_path, {"tool_input": {"command": "ls"}})
    chosen = (tmp_path / "python").read_text(encoding="utf-8").strip()
    assert chosen in {"python3", "python", "py"}


def test_uses_the_remembered_interpreter(tmp_path):
    (tmp_path / "python").write_text("no-such-python-xyz\n", encoding="utf-8")
    done = launch(["safety_guard"], tmp_path, {"tool_input": {"command": "rm -rf /"}})
    assert done.returncode == 2  # stale cache entry: found again, not trusted blindly
    assert (tmp_path / "python").read_text(encoding="utf-8").strip() != "no-such-python-xyz"


def test_passes_arguments_through(tmp_path):
    clean = tmp_path / "clean"
    clean.mkdir()
    done = launch(["clone_scan", "--scan", str(clean)], tmp_path / "data")
    assert done.returncode == 0 and b"clean" in done.stdout


def test_without_python_it_steps_aside_and_says_so_once(tmp_path):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    first = launch(
        ["safety_guard"],
        tmp_path,
        {"tool_input": {"command": "rm -rf /"}},
        path=str(empty),
    )
    assert first.returncode == 0
    assert "no Python 3.9+" in json.loads(first.stdout)["systemMessage"]
    second = launch(
        ["safety_guard"],
        tmp_path,
        {"tool_input": {"command": "rm -rf /"}},
        path=str(empty),
    )
    assert second.returncode == 0 and second.stdout == b""


HOOK_CASES = {
    "edit_guard": (
        {
            "tool_name": "Edit",
            "tool_input": {"file_path": "nope", "old_string": "a", "new_string": "a"},
        },
        2,
    ),
    "safety_guard": (
        {"tool_name": "Bash", "tool_input": {"command": "git push --force origin main"}},
        2,
    ),
    "secret_scan": ({"tool_name": "Bash", "tool_input": {"command": "ls"}}, 0),
    "browser_guard": (
        {"tool_name": "mcp__Claude_Browser__find", "tool_input": {}, "session_id": "s"},
        0,
    ),
    "clone_scan": ({"tool_name": "Bash", "tool_input": {"command": "ls"}}, 0),
}


def test_every_hooks_json_command_runs_as_the_harness_runs_it(tmp_path):
    """The command string goes through `sh -c` with ${CLAUDE_PLUGIN_ROOT} expanded by the shell."""
    config = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    commands = [
        h["command"] for groups in config["hooks"].values() for g in groups for h in g["hooks"]
    ]
    assert len(commands) == len(HOOK_CASES)
    env = {**os.environ, "CLAUDE_PLUGIN_ROOT": ROOT.as_posix(), "CLAUDE_PLUGIN_DATA": str(tmp_path)}
    for command in commands:
        payload, expected = HOOK_CASES[command.rsplit(" ", 1)[1]]
        done = subprocess.run(
            [SH, "-c", command],
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            env=env,
            timeout=60,
        )
        assert done.returncode == expected, (command, done.stderr[-300:])


def test_unwritable_data_dir_without_python_does_not_block(tmp_path):
    """A failed redirection of `:` used to exit the POSIX shell with 2, which blocks the call."""
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    done = launch(
        ["safety_guard"], blocker / "data", {"tool_input": {"command": "ls"}}, path=str(empty)
    )
    assert done.returncode == 0


def test_cache_naming_another_program_is_ignored(tmp_path):
    marker = tmp_path / "ran.txt"
    evil = tmp_path / "evil"
    evil.write_text(f"#!/bin/sh\necho x > '{marker.as_posix()}'\n", encoding="utf-8")
    evil.chmod(0o755)
    (tmp_path / "python").write_text(str(evil.as_posix()) + "\n", encoding="utf-8")
    done = launch(["safety_guard"], tmp_path, {"tool_input": {"command": "rm -rf /"}})
    assert done.returncode == 2 and not marker.exists()
