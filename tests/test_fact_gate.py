from __future__ import annotations

import json
import os
import time

import pytest

import _common as c
import fact_gate as fg
from conftest import run_guard

SESSION = "sess-facts-1"


def human(text="do it", prompt="p1"):
    return {"type": "user", "promptId": prompt, "message": {"role": "user", "content": text}}


def tool_use(call_id, name, tool_input, msg="m1"):
    block = {"type": "tool_use", "id": call_id, "name": name, "input": tool_input}
    return {"type": "assistant", "message": {"id": msg, "content": [block]}}


def result(call_id, prompt="p1", error=None):
    block = {"type": "tool_result", "tool_use_id": call_id, "content": "ok"}
    if error is not None:
        block["is_error"] = error
    return {"type": "user", "promptId": prompt, "message": {"content": [block]}}


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proj"
    for folder in ("src/payments", "app/auth", "db/migrations", "tests", "src/plain"):
        (root / folder).mkdir(parents=True)
    (root / "src/payments/charge.py").write_text("def charge(): pass\n", encoding="utf-8")
    (root / "app/auth/login.py").write_text("def login(): pass\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[tool.ruff]\n", encoding="utf-8")
    return root


@pytest.fixture
def transcript(tmp_path):
    path = tmp_path / "transcript.jsonl"

    def write(records):
        path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
        return str(path)

    return write


def edit(
    project,
    path,
    new="x = 1\n",
    tool="Edit",
    transcript_path="",
    session=SESSION,
    tool_use_id="edit1",
):
    key = "notebook_path" if tool == "NotebookEdit" else "file_path"
    tool_input = {key: str(project / path), "old_string": "a", "new_string": new}
    if tool == "Write":
        tool_input = {key: str(project / path), "content": new}
    payload = {
        "session_id": session,
        "cwd": str(project),
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_use_id": tool_use_id,
    }
    if transcript_path:
        payload["transcript_path"] = transcript_path
    return payload


def run(payload, env=None):
    return run_guard("fact_gate", payload, env=env)


def note_of(proc) -> str:
    out = json.loads(proc.stdout.decode("utf-8"))
    return out["hookSpecificOutput"]["additionalContext"]


def state_path(tmp_path):
    return tmp_path / "plugin-data" / "facts" / f"{SESSION}.json"


# --- first touch -------------------------------------------------------------


def test_first_edit_of_a_money_file_is_denied_with_the_questions(project, transcript):
    proc = run(edit(project, "src/payments/charge.py", transcript_path=transcript([human()])))
    err = proc.stderr.decode("utf-8")
    assert proc.returncode == 2 and proc.stdout == b""
    assert "first edit of a money path (src/payments/charge.py)" in err
    assert "who reads charge" in err and "quote the user's current instruction" in err
    assert err.rstrip().endswith(fg.HINT)


def test_an_ordinary_file_passes_and_leaves_no_state(project, transcript, tmp_path):
    proc = run(edit(project, "src/plain/thing.py", transcript_path=transcript([human()])))
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")
    assert not (tmp_path / "plugin-data").exists()


def test_a_test_file_in_a_money_folder_passes(project, transcript):
    proc = run(edit(project, "src/payments/test_charge.py", transcript_path=transcript([human()])))
    assert proc.returncode == 0


@pytest.mark.parametrize(
    ("path", "tool", "title"),
    [
        ("app/auth/login.py", "Edit", "auth path"),
        ("db/migrations/0042_add_orders.py", "Edit", "schema"),
        ("pyproject.toml", "Edit", "check configuration"),
        ("src/payments/new_module.py", "Write", "money path"),
        ("src/payments/book.ipynb", "NotebookEdit", "money path"),
    ],
)
def test_each_class_and_tool_is_gated(project, transcript, path, tool, title):
    proc = run(edit(project, path, tool=tool, transcript_path=transcript([human()])))
    assert proc.returncode == 2 and title in proc.stderr.decode("utf-8")


def test_schema_questions_name_the_table(project, transcript):
    payload = edit(
        project,
        "db/migrations/0042.py",
        new="op.add_column('orders', c)",
        transcript_path=transcript([human()]),
    )
    assert "touches orders" in run(payload).stderr.decode("utf-8")


def test_a_generic_stem_falls_back_to_the_symbol(project, transcript):
    payload = edit(
        project,
        "app/auth/models.py",
        new="class Token(Base):\n    pass",
        transcript_path=transcript([human()]),
    )
    assert "who calls Token" in run(payload).stderr.decode("utf-8")


def test_writing_a_new_check_config_passes_with_a_note(project, transcript):
    proc = run(
        edit(
            project,
            "ruff.toml",
            tool="Write",
            new="[lint]\n",
            transcript_path=transcript([human()]),
        )
    )
    assert proc.returncode == 0 and "nothing to weaken yet" in note_of(proc)


def test_off_switches(project, transcript):
    for env in ({"PREFLIGHT": "0"}, {"PREFLIGHT_FACTS": "0"}):
        proc = run(
            edit(project, "src/payments/charge.py", transcript_path=transcript([human()])), env=env
        )
        assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")


def test_exempt_globs_from_the_environment(project, transcript):
    env = {"PREFLIGHT_FACTS_EXEMPT": "src/payments/*"}
    proc = run(
        edit(project, "src/payments/charge.py", transcript_path=transcript([human()])), env=env
    )
    assert proc.returncode == 0


# --- retry, credit, cap --------------------------------------------------------


def test_retry_without_a_search_is_denied_again_then_capped(project, transcript, tmp_path):
    payload = edit(project, "src/payments/charge.py", transcript_path=transcript([human()]))
    assert run(payload).returncode == 2
    second = run(payload)
    assert second.returncode == 2
    err = second.stderr.decode("utf-8")
    assert err.count("  - ") == 1 and "(Grep/rg), where every amount" in err  # condensed
    state = json.loads(state_path(tmp_path).read_text(encoding="utf-8"))
    assert state["denials"] == {"src/payments/charge.py": 2}
    third = run(payload)
    assert third.returncode == 0 and "2 denials" in note_of(third)
    fourth = run(payload)
    assert (fourth.returncode, fourth.stdout) == (0, b"")  # checked: no more notes


def test_cap_is_configurable(project, transcript):
    payload = edit(project, "src/payments/charge.py", transcript_path=transcript([human()]))
    assert run(payload, env={"PREFLIGHT_FACTS_MAX_DENIALS": "1"}).returncode == 2
    assert run(payload, env={"PREFLIGHT_FACTS_MAX_DENIALS": "1"}).returncode == 0


def test_a_search_in_the_current_turn_credits_the_retry(project, transcript, tmp_path):
    records = [human(), tool_use("g1", "Grep", {"pattern": "charge"}), result("g1")]
    proc = run(edit(project, "src/payments/charge.py", transcript_path=transcript(records)))
    assert proc.returncode == 0 and "credited by Grep 'charge'" in note_of(proc)
    state = json.loads(state_path(tmp_path).read_text(encoding="utf-8"))
    assert state["checked"] == ["src/payments/charge.py"]
    again = run(edit(project, "src/payments/charge.py"))  # no transcript needed any more
    assert (again.returncode, again.stdout) == (0, b"")


@pytest.mark.parametrize(
    "records",
    [
        [human(), tool_use("g1", "Grep", {"pattern": "charge"}), result("g1"), human("next")],
        [human(), tool_use("g1", "Grep", {"pattern": "charge"}, msg="m-edit"), result("g1")],
        [human(), tool_use("g1", "Grep", {"pattern": "charge"}), result("g1", error=True)],
        [human(), tool_use("g1", "Read", {"file_path": "src/payments/charge.py"}), result("g1")],
        [human(), tool_use("g1", "Glob", {"pattern": "**/charge.py"}), result("g1")],
        [human(), tool_use("g1", "Bash", {"command": "grep charge < notes"}), result("g1")],
        [human(), tool_use("g1", "Grep", {"pattern": "charges"}), result("g1")],
        [human(), tool_use("g1", "Grep", {"pattern": "charge"})],
    ],
)
def test_these_do_not_credit(project, transcript, records):
    payload = edit(project, "src/payments/charge.py", transcript_path=transcript(records))
    payload["tool_use_id"] = "e1"
    if records[1]["message"].get("id") == "m-edit":
        records[1]["message"]["content"].append(
            {"type": "tool_use", "id": "e1", "name": "Edit", "input": {}}
        )
        payload["transcript_path"] = transcript(records)
    assert run(payload).returncode == 2


@pytest.mark.parametrize(
    "command",
    [
        "rg charge src",
        "grep -rn charge .",
        "git grep charge",
        "fd charge",
        "Select-String -Pattern charge -Path src",
    ],
)
def test_shell_searches_credit(project, transcript, command):
    tool = "PowerShell" if command.startswith("Select") else "Bash"
    records = [human(), tool_use("b1", tool, {"command": command}), result("b1")]
    proc = run(edit(project, "src/payments/charge.py", transcript_path=transcript(records)))
    assert proc.returncode == 0, proc.stderr


def test_search_for_the_table_credits_a_migration(project, transcript):
    records = [human(), tool_use("g1", "Grep", {"pattern": "orders"}), result("g1")]
    payload = edit(
        project,
        "db/migrations/0042.py",
        new="op.add_column('orders', c)",
        transcript_path=transcript(records),
    )
    assert run(payload).returncode == 0


def test_search_for_the_symbol_credits_a_generic_stem(project, transcript):
    records = [human(), tool_use("g1", "Grep", {"pattern": "Token"}), result("g1")]
    payload = edit(
        project,
        "app/auth/models.py",
        new="class Token(Base):\n    pass",
        transcript_path=transcript(records),
    )
    assert run(payload).returncode == 0


# --- missing pieces, damage, expiry ------------------------------------------


def test_without_a_transcript_the_first_edit_is_denied_and_the_retry_passes(project):
    payload = edit(project, "src/payments/charge.py")
    assert run(payload).returncode == 2
    proc = run(payload)
    assert proc.returncode == 0 and "no transcript" in note_of(proc)


def test_without_a_session_id_there_is_no_memory(project, transcript, tmp_path):
    payload = edit(
        project, "src/payments/charge.py", transcript_path=transcript([human()]), session=""
    )
    assert run(payload).returncode == 2
    assert run(payload).returncode == 2  # nothing remembered: still the first denial
    assert not (tmp_path / "plugin-data" / "facts").exists()
    records = [human(), tool_use("g1", "Grep", {"pattern": "charge"}), result("g1")]
    payload["transcript_path"] = transcript(records)
    assert run(payload).returncode == 0


def test_two_prompt_ids_in_a_window_without_a_start_give_no_credit(project, transcript):
    records = [
        tool_use("g1", "Grep", {"pattern": "charge"}),
        result("g1", prompt="p1"),
        result("g2", prompt="p2"),
    ]
    assert (
        run(edit(project, "src/payments/charge.py", transcript_path=transcript(records))).returncode
        == 2
    )


def test_a_large_transcript_is_read_from_its_tail(project, transcript):
    filler = [human("x" * 1000, prompt="old")] * 600  # ~600 KiB before the current turn
    records = filler + [human(), tool_use("g1", "Grep", {"pattern": "charge"}), result("g1")]
    assert (
        run(edit(project, "src/payments/charge.py", transcript_path=transcript(records))).returncode
        == 0
    )


def test_a_stale_state_file_is_forgotten(project, transcript, tmp_path):
    payload = edit(project, "src/payments/charge.py", transcript_path=transcript([human()]))
    assert run(payload).returncode == 2
    path = state_path(tmp_path)
    state = json.loads(path.read_text(encoding="utf-8"))
    state["last_active"] = time.time() - fg.IDLE_SECONDS - 60
    path.write_text(json.dumps(state), encoding="utf-8")
    proc = run(payload)
    err = proc.stderr.decode("utf-8")
    assert proc.returncode == 2 and err.count("  - ") == 4  # full text: the first denial again
    state = json.loads(path.read_text(encoding="utf-8"))
    assert state["denials"] == {"src/payments/charge.py": 1}


def test_a_damaged_state_file_is_forgotten(project, transcript, tmp_path):
    path = state_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text('{"checked": "nope", "denials": []}', encoding="utf-8")
    payload = edit(project, "src/payments/charge.py", transcript_path=transcript([human()]))
    assert run(payload).returncode == 2
    path.write_text("{garbage", encoding="utf-8")
    assert run(payload).returncode == 2


def test_session_id_with_path_characters_is_sanitised(project, transcript, tmp_path):
    payload = edit(
        project,
        "src/payments/charge.py",
        transcript_path=transcript([human()]),
        session="../../evil",
    )
    assert run(payload).returncode == 2
    assert not (tmp_path / "evil.json").exists()
    assert list((tmp_path / "plugin-data" / "facts").glob("*.json")) == [
        tmp_path / "plugin-data" / "facts" / "evil.json"
    ]


def test_a_nul_in_cwd_does_not_crash(project, transcript):
    payload = edit(project, "src/payments/charge.py", transcript_path=transcript([human()]))
    payload["cwd"] = "D:\\x\x00y"
    proc = run(payload)
    assert proc.returncode in (0, 2) and b"Traceback" not in proc.stderr


def test_a_broken_transcript_line_in_the_turn_is_skipped(project, transcript):
    path = transcript([human(), tool_use("g1", "Grep", {"pattern": "charge"}), result("g1")])
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("{broken\n")
    assert run(edit(project, "src/payments/charge.py", transcript_path=path)).returncode == 0


def test_log_records_the_verdict_when_asked(project, transcript, tmp_path):
    payload = edit(project, "src/payments/charge.py", transcript_path=transcript([human()]))
    run(payload, env={"PREFLIGHT_LOG": "1"})
    log = (tmp_path / "plugin-data" / "log" / "facts.jsonl").read_text(encoding="utf-8")
    assert '"verdict": "deny"' in log and "charge.py" in log


def test_old_session_files_are_pruned(project, transcript, tmp_path):
    folder = tmp_path / "plugin-data" / "facts"
    folder.mkdir(parents=True)
    old = folder / "ancient.json"
    old.write_text("{}", encoding="utf-8")
    stale = time.time() - fg.KEEP_SECONDS - 60
    os.utime(old, (stale, stale))
    run(edit(project, "src/payments/charge.py", transcript_path=transcript([human()])))
    assert not old.exists()


def test_decide_does_not_read_state_for_a_plain_file(project, monkeypatch):
    def boom(session):
        raise AssertionError("state read for an ordinary file")

    monkeypatch.setattr(fg, "load_state", boom)
    payload = edit(project, "src/plain/x.py")
    assert fg.decide(payload, "Edit", payload["tool_input"], SESSION) == (fg.PASS, None)


def test_session_file_helper_rejects_empty_names():
    assert c.session_file("facts", "") is None


# --- what the mutation run found uncovered -------------------------------------


@pytest.mark.parametrize(
    ("path", "new", "phrases"),
    [
        (
            "src/payments/charge.py",
            "x",
            ["importers and callers", "currency and rounding", "pins the current numbers"],
        ),
        (
            "app/auth/login.py",
            "x",
            ["importers and callers", "adds, removes or bypasses", "unhappy path (search"],
        ),
        (
            "db/migrations/0042.py",
            "op.add_column('orders', c)",
            ["touches orders", "changed column", "rollback"],
        ),
        ("pyproject.toml", "x", ["weakens or changes", "currently fails it", "not fixed instead"]),
    ],
)
def test_each_class_asks_its_four_facts(project, transcript, path, new, phrases):
    proc = run(edit(project, path, new=new, transcript_path=transcript([human()])))
    err = proc.stderr.decode("utf-8")
    assert err.count("  - ") == 4 and "instruction verbatim" in err
    assert all(p in err for p in phrases), err
    assert "Reading the file does not count" in err


def test_odd_edit_inputs_do_not_crash_the_gate(project, transcript):
    payload = edit(project, "src/payments/charge.py", transcript_path=transcript([human()]))
    payload["tool_input"]["new_string"] = ["not", "a", "string"]
    assert run(payload).returncode == 2
    del payload["tool_input"]["new_string"]
    assert run(payload).returncode == 2
    payload["tool_input"] = {"file_path": str(project / "Makefile"), "new_string": None}
    assert run(payload).returncode == 0


def test_pruning_keeps_fresh_session_files(project, transcript, tmp_path):
    folder = tmp_path / "plugin-data" / "facts"
    folder.mkdir(parents=True)
    old, fresh_file = folder / "ancient.json", folder / "fresh.json"
    old.write_text("{}", encoding="utf-8")
    fresh_file.write_text("{}", encoding="utf-8")
    stale = time.time() - fg.KEEP_SECONDS - 60
    os.utime(old, (stale, stale))
    run(edit(project, "src/payments/charge.py", transcript_path=transcript([human()])))
    assert not old.exists() and fresh_file.exists()


def test_cap_from_the_environment_is_trimmed(project, transcript):
    payload = edit(project, "src/payments/charge.py", transcript_path=transcript([human()]))
    assert run(payload, env={"PREFLIGHT_FACTS_MAX_DENIALS": " 1 "}).returncode == 2
    assert run(payload, env={"PREFLIGHT_FACTS_MAX_DENIALS": " 1 "}).returncode == 0


def test_a_missing_transcript_file_counts_as_no_transcript(project, tmp_path):
    payload = edit(project, "src/payments/charge.py", transcript_path=str(tmp_path / "gone.jsonl"))
    assert run(payload).returncode == 2
    proc = run(payload)
    assert proc.returncode == 0 and "no transcript" in note_of(proc)
