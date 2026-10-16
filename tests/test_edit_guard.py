from __future__ import annotations

import pytest

import edit_guard as eg
from conftest import run_guard

SOURCE = (
    "def alpha():\n    return 1\n\n\ndef beta():\n    return 2\n\n\ndef gamma():\n    return 2\n"
)


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text(SOURCE, encoding="utf-8")
    return str(path)


def edit(path, old, new="x", **extra):
    return {"file_path": path, "old_string": old, "new_string": new, **extra}


def test_unique_anchor_passes(sample):
    assert eg.check_edit(edit(sample, "def alpha():\n    return 1\n")) == []


def test_missing_anchor_blocks_and_shows_closest_line(sample):
    problems = eg.check_edit(edit(sample, "def alpah():\n    return 1\n"))
    assert len(problems) == 1
    assert "not in the file" in problems[0]
    assert "Closest line in the file: 'def alpha():'" in problems[0]


def test_missing_anchor_without_similar_line_has_no_hint(sample):
    problems = eg.check_edit(edit(sample, "completely unrelated text"))
    assert problems and "Closest line" not in problems[0]


def test_ambiguous_anchor_blocks(sample):
    problems = eg.check_edit(edit(sample, "    return 2\n"))
    assert len(problems) == 1
    assert "occurs 2 times" in problems[0]


def test_ambiguous_anchor_with_replace_all_passes(sample):
    assert eg.check_edit(edit(sample, "    return 2\n", replace_all=True)) == []


def test_identical_strings_block_without_reading_the_file(tmp_path):
    missing = str(tmp_path / "nope.py")
    problems = eg.check_edit(edit(missing, "same", "same"))
    assert problems and "identical" in problems[0]


def test_bypass_marker_passes(sample):
    assert eg.check_edit(edit(sample, "not there", "y  #edit-ok")) == []


def test_missing_file_passes(tmp_path):
    assert eg.check_edit(edit(str(tmp_path / "nope.py"), "a", "b")) == []


def test_binary_file_passes(tmp_path):
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\xff\xfe\x00garbage")
    assert eg.check_edit(edit(str(path), "a", "b")) == []


def test_crlf_file_matches_lf_anchor(tmp_path):
    path = tmp_path / "crlf.py"
    path.write_bytes(b"line one\r\nline two\r\n")
    assert eg.check_edit(edit(str(path), "line one\nline two\n")) == []


def test_crlf_anchor_matches_crlf_file(tmp_path):
    path = tmp_path / "crlf.py"
    path.write_bytes(b"line one\r\nline two\r\n")
    assert eg.check_edit(edit(str(path), "line one\r\nline two\r\n")) == []


@pytest.mark.parametrize("payload", [{}, {"file_path": "x"}, {"file_path": "x", "old_string": ""}])
def test_incomplete_input_passes(payload):
    assert eg.check_edit(payload) == []


def test_nearest_line_ignores_blank_anchor():
    assert eg.nearest_line("a\nb\n", "\n   \n") == ""


def test_nearest_line_uses_first_non_blank_line():
    assert eg.nearest_line("def alpha():\n", "\n\ndef alpah():\nzzz") == "def alpha():"


def test_nearest_line_ignores_indentation_on_both_sides():
    text = "class A:\n        return compute(alpha)\n"
    anchor = " " * 40 + "return compute(alpah)"
    assert eg.nearest_line(text, anchor) == "return compute(alpha)"


def test_long_hint_is_truncated(tmp_path):
    path = tmp_path / "long.py"
    line = "value = " + "x" * 300
    path.write_text(line + "\n", encoding="utf-8")
    problems = eg.check_edit(edit(str(path), "value = " + "x" * 299 + "y"))
    assert repr(line[:120]) in problems[0]
    assert repr(line[:121]) not in problems[0]


def test_empty_path_passes_even_for_identical_strings():
    assert eg.check_edit({"file_path": "", "old_string": "a", "new_string": "a"}) == []


def test_process_lets_a_good_edit_through(sample):
    payload = {"tool_name": "Edit", "tool_input": edit(sample, "def alpha():\n")}
    done = run_guard("edit_guard", payload)
    assert done.returncode == 0
    assert done.stderr == b""


def test_process_log_records_file_and_short_problems(sample, tmp_path):
    import json

    data = tmp_path / "data"
    payload = {"tool_name": "Edit", "tool_input": edit(sample, "    return 2\n")}
    run_guard("edit_guard", payload, env={"PREFLIGHT_LOG": "1", "CLAUDE_PLUGIN_DATA": str(data)})
    record = json.loads((data / "log" / "edit.jsonl").read_text(encoding="utf-8"))
    assert record["file"] == "sample.py"
    assert [len(p) for p in record["problems"]] == [80]


def test_process_blocks_with_exit_2(sample):
    done = run_guard(
        "edit_guard", {"tool_name": "Edit", "tool_input": edit(sample, "    return 2\n")}
    )
    assert done.returncode == 2
    assert "preflight/edit" in done.stderr.decode("utf-8")


def test_process_ignores_other_tools(sample):
    done = run_guard(
        "edit_guard", {"tool_name": "Write", "tool_input": edit(sample, "    return 2\n")}
    )
    assert done.returncode == 0


@pytest.mark.parametrize("switch", ["PREFLIGHT", "PREFLIGHT_EDIT"])
def test_off_switch(sample, switch):
    payload = {"tool_name": "Edit", "tool_input": edit(sample, "    return 2\n")}
    assert run_guard("edit_guard", payload, env={switch: "0"}).returncode == 0


def test_garbage_stdin_passes():
    import subprocess
    import sys

    from conftest import GUARDS

    done = subprocess.run(
        [sys.executable, str(GUARDS / "edit_guard.py")],
        input=b"not json",
        capture_output=True,
        timeout=60,
    )
    assert done.returncode == 0


def test_curly_quotes_in_the_file_match_straight_quotes_in_the_anchor(tmp_path):
    path = tmp_path / "q.md"
    path.write_text(
        "say " + chr(0x201C) + "hello" + chr(0x201D) + " and " + chr(0x2019) + "bye\n",
        encoding="utf-8",
    )
    assert eg.check_edit(edit(str(path), 'say "hello" and \'bye')) == []


def test_closest_line_hint_on_a_huge_file_is_fast(tmp_path):
    import time

    path = tmp_path / "big.py"
    path.write_text(
        "".join(f"value_{i} = compute(alpha, {i})\n" for i in range(200_000)), encoding="utf-8"
    )
    started = time.perf_counter()
    problems = eg.check_edit(edit(str(path), "value_17 = compute(alpah, 17)"))
    assert time.perf_counter() - started < 5
    assert problems and "Closest line" in problems[0]
