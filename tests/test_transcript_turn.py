from __future__ import annotations

import json

import pytest

import search_credit as sc
import transcript_turn as tt

# --- transcript records, as Claude Code writes them ---------------------------


def human(text="do it", prompt="p1", **extra):
    return {
        "type": "user",
        "promptId": prompt,
        "message": {"role": "user", "content": text},
        **extra,
    }


def tool_use(call_id, name, tool_input, msg="m1"):
    block = {"type": "tool_use", "id": call_id, "name": name, "input": tool_input}
    return {"type": "assistant", "message": {"id": msg, "role": "assistant", "content": [block]}}


def result(call_id, content="ok", prompt="p1", error=None):
    block = {"type": "tool_result", "tool_use_id": call_id, "content": content}
    if error is not None:
        block["is_error"] = error
    return {"type": "user", "promptId": prompt, "message": {"role": "user", "content": [block]}}


def write(path, records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return str(path)


GREP = {"pattern": "charge", "path": "src"}


# --- tail reading --------------------------------------------------------------


def test_tail_reads_whole_small_file(tmp_path):
    path = write(tmp_path / "t.jsonl", [human(), tool_use("a", "Grep", GREP), result("a")])
    assert [r["type"] for r in tt.tail_records(path)] == ["user", "assistant", "user"]


def test_tail_drops_the_fragment_line_and_bad_json(tmp_path, monkeypatch):
    records = [human("x" * 300), human("second"), tool_use("a", "Grep", GREP), result("a")]
    path = tmp_path / "t.jsonl"
    write(path, records)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{not json\n")
    # The window starts inside the first, long record: that fragment is dropped.
    monkeypatch.setattr(tt, "TAIL_BYTES", path.stat().st_size - 50)
    got = tt.tail_records(str(path))
    assert [r["type"] for r in got] == ["user", "assistant", "user"]
    assert got[0]["message"]["content"] == "second"


def test_tail_window_is_bounded(tmp_path):
    """A transcript of a few megabytes is read from its tail only."""
    path = write(tmp_path / "t.jsonl", [human("x" * 1000) for _ in range(2000)])
    assert path and (tmp_path / "t.jsonl").stat().st_size > 4 * tt.TAIL_BYTES
    got = tt.tail_records(path)
    assert 0 < len(got) <= tt.TAIL_BYTES // 1000 + 1


def test_tail_caps_the_number_of_lines(tmp_path, monkeypatch):
    monkeypatch.setattr(tt, "MAX_LINES", 3)
    path = write(tmp_path / "t.jsonl", [human(str(i)) for i in range(10)])
    assert [r["message"]["content"] for r in tt.tail_records(path)] == ["7", "8", "9"]


def test_tail_of_a_missing_or_unreadable_file_is_empty(tmp_path):
    assert tt.tail_records(str(tmp_path / "missing.jsonl")) == []
    assert tt.tail_records("") == []


def test_tail_survives_a_half_written_last_line(tmp_path):
    path = tmp_path / "t.jsonl"
    path.write_text(json.dumps(human()) + "\n" + '{"type": "assist', encoding="utf-8")
    assert len(tt.tail_records(str(path))) == 1


# --- the current turn ----------------------------------------------------------


def test_turn_starts_at_the_latest_human_message():
    records = [
        human("old"),
        tool_use("a", "Grep", GREP),
        result("a"),
        human("new"),
        tool_use("b", "Read", {}),
    ]
    turn = tt.current_turn(records)
    assert turn is not None and turn[0]["message"]["content"] == "new" and len(turn) == 2


@pytest.mark.parametrize(
    "record",
    [
        result("a"),
        {**human(), "isMeta": True},
        {**human(), "isSidechain": True},
        {"type": "system", "subtype": "stop_hook_summary"},
        {"type": "assistant", "message": {"content": []}},
    ],
)
def test_these_records_never_start_a_turn(record):
    assert tt.starts_turn(record) is False


def test_pasted_text_blocks_start_a_turn():
    rec = {"type": "user", "message": {"content": [{"type": "text", "text": "hi"}]}}
    assert tt.starts_turn(rec) is True


def test_compaction_starts_a_turn():
    assert tt.starts_turn({"type": "system", "subtype": "compact_boundary"}) is True
    assert tt.starts_turn({**human("summary"), "isCompactSummary": True}) is True


def test_window_without_a_start_is_the_turn_only_with_one_prompt_id():
    one = [tool_use("a", "Grep", GREP), result("a", prompt="p1"), result("b", prompt="p1")]
    assert tt.current_turn(one) == one
    two = [tool_use("a", "Grep", GREP), result("a", prompt="p1"), result("b", prompt="p2")]
    assert tt.current_turn(two) is None
    assert tt.current_turn([tool_use("a", "Grep", GREP)]) is None


# --- completed calls -----------------------------------------------------------


def test_completed_calls_need_a_clean_result():
    turn = [
        human(),
        tool_use("a", "Grep", GREP),
        tool_use("b", "Grep", GREP),
        tool_use("c", "Grep", GREP),
        tool_use("d", "Grep", GREP),
        result("a"),
        result("b", error=True),
        result("c", content="<tool_use_error>boom"),
    ]
    assert [c.id for c in tt.completed_calls(turn)] == ["a"]


def test_a_call_id_seen_twice_is_never_trusted():
    turn = [human(), tool_use("a", "Grep", GREP), result("a"), result("a")]
    assert tt.completed_calls(turn) == []
    turn = [human(), tool_use("a", "Grep", GREP), tool_use("a", "Grep", GREP), result("a")]
    assert tt.completed_calls(turn) == []


def test_result_content_as_blocks_is_read_for_the_error_marker():
    turn = [
        human(),
        tool_use("a", "Grep", GREP),
        result("a", content=[{"type": "text", "text": "<tool_use_error>x"}]),
    ]
    assert tt.completed_calls(turn) == []


def test_calls_carry_their_assistant_message_id():
    turn = [human(), tool_use("a", "Grep", GREP, msg="m7"), result("a")]
    call = tt.completed_calls(turn)[0]
    assert (call.name, call.batch, call.input) == ("Grep", "m7", GREP)
    assert tt.batch_of(turn, "a") == "m7" and tt.batch_of(turn, "zzz") == ""


def test_request_id_is_the_batch_when_the_message_has_no_id():
    rec = {
        "type": "assistant",
        "requestId": "req9",
        "message": {"content": [{"type": "tool_use", "id": "a", "name": "Grep", "input": GREP}]},
    }
    assert tt.completed_calls([human(), rec, result("a")])[0].batch == "req9"


def test_sidechain_calls_are_ignored():
    rec = {**tool_use("a", "Grep", GREP), "isSidechain": True}
    assert tt.completed_calls([human(), rec, result("a")]) == []


# --- what counts as a search ---------------------------------------------------


def test_grep_tool_search():
    (search,) = sc.searches("Grep", {"pattern": "charge", "glob": "*.py,!legacy/*", "type": "py"})
    assert search.text == "charge" and search.restrict == ["*.py", "*.py"]
    assert search.exclude == ["legacy/*"] and search.lookup is False


def test_grep_confined_to_one_name_is_a_lookup():
    (search,) = sc.searches("Grep", {"pattern": "x", "glob": "charge.py"})
    assert search.lookup is True


def test_glob_tool_search():
    assert sc.searches("Glob", {"pattern": "**/charge.*"})[0].lookup is False
    assert sc.searches("Glob", {"pattern": "**/charge.py"})[0].lookup is True
    assert sc.searches("Glob", {"pattern": "src/charge.py"})[0].lookup is True


def test_read_and_other_tools_are_not_searches():
    assert sc.searches("Read", {"file_path": "charge.py"}) == []
    assert sc.searches("Edit", {"file_path": "charge.py", "old_string": "charge"}) == []
    assert sc.searches("WebSearch", {"query": "charge"}) == []


@pytest.mark.parametrize(
    ("command", "labels"),
    [
        ("rg charge src", ["rg"]),
        ("grep -rn charge .", ["grep"]),
        ("git grep charge", ["git grep"]),
        ("git ls-files | grep charge", ["git ls-files", "grep"]),  # the listing feeds the grep
        ("find . -name 'charge*'", ["find"]),
        ("fd charge src", ["fd"]),
        ("cat x.py", []),
        ("ls src", []),
        ("cat f | grep charge", []),
        ("grep charge < f", []),
        ("cat f | grep charge src", ["grep"]),
        ("rg charge src && grep -r pay lib", ["rg", "grep"]),
        ("rg $(echo charge) src", []),
        ("rg `cat p` src", []),
        ("rg charge <<EOF\nx\nEOF", []),
        ("sudo rg charge src", ["rg"]),
    ],
)
def test_shell_searches(command, labels):
    assert [
        s.label.split(" ")[0]
        + (" grep" if "git grep" in s.label else " ls-files" if "ls-files" in s.label else "")
        for s in sc.shell_searches(command, False)
    ] == labels


def test_powershell_search():
    (search,) = sc.shell_searches("Select-String -Pattern charge -Path src -Include *.py", True)
    assert search.restrict == ["*.py"] and "charge" in search.text
    assert sc.shell_searches("sls charge src\\*.py", True)[0].restrict == []


def test_very_long_commands_are_not_read():
    assert sc.shell_searches("rg charge " + "x" * sc.MAX_COMMAND, False) == []


@pytest.mark.parametrize(
    ("command", "restrict", "exclude"),
    [
        ("rg -g '*.py' charge .", ["*.py"], []),
        ("rg --glob=!*.md charge .", [], ["*.md"]),
        ("rg -t py charge .", ["*.py"], []),
        ("rg -T js charge .", [], ["*.js"]),
        ("grep -r --include='*.py' --exclude-dir=build charge .", ["*.py"], ["build"]),
        ("fd -e py charge", ["*.py"], []),
        ("fd -E legacy charge", [], ["legacy"]),
        ("find . -name '*.py' -newer x", ["*.py"], []),
        ("git grep charge -- . ':!vendor'", [], ["vendor"]),
        ("rg -e charge src", [], []),
    ],
)
def test_shell_restrictions_and_exclusions(command, restrict, exclude):
    (search,) = sc.shell_searches(command, False)
    assert (search.restrict, search.exclude) == (restrict, exclude)


def test_grep_dash_e_is_the_pattern_not_an_extension():
    (search,) = sc.shell_searches("grep -e charge src", False)
    assert search.restrict == [] and sc.credits(search, ["charge"], "charge.py")


# --- does a search credit a file? ---------------------------------------------


def search(text, restrict=(), exclude=(), lookup=False):
    return sc.Search("x", text, list(restrict), list(exclude), lookup)


@pytest.mark.parametrize(
    ("text", "word", "expected"),
    [
        ("charge", "charge", True),
        ("payment_service", "payment", True),
        ("payments", "payment", False),
        ("Charge\\b", "charge", True),
        ("(charge|refund)", "charge", True),
        ("x", "", False),
        ("0042_add_orders", "0042_add_orders", True),
    ],
)
def test_mentions_whole_words(text, word, expected):
    assert sc.mentions(text, word) is expected


def test_credits_by_stem_or_symbol():
    assert sc.credits(search("def charge"), ["charge"], "charge.py")
    assert sc.credits(search("OrderItem"), ["", "OrderItem"], "models.py")
    assert not sc.credits(search("models"), [""], "models.py")


def test_restrictions_must_match_the_file_name():
    assert sc.credits(search("charge", restrict=["*.py"]), ["charge"], "charge.py")
    assert not sc.credits(search("charge", restrict=["*.js"]), ["charge"], "charge.py")
    assert sc.credits(search("charge", restrict=["*.js", "*.py"]), ["charge"], "charge.py")


def test_exclusions_block_the_credit():
    assert not sc.credits(search("TODO", exclude=["charge.py"]), ["charge"], "charge.py")
    assert not sc.credits(search("TODO", exclude=["*.py"]), ["charge"], "charge.py")
    assert not sc.credits(search("charge", exclude=["charge"]), ["charge"], "charge.py")
    assert sc.credits(search("charge", exclude=["*.md"]), ["charge"], "charge.py")


def test_a_lookup_never_credits():
    assert not sc.credits(search("charge", lookup=True), ["charge"], "charge.py")


def test_crediting_label_skips_the_edit_batch_and_names_the_search():
    calls = [
        tt.Call("a", "Grep", {"pattern": "charge"}, "m1"),
        tt.Call("b", "Bash", {"command": "rg charge src"}, "m2"),
    ]
    assert sc.crediting_label(calls, ["charge"], "src/charge.py", "m1") == "rg 'charge src'"
    assert sc.crediting_label(calls, ["charge"], "src/charge.py", "") == "Grep 'charge'"
    assert sc.crediting_label(calls, ["other"], "src/charge.py", "") == ""
    assert sc.crediting_label(calls, [""], "src/models.py", "") == ""


# --- what the mutation run found uncovered -------------------------------------


def test_grep_globs_are_trimmed():
    (s,) = sc.searches("Grep", {"pattern": "x", "glob": " *.py , !legacy/* "})
    assert (s.restrict, s.exclude) == (["*.py"], ["legacy/*"])


def test_a_lookup_needs_every_restriction_to_name_one_file():
    assert sc.searches("Grep", {"pattern": "x", "glob": "charge.py,*.py"})[0].lookup is False


def test_powershell_keeps_backslashes_and_bash_eats_them():
    assert sc.searches("PowerShell", {"command": r"rg charge C:\src"})[0].text == r"charge C:\src"
    assert sc.searches("Bash", {"command": r"rg charge C:\src"})[0].text == "charge C:src"


@pytest.mark.parametrize(
    ("command", "labels"),
    [
        ("rg 'charge src", []),  # unclosed quote: not parsed
        ("> out.txt && rg charge src", ["rg"]),  # a stage with no words
        ("RG charge src", ["rg"]),
        ("git GREP charge", ["git grep"]),
        ("cat grep", []),
        ("git", []),
        ("git log charge", []),
        ("cat f | rg -g '*.py' charge", []),  # the glob value is not a path operand
    ],
)
def test_shell_searches_edge_cases(command, labels):
    got = [s.label.split("'")[0].strip() for s in sc.shell_searches(command, False)]
    assert got == labels


@pytest.mark.parametrize(
    ("text", "word", "expected"),
    [
        ("a - b", "", False),
        ("payment2", "payment", False),
        ("v2_payment", "payment", True),
    ],
)
def test_mentions_edge_cases(text, word, expected):
    assert sc.mentions(text, word) is expected


def test_credit_is_case_insensitive_on_names_and_globs():
    assert sc.credits(search("charge", restrict=["*.PY"]), ["charge"], "Charge.py")
    assert not sc.credits(search("TODO", exclude=["CHARGE.py"]), ["charge"], "charge.py")
    assert not sc.credits(search("charge", exclude=["charge"]), ["charge", ""], "charge.py")


def test_tail_skips_json_that_is_not_a_record(tmp_path):
    path = tmp_path / "t.jsonl"
    path.write_text('[1, 2]\n"text"\n42\n' + json.dumps(human()) + "\n", encoding="utf-8")
    assert [r["type"] for r in tt.tail_records(str(path))] == ["user"]


def test_records_without_a_message_are_harmless():
    assert tt.starts_turn({"type": "user"}) is False
    assert tt.starts_turn({"type": "user", "message": {"content": {"odd": 1}}}) is False
    assert (
        tt.completed_calls(
            [{"type": "user"}, {"type": "assistant"}, {"type": "user", "message": {}}]
        )
        == []
    )
    assert tt.batch_of([{"type": "assistant"}], "a") == ""


def test_a_sidechain_result_does_not_complete_a_call():
    side = {**result("a"), "isSidechain": True}
    assert tt.completed_calls([human(), tool_use("a", "Grep", GREP), side]) == []


def test_a_call_with_a_non_dict_input_is_ignored():
    rec = {
        "type": "assistant",
        "message": {
            "id": "m",
            "content": [{"type": "tool_use", "id": "a", "name": "Grep", "input": "x"}],
        },
    }
    assert tt.completed_calls([human(), rec, result("a")]) == []


@pytest.mark.parametrize("error", ["true", "True", True])
def test_error_flags_in_any_spelling(error):
    assert (
        tt.completed_calls([human(), tool_use("a", "Grep", GREP), result("a", error=error)]) == []
    )
    assert (
        tt.completed_calls([human(), tool_use("a", "Grep", GREP), result("a", error=False)]) != []
    )
