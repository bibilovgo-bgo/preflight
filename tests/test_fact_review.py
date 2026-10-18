"""Regression tests for the code review of the facts stage, one group per finding."""

from __future__ import annotations

import json
import os

import pytest
from test_fact_gate import SESSION, edit, human, note_of, result, run, state_path, tool_use

import fact_classes as fc
import fact_gate as fg
import search_credit as sc
import transcript_turn as tt


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proj"
    for folder in ("src/payments", "app/auth", "app/schemas", "models", "src/plain"):
        (root / folder).mkdir(parents=True)
    (root / "src/payments/charge.py").write_text("def charge(): pass\n", encoding="utf-8")
    return root


@pytest.fixture
def transcript(tmp_path):
    def write(records):
        path = tmp_path / "transcript.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
        return str(path)

    return write


# --- the old text of an edit counts as much as the new ------------------------


def test_removing_an_auth_check_is_an_auth_edit(project, transcript):
    payload = edit(
        project, "src/plain/views.py", new="def export():", transcript_path=transcript([human()])
    )
    payload["tool_input"]["old_string"] = "@login_required\ndef export():"
    proc = run(payload)
    assert proc.returncode == 2 and "auth path" in proc.stderr.decode("utf-8")


def test_removing_a_column_is_a_schema_edit(project):
    text = fg.edit_text({"old_string": "op.drop_column('orders', 'x')", "new_string": "# gone"})
    assert fc.classify("src/plain/step.py", text, project, []).cls == "schema"


def test_multiedit_texts_are_read(project):
    tool_input = {
        "file_path": "x.py",
        "edits": [{"old_string": "a", "new_string": "check_password(u, p)"}, "junk"],
    }
    assert "check_password" in fg.edit_text(tool_input)


# --- a generic stem without a symbol is credited by its folder ----------------


def test_folder_name_credits_a_generic_stem_without_a_symbol(project, transcript):
    target = fc.classify("app/auth/models.py", "x = 1", project, [])
    assert (target.stem, target.symbol, target.parent) == ("", "", "auth")
    assert fg.credit_words(target) == ["", "", "", "auth"]
    records = [
        human(),
        tool_use("g1", "Grep", {"pattern": "auth"}),
        result("g1"),
        tool_use(
            "edit1", "Edit", {}, msg="m-edit"
        ),  # the gated call's own message, as Claude Code writes it
    ]
    proc = run(
        edit(project, "app/auth/models.py", new="x = 1", transcript_path=transcript(records))
    )
    assert proc.returncode == 0 and "credited" in note_of(proc)


def test_symbol_from_the_old_text_is_used(project):
    text = fg.edit_text(
        {"old_string": "class Token(Base):\n    ttl = 1", "new_string": "    ttl = 2"}
    )
    assert fc.classify("app/auth/models.py", text, project, []).symbol == "Token"


def test_questions_name_the_file_when_nothing_else_names_it(project):
    target = fc.classify("app/auth/models.py", "x = 1", project, [])
    assert "who calls app/auth/models.py" in fg.questions(target, condensed=False)[0]


# --- Grep globs with braces ------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("*.{ts,tsx}", ["*.ts", "*.tsx"]),
        ("*.py,!legacy/*", ["*.py", "!legacy/*"]),
        ("src/{a,b}/*.py, *.md", ["src/a/*.py", "src/b/*.py", "*.md"]),
        ("", []),
    ],
)
def test_grep_globs_keep_brace_commas(raw, expected):
    assert sc._globs(raw) == expected


def test_brace_glob_credits_a_tsx_file():
    (search,) = sc.searches("Grep", {"pattern": "charge", "glob": "*.{ts,tsx}"})
    assert sc.credits(search, ["charge"], "charge.tsx")


# --- concurrent hook processes merge their memory ------------------------------


def test_save_merges_with_what_another_process_wrote(tmp_path):
    first = fg.fresh()
    first["denials"]["a.py"] = 1
    fg.save_state(SESSION, first)
    other = fg.fresh()  # loaded before `first` was saved, by another process
    other["denials"]["b.py"] = 1
    other["checked"].append("c.py")
    fg.save_state(SESSION, other)
    state = json.loads(state_path(tmp_path).read_text(encoding="utf-8"))
    assert state["denials"] == {"a.py": 1, "b.py": 1} and state["checked"] == ["c.py"]


def test_merge_keeps_the_higher_denial_count():
    assert fg.merged(SESSION, {"checked": [], "denials": {"a.py": 2}})["denials"] == {"a.py": 2}


# --- schemas/ and models/ need database talk; money needs two signals -------------


@pytest.mark.parametrize(
    ("path", "text", "expected"),
    [
        ("app/schemas/user.py", "class User(BaseModel):\n    name: str", ""),
        ("app/schemas/user.py", "class User(Base):\n    id = Column(Integer)", "schema"),
        ("models/resnet.py", "def forward(self, x):", ""),
        ("models/order.py", "class Order(models.Model):", "schema"),
        ("db/migrations/0001.py", "", "schema"),
    ],
)
def test_soft_schema_folders(project, path, text, expected):
    assert fc.classify(path, text, project, []).cls == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("average = total / count", ""),
        ("progress += 1  # total steps", ""),
        ("total = price * qty", "money"),
        ("amount = Decimal(raw)", "money"),
        ("price = 10  # usd", "money"),
        ("fee = round(x, 2)", "money"),
        ("label = f'{total} $'", "money"),
    ],
)
def test_money_by_content_needs_two_signals(project, text, expected):
    assert fc.classify("src/plain/x.py", text, project, []).cls == expected


# --- same-batch exclusion without a tool_use_id ---------------------------------


def test_newest_assistant_message_is_the_batch_when_the_id_is_unknown(project, transcript):
    records = [human(), tool_use("g1", "Grep", {"pattern": "charge"}, msg="m-last"), result("g1")]
    payload = edit(project, "src/payments/charge.py", transcript_path=transcript(records))
    del payload["tool_use_id"]
    assert run(payload).returncode == 2
    assert tt.last_batch(records) == "m-last" and tt.last_batch([human()]) == ""


def test_an_earlier_message_still_credits_without_an_id(project, transcript):
    records = [
        human(),
        tool_use("g1", "Grep", {"pattern": "charge"}, msg="m1"),
        result("g1"),
        tool_use("r1", "Read", {}, msg="m2"),
        result("r1"),
    ]
    payload = edit(project, "src/payments/charge.py", transcript_path=transcript(records))
    del payload["tool_use_id"]
    assert run(payload).returncode == 0


# --- git global options and wrappers ----------------------------------------------


@pytest.mark.parametrize(
    ("command", "labels"),
    [
        ("git -C src grep charge", ["git grep"]),
        ("git -c core.quotepath=off grep charge", ["git grep"]),
        ("bash -c 'rg charge src'", ["rg"]),
        ("bash -c 'bash -c \"rg charge src\"'", ["rg"]),
        ("gci -r *.py | sls charge", ["sls"]),
        ("find . -name '*.py' | grep charge", ["find", "grep"]),
        ("cat list.txt | grep charge", []),
    ],
)
def test_wrapped_and_piped_searches(command, labels):
    powershell = command.startswith("gci")
    got = [s.label.split("'")[0].strip() for s in sc.shell_searches(command, powershell)]
    assert got == labels


def test_wrapper_depth_is_capped():
    nested = "rg charge src"
    for _ in range(sc.MAX_DEPTH + 1):
        nested = f"bash -c '{nested.replace(chr(39), chr(34))}'"
    assert sc.shell_searches(nested, False) == []


# --- glued short options -------------------------------------------------------------


def test_glued_short_option_keeps_the_restriction():
    (search,) = sc.shell_searches("rg -g*.js charge .", False)
    assert search.restrict == ["*.js"] and not sc.credits(search, ["charge"], "charge.py")
    (search,) = sc.shell_searches("rg -tpy charge .", False)
    assert search.restrict == ["*.py"]


# --- test files of other languages, Windows-only path cleaning ------------------------


@pytest.mark.parametrize(
    "path", ["pkg/payments/charge_test.go", "lib/billing/charge_spec.rb", "src/auth/login_test.ts"]
)
def test_other_languages_tests_are_exempt(project, path):
    assert fc.classify(path, "", project, []).cls == ""


@pytest.mark.skipif(os.name == "nt", reason="POSIX names may end in a dot")
def test_posix_paths_keep_trailing_dots(project):
    assert fc.classify("src/payments./x.py", "", project, []).rel == "src/payments./x.py"
    assert fc.classify("src/payments./x.py", "", project, []).cls == ""


def test_windows_style_paths_are_cleaned_everywhere(project):
    assert fc._clean("src\\payments.\\x.py::$DATA") == "src/payments/x.py"


# --- the new-config note is remembered; a NUL in the path does not crash ----------------


def test_new_config_note_is_given_once(project, transcript):
    payload = edit(
        project, "ruff.toml", tool="Write", new="[lint]\n", transcript_path=transcript([human()])
    )
    first = run(payload)
    assert first.returncode == 0 and "nothing to weaken" in note_of(first)
    second = run(payload)
    assert (second.returncode, second.stdout) == (0, b"")


def test_nul_in_the_target_path_does_not_crash(project, transcript):
    payload = edit(
        project, "ruff.toml", tool="Write", new="[lint]\n", transcript_path=transcript([human()])
    )
    payload["tool_input"]["file_path"] = str(project / "ruff\x00.toml")
    proc = run(payload)
    assert proc.returncode in (0, 2) and b"Traceback" not in proc.stderr


# --- hooks.json wires MultiEdit too ----------------------------------------------------


def test_multiedit_is_in_the_matcher():
    from conftest import ROOT

    config = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    matchers = [g["matcher"] for g in config["hooks"]["PreToolUse"]]
    assert "Edit|Write|MultiEdit|NotebookEdit" in matchers


# --- security review: a network path is never stat'ed (Windows would send the NTLM hash) ---


@pytest.mark.parametrize(
    "path",
    [
        "//attacker/share/x/foo.py",
        "\\\\attacker\\share\\x\\pyproject.toml",
        "//attacker/share/payments/charge.py",
        "smb://attacker/share/x.py",
    ],
)
def test_network_paths_are_never_touched(project, monkeypatch, path):
    def boom(*args, **kwargs):
        raise AssertionError("filesystem call on a network path")

    monkeypatch.setattr(fc.Path, "exists", boom)
    monkeypatch.setattr(fc.os.path, "realpath", boom)
    assert fc.classify(path, "x = 1", project, []).cls == ""


def test_network_path_write_passes_silently(project, transcript):
    payload = edit(
        project, "x", tool="Write", new="[lint]\n", transcript_path=transcript([human()])
    )
    payload["tool_input"]["file_path"] = "\\\\attacker\\share\\pyproject.toml"
    proc = run(payload)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")


def test_a_project_on_a_network_share_is_left_alone(monkeypatch):
    monkeypatch.setattr(
        fc.Path, "exists", lambda self: (_ for _ in ()).throw(AssertionError("stat"))
    )
    root = fc.Path("//server/projects/app")
    assert fc.classify("src/payments/charge.py", "", root, []).cls == ""


def test_exists_helper_refuses_network_paths():
    assert fg._exists(fc.Path("//attacker/share/ruff.toml")) is True


# --- third mutation round --------------------------------------------------------------


def test_money_words_are_counted_without_case(project):
    assert fc.classify("src/plain/x.py", "total = Total * 2", project, []).cls == ""


def test_folder_name_is_not_a_credit_word_when_the_stem_names_the_file(project):
    target = fc.classify("src/payments/charge.py", "x = 1", project, [])
    assert fg.credit_words(target) == ["charge", "", ""]
    target = fc.classify("app/auth/models.py", "def login(): pass", project, [])
    assert fg.credit_words(target) == ["", "login", ""]


def test_writing_over_an_existing_check_config_is_denied(project, transcript):
    (project / "pyproject.toml").write_text("[tool.ruff]\n", encoding="utf-8")
    payload = edit(
        project,
        "pyproject.toml",
        tool="Write",
        new="[tool.ruff]\nignore = ['E501']\n",
        transcript_path=transcript([human()]),
    )
    assert run(payload).returncode == 2


def test_wrapper_depth_cap_is_exact():
    def nested(levels):
        command = "rg charge src"
        for _ in range(levels):
            command = f"bash -c '{command.replace(chr(39), chr(34))}'"
        return command

    assert sc.shell_searches(nested(sc.MAX_DEPTH - 1), False) != []
    assert sc.shell_searches(nested(sc.MAX_DEPTH), False) == []


def test_git_listing_subcommand_is_read_like_the_search_one():
    got = [
        s.label.split("'")[0].strip()
        for s in sc.shell_searches("git LS-FILES | grep charge", False)
    ]
    assert got == ["git ls-files", "grep"]
