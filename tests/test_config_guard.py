from __future__ import annotations

import os

import pytest

import config_formats as cf
import config_guard as cg
import fact_classes as fc
from conftest import run_guard

PYPROJECT = '[project]\nname = "x"\n\n[tool.ruff.lint]\nselect = ["E", "F"]\nignore = ["E501"]\n'
WORKFLOW = "jobs:\n  t:\n    steps:\n      - run: pytest -q\n"
PRECOMMIT = "repos:\n  - repo: local\n    hooks:\n      - id: mypy\n        entry: mypy\n"


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proj"
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src").mkdir()
    (root / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (root / ".github/workflows/ci.yml").write_text(WORKFLOW, encoding="utf-8")
    (root / ".pre-commit-config.yaml").write_text(PRECOMMIT, encoding="utf-8")
    (root / "tests/conftest.py").write_text("import pytest\n", encoding="utf-8")
    (root / "setup.cfg").write_text("[flake8]\nextend-ignore = E203\n", encoding="utf-8")
    (root / "src/app.py").write_text("x = 1\n", encoding="utf-8")
    return root


def edit(project, path, old, new, tool="Edit", **extra):
    tool_input = {"file_path": str(project / path), "old_string": old, "new_string": new, **extra}
    return {"cwd": str(project), "tool_name": tool, "tool_input": tool_input}


def write(project, path, content):
    return {
        "cwd": str(project),
        "tool_name": "Write",
        "tool_input": {"file_path": str(project / path), "content": content},
    }


def run(payload, env=None):
    return run_guard("config_guard", payload, env=env)


def blocked(proc) -> str:
    assert proc.returncode == 2 and proc.stdout == b"", proc.stderr
    return proc.stderr.decode("utf-8")


def passed(proc) -> None:
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")


WEAKEN = 'ignore = ["E501", "F401"]'


def test_a_weakening_edit_is_blocked_with_the_recipe(project):
    err = blocked(run(edit(project, "pyproject.toml", 'ignore = ["E501"]', WEAKEN)))
    assert err.startswith("preflight config: this edit weakens a check (pyproject.toml)")
    assert "  - tool.ruff.lint.ignore: adds F401" in err
    assert err.rstrip().endswith(cg.HINT)
    assert "Fix the code the check fails on" in err and "PREFLIGHT_CONFIG=0" in err


def test_tightening_passes_silently(project):
    passed(run(edit(project, "pyproject.toml", 'select = ["E", "F"]', 'select = ["E", "F", "B"]')))


def test_unrelated_edit_of_a_config_passes(project):
    passed(run(edit(project, "pyproject.toml", 'name = "x"', 'name = "y"')))


def test_a_new_config_file_passes(project):
    passed(run(write(project, "ruff.toml", 'ignore = ["E501"]\n')))


def test_writing_an_existing_config_is_compared_with_the_disk(project):
    blocked(run(write(project, "pyproject.toml", PYPROJECT.replace('ignore = ["E501"]', WEAKEN))))
    passed(run(write(project, "pyproject.toml", PYPROJECT)))


def test_multiedit_applies_the_edits_in_order(project):
    edits = [
        {"old_string": 'name = "x"', "new_string": 'name = "y"'},
        {"old_string": 'ignore = ["E501"]', "new_string": WEAKEN},
    ]
    payload = edit(project, "pyproject.toml", "", "", tool="MultiEdit")
    payload["tool_input"] = {"file_path": str(project / "pyproject.toml"), "edits": edits}
    assert "adds F401" in blocked(run(payload))
    edits[1]["old_string"] = "not in the file"
    passed(run(payload))


def test_replace_all_reaches_the_second_occurrence(project):
    text = '[tool.hatch.build]\nonly-include = ["E501"]\n[tool.ruff.lint]\nignore = ["E501"]\n'
    (project / "pyproject.toml").write_text(text, encoding="utf-8")
    passed(run(edit(project, "pyproject.toml", '"E501"]', '"E501", "F401"]')))
    blocked(run(edit(project, "pyproject.toml", '"E501"]', '"E501", "F401"]', replace_all=True)))


def test_an_edit_that_does_not_apply_passes(project):
    passed(run(edit(project, "pyproject.toml", "absent text", WEAKEN)))


def test_an_edit_that_breaks_the_toml_is_blocked(project):
    """Breaking the file first would let the next edit weaken it unseen (security review)."""
    err = blocked(
        run(edit(project, "pyproject.toml", 'ignore = ["E501"]', 'ignore = ["E501", "F401"'))
    )
    assert "leaves the file unparsable" in err


def test_a_file_that_was_already_broken_passes(project):
    (project / "pyproject.toml").write_text(PYPROJECT + "junk =\n", encoding="utf-8")
    passed(run(edit(project, "pyproject.toml", 'ignore = ["E501"]', WEAKEN)))


@pytest.mark.parametrize("env", [{"PREFLIGHT": "0"}, {"PREFLIGHT_CONFIG": "0"}])
def test_off_switches(project, env):
    passed(run(edit(project, "pyproject.toml", 'ignore = ["E501"]', WEAKEN), env=env))


@pytest.mark.parametrize("globs", ["pyproject.toml", "*.toml;x", " ./nothing ; PYPROJECT.TOML "])
def test_exempt_globs(project, globs):
    proc = run(
        edit(project, "pyproject.toml", 'ignore = ["E501"]', WEAKEN),
        env={"PREFLIGHT_CONFIG_EXEMPT": globs},
    )
    passed(proc)  # by path or by name, any case, any of the `;`-separated globs


def test_the_facts_exemption_does_not_exempt_this_guard(project):
    proc = run(
        edit(project, "pyproject.toml", 'ignore = ["E501"]', WEAKEN),
        env={"PREFLIGHT_FACTS_EXEMPT": "pyproject.toml"},
    )
    blocked(proc)


def test_conftest_under_tests_is_guarded(project):
    err = blocked(
        run(
            edit(
                project,
                "tests/conftest.py",
                "import pytest\n",
                "import pytest\ncollect_ignore = ['x']\n",
            )
        )
    )
    assert "conftest: adds collect_ignore" in err


def test_workflow_and_precommit_are_guarded(project):
    err = blocked(run(edit(project, ".github/workflows/ci.yml", "pytest -q", "pytest -q || true")))
    assert "steps: adds || true" in err
    err = blocked(
        run(edit(project, ".pre-commit-config.yaml", "      - id: mypy\n        entry: mypy\n", ""))
    )
    assert "hooks: removes hook mypy" in err and "hooks: mypy no longer runs" in err


def test_setup_cfg_is_guarded(project):
    assert "flake8.extend-ignore: adds W503" in blocked(
        run(edit(project, "setup.cfg", "E203", "E203, W503"))
    )


def test_ordinary_files_and_other_tools_pass(project):
    passed(run(edit(project, "src/app.py", "x = 1", "x = 2")))
    payload = edit(project, "pyproject.toml", 'ignore = ["E501"]', WEAKEN, tool="NotebookEdit")
    passed(run(payload))
    passed(run({"cwd": str(project), "tool_name": "Edit", "tool_input": {"file_path": 5}}))


def test_crlf_file_with_lf_anchor(project):
    (project / "pyproject.toml").write_bytes(PYPROJECT.replace("\n", "\r\n").encode("utf-8"))
    blocked(
        run(
            edit(
                project,
                "pyproject.toml",
                'select = ["E", "F"]\nignore = ["E501"]',
                'select = ["E", "F"]\nignore = ["E501", "X1"]',
            )
        )
    )


def test_a_byte_order_mark_does_not_hide_the_file(project):
    """Windows PowerShell 5.1 writes `Set-Content -Encoding utf8` with a BOM; the live run
    showed the TOML reader refusing such a file and the weakening going through."""
    (project / "pyproject.toml").write_bytes(b"\xef\xbb\xbf" + PYPROJECT.encode("utf-8"))
    blocked(run(edit(project, "pyproject.toml", 'ignore = ["E501"]', WEAKEN)))
    blocked(
        run(
            write(
                project, "pyproject.toml", cg.BOM + PYPROJECT.replace('ignore = ["E501"]', WEAKEN)
            )
        )
    )


def test_a_result_of_exactly_the_limit_is_judged(monkeypatch):
    monkeypatch.setattr(cg, "MAX_BYTES", 4)
    assert cg.edited("x", "Write", {"content": "abcd"}) == "abcd"
    assert cg.edited("ab", "Edit", {"old_string": "b", "new_string": "bcd"}) == "abcd"


def test_an_oversized_result_is_refused_before_it_is_built():
    with pytest.raises(cg.Oversize):
        cg.edited("a", "Write", {"content": "x" * (cg.MAX_BYTES + 1)})
    with pytest.raises(cg.Oversize):
        cg.edited("a", "Edit", {"old_string": "a", "new_string": "y" * (cg.MAX_BYTES + 1)})
    huge = {"old_string": "\n", "new_string": "x" * 4096, "replace_all": True}
    with pytest.raises(cg.Oversize):  # 100k lines times 4 KB would be 400 MB
        cg.edited("\n" * 100_000, "Edit", huge)


def test_a_worktree_mirror_is_judged_like_the_project(project):
    wt = project / ".claude" / "worktrees" / "w"
    (wt / ".git").mkdir(parents=True)
    (wt / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    blocked(run(edit(project, ".claude/worktrees/w/pyproject.toml", 'ignore = ["E501"]', WEAKEN)))


def test_the_log_names_rules_not_values(project, tmp_path):
    run(edit(project, "pyproject.toml", 'ignore = ["E501"]', WEAKEN), env={"PREFLIGHT_LOG": "1"})
    log = (tmp_path / "plugin-data" / "log" / "config.jsonl").read_text(encoding="utf-8")
    assert '"rules": ["ignore"]' in log and "F401" not in log


def test_a_nul_in_cwd_does_not_crash(project):
    payload = edit(project, "pyproject.toml", 'ignore = ["E501"]', WEAKEN)
    payload["cwd"] = "D:\\x\x00y"
    proc = run(payload)
    assert proc.returncode in (0, 2) and b"Traceback" not in proc.stderr
    payload["tool_input"]["file_path"] = "pyproject.toml"  # relative: joined to the broken cwd
    proc = run(payload)
    assert proc.returncode == 0 and b"Traceback" not in proc.stderr


# --- in process: what the guard never touches -------------------------------------


def test_a_network_path_is_never_opened(project, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("a network path was opened")

    monkeypatch.setattr(cg.os, "stat", boom)
    monkeypatch.setattr(cg, "open", boom, raising=False)
    for path in ("\\\\attacker\\share\\pyproject.toml", "//attacker/share/pyproject.toml"):
        payload = {
            "cwd": str(project),
            "tool_name": "Edit",
            "tool_input": {"file_path": path, "old_string": "a", "new_string": "b"},
        }
        assert cg.decide(payload, "Edit", payload["tool_input"])[0] == []


def test_an_ordinary_file_is_not_read(project, monkeypatch):
    monkeypatch.setattr(cg, "read_text", lambda path: (_ for _ in ()).throw(AssertionError(path)))
    payload = edit(project, "src/app.py", "x = 1", "x = 2")
    assert cg.decide(payload, "Edit", payload["tool_input"]) == ([], "src/app.py")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX")
def test_a_fifo_is_not_opened(project):
    """Opening a FIFO blocks until a writer comes: the hook would hang to its timeout."""
    os.remove(project / "pyproject.toml")
    os.mkfifo(project / "pyproject.toml")
    assert cg.read_text(project / "pyproject.toml") is None


def test_big_files_directories_and_missing_files_are_not_read(project, monkeypatch):
    monkeypatch.setattr(cg, "MAX_BYTES", 10)
    with pytest.raises(cg.Oversize):
        cg.read_text(project / "pyproject.toml")
    monkeypatch.setattr(cg, "MAX_BYTES", 1 << 20)
    assert cg.read_text(project / "pyproject.toml") == PYPROJECT
    (project / "dir.toml").mkdir()
    assert cg.read_text(project / "dir.toml") is None
    assert cg.read_text(project / "gone.toml") is None


def test_in_process_the_quiet_paths_return_instead_of_raising(project):
    """In a hook process a crash also lets the edit through, so only a direct call shows
    that each early exit is a decision and not an exception caught by `_common.run`."""
    assert cg.judge("pyproject.toml", "junk =\n", PYPROJECT) == []
    assert cg.judge("pyproject.toml", PYPROJECT, "junk =\n") == [
        "pyproject.toml: the edit leaves the file unparsable, and the checks would stop reading it"
    ]
    missing = edit(project, "ruff.toml", "a", "b")
    assert cg.decide(missing, "Edit", missing["tool_input"]) == ([], "ruff.toml")
    absent = edit(project, "pyproject.toml", "not in the file", WEAKEN)
    assert cg.decide(absent, "Edit", absent["tool_input"]) == ([], "pyproject.toml")
    same = write(project, "pyproject.toml", PYPROJECT)
    assert cg.decide(same, "Write", same["tool_input"]) == ([], "pyproject.toml")


def test_edited_refuses_odd_inputs():
    assert cg.edited("a", "MultiEdit", {}) is None
    assert cg.edited("a", "Edit", {"old_string": "a", "new_string": None}) is None
    assert cg.edited("a", "Edit", {"old_string": None, "new_string": "b"}) is None
    first_misses = [{"old_string": "zz", "new_string": "q"}, {"old_string": "a", "new_string": "c"}]
    assert cg.edited("ab", "MultiEdit", {"edits": first_misses}) is None
    assert cg.edited("a", "Write", {"content": None}) is None
    assert cg.edited("a", "MultiEdit", {"edits": "x"}) is None
    assert cg.edited("a", "MultiEdit", {"edits": ["x"]}) is None
    assert cg.edited("a", "Edit", {"old_string": "", "new_string": "b"}) is None
    assert cg.edited("aa", "Edit", {"old_string": "a", "new_string": "b"}) == "ba"
    assert (
        cg.edited("aa", "Edit", {"old_string": "a", "new_string": "b", "replace_all": True}) == "bb"
    )
    assert cg.edited("x\n", "Write", {"content": "y\r\nz"}) == "y\nz"


@pytest.mark.parametrize(
    ("rel", "kind"),
    [
        ("pyproject.toml", "pyproject.toml"),
        ("sub/setup.cfg", "setup.cfg"),
        ("tests/conftest.py", "conftest"),
        (".pre-commit-config.yml", "precommit"),
        (".github/workflows/ci.yaml", "workflow"),
        ("pkg/.github/workflows/ci.yml", "workflow"),
        (".github/workflows/readme.md", ""),
        ("workflows/ci.yml", ""),
        (".eslintrc.json", ""),
        ("Makefile", ""),
    ],
)
def test_kind_of(rel, kind):
    assert cg.kind_of(rel) == kind


def test_every_guarded_name_is_a_check_configuration_for_the_facts_gate():
    assert set(cf.FORMATS) | {"conftest.py"} | cg.PRECOMMIT <= fc.CONFIG_NAMES
