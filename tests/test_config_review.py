"""Regression tests for the findings of the code review of the config guard (18.10.2026).

Each test is named after what the review showed: a legitimate edit that was blocked, or a
weakening the README promises to catch that went through.
"""

from __future__ import annotations

import json

import pytest

import config_formats as cf
import config_rules as cr
import config_text as ct
import toml_lite as tl
from conftest import ROOT

tomllib = pytest.importorskip("tomllib")


def toml(before: str, after: str, name: str = "pyproject.toml") -> list:
    return cr.weakened(cf.parse(name, before), cf.parse(name, after))


# --- false blocks: a key that moves, splits or gets renamed is the same setting ------------


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (
            '[tool.ruff]\nselect = ["E", "F"]\nignore = ["E501"]\n',
            '[tool.ruff.lint]\nselect = ["E", "F"]\nignore = ["E501"]\n',
        ),
        (
            '[tool.ruff.per-file-ignores]\n"tests/*" = ["S101"]\n',
            '[tool.ruff.lint.per-file-ignores]\n"tests/*" = ["S101"]\n',
        ),
        (
            '[tool.ruff.lint]\nextend-ignore = ["E501"]\n',
            '[tool.ruff.lint]\nextend_ignore = ["E501"]\n',
        ),
        ('[tool.ruff.lint]\nignore = ["E501"]\n', '[tool.ruff.lint]\nextend-ignore = ["E501"]\n'),
        (
            '[tool.ruff.lint]\nselect = ["E", "F"]\n',
            '[tool.ruff.lint]\nextend-select = ["E", "F"]\n',
        ),
    ],
)
def test_the_ruff_lint_migration_and_key_renames_pass(before, after):
    assert toml(before, after) == []


def test_moving_a_ruff_key_does_not_hide_a_new_code():
    before = '[tool.ruff]\nignore = ["E501"]\n'
    after = '[tool.ruff.lint]\nignore = ["E501", "F401"]\n'
    assert toml(before, after) == ["tool.ruff.lint.ignore: adds F401"]


OVERRIDE = "[[tool.mypy.overrides]]\nmodule = {}\nignore_missing_imports = true\n"


@pytest.mark.parametrize(
    ("before", "after"),
    [('["a", "b"]', '["b", "a"]'), ('"a"', '["a"]'), ('["a", "b"]', '["a"]')],
)
def test_editing_the_module_list_of_a_mypy_override_does_not_rename_it(before, after):
    assert toml(OVERRIDE.format(before), OVERRIDE.format(after)) == []


def test_a_module_added_to_a_lax_override_is_a_weakening():
    found = toml(OVERRIDE.format('["a"]'), OVERRIDE.format('["a", "b"]'))
    assert found == ["tool.mypy.overrides.b.ignore_missing_imports: unset -> True"]


@pytest.mark.parametrize(
    ("before", "after"),
    [('["E", "F"]', '["ALL"]'), ('["E501", "F"]', '["E", "F"]')],
)
def test_a_wider_select_code_covers_the_narrow_one(before, after):
    assert (
        toml(f"[tool.ruff.lint]\nselect = {before}\n", f"[tool.ruff.lint]\nselect = {after}\n")
        == []
    )


def test_an_ignore_already_covered_by_a_prefix_adds_nothing():
    assert (
        toml('[tool.ruff.lint]\nignore = ["E"]\n', '[tool.ruff.lint]\nignore = ["E", "E501"]\n')
        == []
    )


def test_a_filter_narrowed_to_one_module_is_not_a_new_ignore():
    before = '[tool.pytest.ini_options]\nfilterwarnings = ["ignore::DeprecationWarning"]\n'
    after = '[tool.pytest.ini_options]\nfilterwarnings = ["ignore::DeprecationWarning:foo"]\n'
    assert toml(before, after) == []


def test_tox_commands_moved_to_another_environment_pass():
    before = '[testenv]\ncommands = pytest -m "not slow"\n'
    after = '[testenv]\ndeps = pytest\n[testenv:py]\ncommands = pytest -m "not slow"\n'
    assert toml(before, after, "tox.ini") == []


def test_pylint_reports_is_not_a_pyright_rule():
    assert (
        toml("[tool.pylint.reports]\nreports = true\n", "[tool.pylint.reports]\nreports = false\n")
        == []
    )


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("basic", []), ("strict", ["pyright.reportmissingtypestubs: unset -> none"])],
)
def test_a_report_rule_set_to_its_default_is_judged_by_the_mode(mode, expected):
    before = json.dumps({"typeCheckingMode": mode})
    after = json.dumps({"typeCheckingMode": mode, "reportMissingTypeStubs": "none"})
    assert toml(before, after, "pyrightconfig.json") == expected


# --- false blocks in workflows and hooks ------------------------------------------------

STEP = "jobs:\n  t:\n    steps:\n      - run: {}\n"


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("pytest -q", "pip install -e . && pytest -q"),
        ("npm test", "npm install && npm test"),
        ("rsync -a ./ out/", "rsync -a --exclude=.git ./ out/"),
        ("tar czf a.tgz .", "tar czf a.tgz --exclude=.git ."),
        ("rm -rf build", "rm -rf build || true"),
    ],
)
def test_installs_and_non_check_commands_are_not_weakenings(before, after):
    assert ct.line_findings("workflow", STEP.format(before), STEP.format(after)) == []


def test_an_exclude_on_a_check_command_still_counts():
    found = ct.line_findings(
        "workflow", STEP.format("ruff check ."), STEP.format("ruff check --exclude=src .")
    )
    assert found == ["steps: adds --exclude=src"]


def test_disabling_the_cache_plugin_is_harmless_and_coverage_is_not():
    before = '[tool.pytest.ini_options]\naddopts = "-q"\n'
    assert toml(before, before.replace('"-q"', '"-q -p no:cacheprovider"')) == []
    assert toml(before, before.replace('"-q"', '"-q -p no:cov"')) == [
        "tool.pytest.ini_options.addopts: adds -p no:cov"
    ]


def test_a_new_job_with_a_marker_adds_a_check():
    after = (
        STEP.format("pytest -q")
        + "  integration:\n    steps:\n      - run: pytest -m integration\n"
    )
    assert ct.line_findings("workflow", STEP.format("pytest -q"), after) == []


def test_a_marker_put_on_the_existing_run_narrows_it():
    found = ct.line_findings("workflow", STEP.format("pytest -q"), STEP.format("pytest -q -m fast"))
    assert found == ["steps: adds -m fast"]


def test_a_hook_renamed_around_its_stem_is_not_removed():
    before = "repos:\n  - repo: local\n    hooks:\n      - id: lint\n        entry: ruff check\n"
    assert ct.line_findings("precommit", before, before.replace("id: lint", "id: ruff-lint")) == []


# --- missed weakenings ------------------------------------------------------------------


def test_a_pytest_option_on_a_continuation_line_counts():
    before = (
        "jobs:\n  t:\n    steps:\n      - run: |\n          pytest -q \\\n            --tb=short\n"
    )
    after = before.replace("--tb=short", "-k fast")
    assert ct.line_findings("workflow", before, after) == ["steps: adds -k fast"]


@pytest.mark.parametrize(
    "after",
    [
        "[flake8]\nper-file-ignores =\n    tests/*: S101,\n        S106\n",
        "[flake8]\nper-file-ignores =\n    tests/*: S101\n    src/*:\n        E501\n",
    ],
)
def test_flake8_per_file_codes_on_continuation_lines_count(after):
    before = "[flake8]\nper-file-ignores =\n    tests/*: S101\n"
    assert len(toml(before, after, "setup.cfg")) == 1


@pytest.mark.parametrize(
    "doc",
    ["t = 07:32:00\n", "t = 1979-05-27 07:32:00\n", "t = 1979-05-27T07:32:00Z\n"],
)
def test_toml_times_parse_as_text(doc):
    expected = {"t": str(tomllib.loads(doc)["t"]).replace("+00:00", "Z")}
    data = tl.TomlReader(doc).document()
    assert data["t"].replace("T", " ") == expected["t"].replace("T", " ")


# --- third mutation round: what the fixes left unguarded ---------------------------------


@pytest.mark.parametrize(
    ("before", "after", "name"),
    [
        (
            '[tool.ruff.lint.per-file-ignores]\n"t/*" = ["S1"]\n',
            '[tool.ruff.lint.extend-per-file-ignores]\n"t/*" = ["S1"]\n',
            "pyproject.toml",
        ),
        (
            '[tool.ruff]\nexclude = ["a"]\n',
            '[tool.ruff]\nextend-exclude = ["a"]\n',
            "pyproject.toml",
        ),
        ('[tool.isort]\nskip = ["a"]\n', '[tool.isort]\nextend_skip = ["a"]\n', "pyproject.toml"),
        (
            '[tool.isort]\nskip_glob = ["a*"]\n',
            '[tool.isort]\nextend_skip_glob = ["a*"]\n',
            "pyproject.toml",
        ),
        (
            "[testenv]\ncommands = pytest -k x\n",
            "[testenv]\ncommands_pre = pytest -k x\n",
            "tox.ini",
        ),
        (
            "[testenv]\ncommands = pytest -k x\n",
            "[testenv]\ncommands_post = pytest -k x\n",
            "tox.ini",
        ),
        ("[coverage:run]\nomit = a/*\n", "[coverage:report]\nomit = a/*\n", "setup.cfg"),
        (
            '[tool.ruff]\nexclude = ["tests/"]\n',
            '[tool.ruff]\nexclude = ["tests/", "tests/unit"]\n',
            "pyproject.toml",
        ),
    ],
)
def test_each_spelling_of_one_setting_is_one_pool(before, after, name):
    assert toml(before, after, name) == []


@pytest.mark.parametrize(
    ("before", "after", "name"),
    [
        (
            '[tool.ruff.lint]\nignore = ["D100"]\n',
            '[tool.pydocstyle]\nignore = ["D100"]\n',
            "pyproject.toml",
        ),
        ("[flake8]\nignore = E501\n", "[pycodestyle]\nignore = E501\n", "setup.cfg"),
    ],
)
def test_two_tools_never_share_a_pool(before, after, name):
    assert len(toml(before, after, name)) == 1


def test_none_is_below_information():
    path = ("pyright", "reportx")
    found = cr.weakened(
        {("pyright", "typecheckingmode"): "basic", path: "information"},
        {("pyright", "typecheckingmode"): "basic", path: "none"},
    )
    assert found == ["pyright.reportx: information -> none"]


def test_an_empty_block_comment_ends_where_it_ends():
    assert cf.read_json('{/**/"a": 1}') == {"a": 1}


def test_no_verify_counts_anywhere():
    before = "jobs:\n  t:\n    steps:\n      - run: git commit -m x\n"
    after = before.replace("-m x", "-m x --no-verify")
    assert ct.line_findings("workflow", before, after) == ["steps: adds --no-verify"]


def test_a_continuation_without_a_space_before_the_backslash():
    before = "jobs:\n  t:\n    steps:\n      - run: |\n          pytest\\\n            -q\n"
    after = before.replace("-q", "-k x")
    assert ct.line_findings("workflow", before, after) == ["steps: adds -k x"]


def test_a_comment_at_the_start_of_a_line_is_dropped():
    before = "jobs:\n  t:\n    steps:\n      - run: pytest\n"
    assert ct.line_findings("workflow", before, before + "#pytest -q || true\n") == []


def test_running_pytest_as_a_module_is_not_a_marker():
    before = "jobs:\n  t:\n    steps:\n      - run: pytest -q\n"
    after = before.replace("pytest -q", "python -m pytest -q")
    assert ct.line_findings("workflow", before, after) == []


def test_a_repo_url_is_not_a_tool_run():
    before = (
        "repos:\n  - repo: https://github.com/pytest-dev/pytest\n    rev: v1\n"
        "    hooks:\n      - id: custom-check\n"
    )
    after = before.replace("pytest-dev/pytest", "acme/hooks")
    assert ct.line_findings("precommit", before, after) == []


def test_the_config_guard_does_not_start_for_notebook_edits():
    hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    matchers = [
        group["matcher"]
        for group in hooks["hooks"]["PreToolUse"]
        if any("config_guard" in h["command"] for h in group["hooks"])
    ]
    assert matchers == ["Edit|Write|MultiEdit"]
