from __future__ import annotations

import time

import pytest

import config_formats as cf
import config_rules as cr
import config_text as ct

PYPROJECT = """[project]
name = "x"
dependencies = ["requests"]

[tool.mypy]
strict = true
warn_unreachable = true

[tool.ruff]
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "B"]
ignore = ["E501"]

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S101"]

[tool.ruff.lint.mccabe]
max-complexity = 10

[tool.pytest.ini_options]
addopts = "-q --strict-markers"
testpaths = ["tests"]
filterwarnings = ["error"]
xfail_strict = true

[tool.coverage.report]
fail_under = 90

[tool.coverage.run]
branch = true

[tool.pyright]
typeCheckingMode = "strict"
reportMissingImports = "error"

[tool.setuptools.packages.find]
exclude = ["tests"]
"""


def findings(old: str, new: str, text: str = PYPROJECT) -> list:
    assert old in text, old
    before = cf.parse("pyproject.toml", text)
    after = cf.parse("pyproject.toml", text.replace(old, new, 1))
    return cr.weakened(before, after)


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ('ignore = ["E501"]', 'ignore = ["E501", "F401"]', "lint.ignore: adds F401"),
        ('ignore = ["E501"]', 'ignore = ["E741"]', "lint.ignore: adds E741"),
        ('select = ["E", "F", "B"]', 'select = ["E", "F"]', "lint.select: drops B"),
        ('select = ["E", "F", "B"]\n', "", "lint.select: removed"),
        ("line-length = 100", "line-length = 120", "line-length: 100 -> 120"),
        (
            "line-length = 100\n",
            "line-length = 100\n[tool.black]\nline-length = 99\n",
            "default 88 -> 99",
        ),
        ("max-complexity = 10", "max-complexity = 25", "max-complexity: 10 -> 25"),
        ('"tests/*" = ["S101"]', '"tests/*" = ["S101", "ANN"]', "adds tests/*:ANN"),
        ('"tests/*" = ["S101"]', '"tests/*" = ["S101"]\n"src/*" = ["E"]', "adds src/*:E"),
        ("--strict-markers", "--strict-markers -p no:cov", "addopts: adds -p no:cov"),
        (
            'reportMissingImports = "error"',
            'reportMissingImports = "error"\nreportPrivateUsage = "warning"',
            "reportprivateusage: unset -> warning",  # strict mode: every report rule is an error
        ),
        ("-q --strict-markers", "-q", "addopts: drops --strict-markers"),
        ("--strict-markers", "--strict-markers -k 'not slow'", "adds -k 'not slow'"),
        (
            "--strict-markers",
            "--strict-markers --deselect tests/a.py::t",
            "adds --deselect tests/a.py::t",
        ),
        ("--strict-markers", "--strict-markers --cov-fail-under=0", ""),
        ('testpaths = ["tests"]', 'testpaths = ["tests/unit"]', "testpaths: drops tests"),
        (
            'filterwarnings = ["error"]',
            'filterwarnings = ["error", "ignore::UserWarning"]',
            "adds ignore::UserWarning",
        ),
        ('filterwarnings = ["error"]', "filterwarnings = []", "filterwarnings: drops error"),
        ("xfail_strict = true", "xfail_strict = false", "xfail_strict: True -> False"),
        ("strict = true", "strict = false", "mypy.strict: True -> False"),
        ("strict = true\n", "", "mypy.strict: True -> unset"),
        ("warn_unreachable = true", "warn_unreachable = false", "warn_unreachable: True -> False"),
        (
            "strict = true\n",
            "strict = true\nignore_missing_imports = true\n",
            "ignore_missing_imports: unset -> True",
        ),
        (
            "strict = true\n",
            "strict = true\nstrict_optional = false\n",
            "strict_optional: unset -> False",
        ),
        ("fail_under = 90", "fail_under = 80", "fail_under: 90 -> 80"),
        ("fail_under = 90\n", "", "fail_under: 90 -> unset"),
        ("branch = true", "branch = false", "branch: True -> False"),
        ('typeCheckingMode = "strict"', 'typeCheckingMode = "basic"', "strict -> basic"),
        ('typeCheckingMode = "strict"\n', "", "strict -> unset"),
        ('reportMissingImports = "error"', 'reportMissingImports = "warning"', "error -> warning"),
        (
            'reportMissingImports = "error"',
            'reportMissingImports = "error"\nreportPrivateUsage = false',
            "unset -> False",
        ),
        (
            'reportMissingImports = "error"',
            'reportMissingImports = "error"\nreportPrivateUsage = "none"',
            "reportprivateusage: unset -> none",
        ),
        ('typeCheckingMode = "strict"', 'typeCheckingMode = "off"', "strict -> off"),
        ("strict = true\n", 'strict = true\nfollow_imports = "skip"\n', "unset -> skip"),
        ("line-length = 100\n", "", ""),  # back to ruff's default of 88: tighter
    ],
)
def test_weakening_is_found(old, new, expected):
    found = findings(old, new)
    if expected:
        assert any(expected in f for f in found), found
    else:
        assert found == [], found  # a coverage floor raised from nothing is not weaker


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('select = ["E", "F", "B"]', 'select = ["E", "F", "B", "UP"]'),
        ('ignore = ["E501"]', "ignore = []"),
        ('ignore = ["E501"]\n', ""),
        ("line-length = 100", "line-length = 88"),
        ("fail_under = 90", "fail_under = 95"),
        (
            'reportMissingImports = "error"\n',
            'reportMissingImports = "error"\nreportPrivateUsage = "error"\n',
        ),
        ('testpaths = ["tests"]', 'testpaths = ["tests", "integration"]'),
        ('testpaths = ["tests"]\n', ""),
        ('exclude = ["tests"]', 'exclude = ["tests", "docs"]'),
        ('name = "x"', 'name = "y"'),
        ('dependencies = ["requests"]', 'dependencies = ["requests", "httpx"]'),
        ("strict = true\n", "strict = true\nstrict_optional = true\n"),
        ("strict = true\n", "strict = true\nwarn_return_any = true\n"),
        ("-q --strict-markers", "-q --strict-markers --runxfail"),
        ('filterwarnings = ["error"]', 'filterwarnings = ["error", "default::DeprecationWarning"]'),
        ("strict = true\n", "strict = true\nignore_missing_imports = false\n"),
        ('typeCheckingMode = "strict"', 'typeCheckingMode = "Strict!"'),  # unknown: not judged
        ('testpaths = ["tests"]', 'testpaths = ["tests"]\nminversion = "8.0"'),
        (
            "max-complexity = 10\n",
            "max-complexity = 10\n[tool.ruff.lint.pylint]\nmax-statements = 100\n",
        ),
        ('exclude = ["tests"]', 'exclude = ["tests"]\n[tool.coverage.html]\ndirectory = "tox/"'),
    ],
)
def test_tightening_and_unrelated_edits_find_nothing(old, new):
    assert findings(old, new) == []


@pytest.mark.parametrize(
    ("key", "old", "new"),
    [("typecheckingmode", "basic", "off"), ("follow_imports", "silent", "skip")],
)
def test_each_step_down_a_rank_counts(key, old, new):
    path = ("tool", "x", key)
    assert cr.weakened({path: old}, {path: new}) == [f"tool.x.{key}: {old} -> {new}"]
    assert cr.weakened({path: new}, {path: old}) == []


def test_a_rank_seen_in_both_states_with_one_unknown_is_not_judged():
    flat = {("tool", "pyright", "typecheckingmode"): "strict"}
    assert cr.weakened(flat, {("tool", "pyright", "typecheckingmode"): "weird"}) == []
    assert cr.weakened({("tool", "pyright", "typecheckingmode"): "weird"}, flat) == []


def test_a_precommit_config_mentioning_itself_is_not_a_tool_that_stopped():
    before = "ci:\n  autofix_commit_msg: '[pre-commit.ci] fixes'\n" + PRECOMMIT
    assert ct.line_findings("precommit", before, PRECOMMIT) == []


def test_pyright_strict_paths_are_a_list_not_a_flag():
    path = ("pyright", "strict")
    assert cr.weakened({path: ["src", "lib"]}, {path: ["src"]}) == ["pyright.strict: drops lib"]
    assert cr.weakened({path: ["src"]}, {path: ["src", "lib"]}) == []


def test_minversion_and_other_numbers_are_not_limits():
    old = {("tool", "pytest", "ini_options", "minversion"): "7.0"}
    assert cr.weakened(old, {("tool", "pytest", "ini_options", "minversion"): "8.0"}) == []
    old = {("tool", "coverage", "report", "precision"): 1}
    assert cr.weakened(old, {("tool", "coverage", "report", "precision"): 3}) == []


def test_a_new_ruff_line_length_just_above_the_default():
    before = cf.parse("ruff.toml", "[lint]\nselect = ['E']\n")
    after = cf.parse("ruff.toml", "line-length = 89\n[lint]\nselect = ['E']\n")
    assert cr.weakened(before, after) == ["tool.ruff.line-length: default 88 -> 89"]


def test_tox_commands_without_pytest_carry_no_pytest_options():
    before = cf.parse("tox.ini", "[testenv]\ncommands =\n    mypy -m alpha\n    ruff check\n")
    after = cf.parse("tox.ini", "[testenv]\ncommands =\n    mypy -m beta\n    ruff check\n")
    assert cr.weakened(before, after) == []


def test_only_command_values_can_stop_a_tool():
    before = {("tool", "coverage", "run", "omit"): ["tox/*", "build/*"]}
    after = {("tool", "coverage", "run", "omit"): ["build/*"]}
    assert cr.weakened(before, after) == []


def test_a_default_true_flag_set_explicitly_and_then_unset_is_not_weaker():
    text = PYPROJECT.replace("strict = true\n", "strict_optional = true\n")
    assert findings("strict_optional = true\n", "", text) == []


def test_ini_lists_flags_and_tox_commands():
    before = cf.parse(
        "tox.ini",
        "[flake8]\nextend-ignore = E203\nmax-line-length = 100\nper-file-ignores =\n    tests/*: S101\n"
        "[testenv]\ncommands =\n    pytest -q\n    mypy src\n",
    )
    after = cf.parse(
        "tox.ini",
        "[flake8]\nextend-ignore = E203, W503\nmax-line-length = 120\nper-file-ignores =\n    tests/*: S101\n    src/*: E501\n"
        "[testenv]\nignore_outcome = true\ncommands =\n    pytest -q || true\n",
    )
    found = cr.weakened(before, after)
    for expected in (
        "flake8.extend-ignore: adds W503",
        "flake8.max-line-length: 100 -> 120",
        "flake8.per-file-ignores: adds src/*:E501",
        "testenv.ignore_outcome: unset -> true",
        "testenv.commands: adds || true",
        "commands: mypy no longer runs",
    ):
        assert any(expected in f for f in found), (expected, found)


def test_a_new_flake8_limit_is_judged_against_its_default():
    found = cr.weakened(
        cf.parse(".flake8", "[flake8]\n"), cf.parse(".flake8", "[flake8]\nmax-line-length = 88\n")
    )
    assert found == ["flake8.max-line-length: default 79 -> 88"]
    found = cr.weakened(
        cf.parse(".flake8", "[flake8]\n"), cf.parse(".flake8", "[flake8]\nmax-complexity = 10\n")
    )
    assert found == []  # a new complexity limit tightens: unset means no limit


def test_mypy_section_override_switched_off():
    before = cf.parse("mypy.ini", "[mypy]\nstrict = True\n")
    after = cf.parse(
        "mypy.ini",
        "[mypy]\nstrict = True\n[mypy-legacy.*]\nignore_errors = True\nfollow_imports = skip\n",
    )
    assert cr.weakened(before, after) == [
        "mypy-legacy.*.follow_imports: unset -> skip",
        "mypy-legacy.*.ignore_errors: unset -> True",
    ]


def test_value_helpers():
    assert cr.items("a, b\n c", "ignore") == ["a", "b", "c"]
    assert cr.items("ignore::X, y\nerror", "filterwarnings") == ["ignore::X, y", "error"]
    assert cr.items(cr.MISSING, "ignore") == [] and cr.items(None, "ignore") == []
    assert cr.as_bool("Yes") is True and cr.as_bool("off") is False and cr.as_bool("maybe") is None
    assert cr.as_bool(1) is True and cr.as_bool(["x"]) is None
    assert cr.as_num("12") == 12.0 and cr.as_num(True) is None and cr.as_num("x") is None
    assert cr.rank("BASIC", cr.RANKS["typecheckingmode"][0], 2) == 1
    assert cr.rank(cr.MISSING, {}, 2) == 2
    assert cr.as_bool("0") is False and cr.as_bool(" yes ") is True and cr.as_bool(True) is True
    assert cr.items([" a ", "", "b"], "ignore") == ["a", "b"]
    assert cr.items(" error \n  ignore::X \n", "filterwarnings") == ["error", "ignore::X"]
    assert cf.per_file_lines("a.py : E1, E2") == ["a.py:E1", "a.py:E2"]
    assert cr.as_num(" 12 ") == 12.0 and cr.as_num(cr.MISSING) is None and cr.as_num(None) is None


# --- text: workflows, pre-commit, conftest --------------------------------------

WORKFLOW = """name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Lint
        run: ruff check . --output-format=github
      - name: Types
        run: mypy --strict src
      - name: Test
        run: |
          set -euo pipefail
          python -m pytest -q --cov-fail-under=90  # the floor
      - run: black --check .
"""


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ("--output-format=github", "--output-format=github || true", "steps: adds || true"),
        ("--output-format=github", "--exit-zero", "steps: adds --exit-zero"),
        (
            "        run: mypy --strict src\n",
            "        run: mypy --strict src\n        continue-on-error: true\n",
            "continue-on-error: true",
        ),
        (
            "      - name: Types\n",
            "      - name: Types\n        if: false\n",
            "steps: adds if: false",
        ),
        (
            "      - name: Lint\n        run: ruff check . --output-format=github\n",
            "",
            "steps: ruff no longer runs",
        ),
        ("--cov-fail-under=90", "--cov-fail-under=80", "lowers --cov-fail-under from 90"),
        (" --cov-fail-under=90", "", "lowers --cov-fail-under from 90"),
        ("set -euo pipefail", "set -uo pipefail", "steps: drops set -e"),
        ("set -euo pipefail", "set +e", "steps: adds set +e"),
        ("mypy --strict src", "mypy src", "steps: drops --strict"),
        ("black --check .", "black .", "steps: drops --check"),
        ("pytest -q", "pytest -q -p no:warnings", "steps: adds -p no:warnings"),
        ("pytest -q", "pytest -q --ignore=tests/slow", "steps: adds --ignore=tests/slow"),
        (
            "runs-on: ubuntu-latest",
            "runs-on: ubuntu-latest\n    env:\n      SKIP: mypy",
            "steps: adds SKIP: mypy",
        ),
        ("ruff check .", "ruff check . --line-length 120", "raises --line-length to 120"),
        ("--output-format=github", "--output-format=github || exit 0", "steps: adds || exit 0"),
        ("pytest -q", "pytest -q -W ignore::UserWarning", "steps: adds -W ignore::UserWarning"),
    ],
)
def test_workflow_weakening(old, new, expected):
    found = ct.line_findings("workflow", WORKFLOW, WORKFLOW.replace(old, new, 1))
    assert any(expected in f for f in found), found


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("actions/checkout@v4", "actions/checkout@v5"),
        ("name: Lint", "name: Lint the code || true with ruff"),
        ("python -m pytest -q", "python -m pytest -q -x"),
        (
            "      - run: black --check .\n",
            "      - run: black --check .\n      - run: pytest -q --strict-markers\n",
        ),
        ("--cov-fail-under=90", "--cov-fail-under=95"),
        ("ruff check .", "pip install ruff\n          ruff check ."),
        ("# the floor", "# drops --check, set +e and || true"),
        (
            "      - run: black --check .\n",
            "      - run: black --check .\n      - run: ruff format --check .\n",
        ),
        (
            "      - run: black --check .\n",
            "      - run: black --check .\n      - run: python -m pytest tests/unit\n",
        ),
        ("ruff check .", "ruff check . --line-length 80"),  # below ruff's default of 88
    ],
)
def test_workflow_edits_that_weaken_nothing(old, new):
    assert ct.line_findings("workflow", WORKFLOW, WORKFLOW.replace(old, new, 1)) == []


def test_a_removed_install_line_does_not_count_as_a_tool_that_stopped():
    before = WORKFLOW.replace(
        "      - run: black", "      - run: pip install bandit\n      - run: black"
    )
    assert ct.line_findings("workflow", before, WORKFLOW) == []


@pytest.mark.parametrize(
    ("line", "tools"),
    [
        ("go test ./...", ["go test"]),
        ("cargo clippy", ["cargo clippy", "clippy"]),
        ("npm run lint", ["npm run lint"]),
        ("pnpm test", ["pnpm test"]),
        ("pre-commit run --all-files", ["pre-commit"]),
    ],
)
def test_a_workflow_that_stops_running_a_check_tool(line, tools):
    before = WORKFLOW + f"      - run: {line}\n"
    found = ct.line_findings("workflow", before, WORKFLOW)
    assert found == [f"steps: {tool} no longer runs" for tool in tools]


def test_dropping_warnings_as_errors_counts():
    assert ct.text_marks("run", ["pytest -W error"], ["pytest"]) == ["run: drops -W error"]
    assert ct.text_marks("run", ['pytest -W "error"'], ["pytest -q"]) == ["run: drops -W error"]


def test_each_coverage_floor_is_compared_with_its_counterpart():
    before = ["pytest --cov-fail-under=90", "pytest --cov-fail-under=60"]
    after = ["pytest --cov-fail-under=70", "pytest --cov-fail-under=60"]
    assert ct.text_marks("ci", before, after) == ["ci: lowers --cov-fail-under from 90"]
    assert ct.text_marks("ci", before, before[::-1]) == []
    assert ct.text_marks("ci", before, before[:1]) == ["ci: lowers --cov-fail-under from 90"]


def test_each_line_limit_is_compared_with_its_counterpart():
    before = ["flake8 --max-line-length=100", "flake8 --max-line-length=79"]
    raised = ["flake8 --max-line-length=100", "flake8 --max-line-length=99"]
    assert ct.text_marks("ci", before, raised) == ["ci: raises --max-line-length to 100"]
    assert ct.text_marks("ci", before, before[::-1]) == []
    assert ct.text_marks("ci", [], ["flake8 --max-line-length=79"]) == []


PRECOMMIT = """repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: check-yaml
      - id: trailing-whitespace
  - repo: local
    hooks:
      - id: typecheck
        name: typecheck
        entry: mypy
        language: system
"""


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ("      - id: trailing-whitespace\n", "", "hooks: removes hook trailing-whitespace"),
        (
            "      - id: typecheck\n        name: typecheck\n        entry: mypy\n",
            "      - id: typecheck\n        name: typecheck\n        entry: echo\n",
            "mypy no longer runs",
        ),
        ("args: [--fix]", "args: [--fix, --exit-zero]", "hooks: adds --exit-zero"),
        ("args: [--fix]", 'args: ["--fix", "--ignore=E501"]', "hooks: adds --ignore=E501"),
        (
            "      - id: ruff-format\n",
            "      - id: ruff-format\n        exclude: ^legacy/\n",
            "hooks: adds exclude: ^legacy/",
        ),
        (
            "      - id: check-yaml\n",
            "      - id: check-yaml\n        stages: [manual]\n",
            "stages: [manual]",
        ),
    ],
)
def test_precommit_weakening(old, new, expected):
    found = ct.line_findings("precommit", PRECOMMIT, PRECOMMIT.replace(old, new, 1))
    assert any(expected in f for f in found), found


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("rev: v0.6.0", "rev: v0.7.0"),
        ("      - id: ruff-format\n", "      - id: ruff-fmt\n"),
        ("repos:\n", "ci:\n  autofix_commit_msg: '[pre-commit.ci] fixes'\nrepos:\n"),
        ("      - id: ruff\n", "      - id: ruff-check\n"),
        (
            "repos:\n",
            "repos:\n  - repo: https://github.com/psf/black\n    rev: 24.1.0\n    hooks:\n      - id: black\n",
        ),
        (
            "https://github.com/astral-sh/ruff-pre-commit",
            "https://github.com/astral-sh/ruff-pre-commit.git",
        ),
    ],
)
def test_precommit_edits_that_weaken_nothing(old, new):
    assert ct.line_findings("precommit", PRECOMMIT, PRECOMMIT.replace(old, new, 1)) == []


CONFTEST = "import pytest\n\n\n@pytest.fixture\ndef db():\n    return 1\n"


@pytest.mark.parametrize(
    ("added", "expected"),
    [
        ("collect_ignore = ['test_slow.py']\n", "collect_ignore"),
        (
            "def pytest_collection_modifyitems(items):\n    for i in items:\n        i.add_marker(pytest.mark.skip)\n",
            "mark.skip",
        ),
        ("pytestmark = pytest.mark.xfail\n", "xfail"),
        ("def pytest_ignore_collect(collection_path):\n    return True\n", "pytest_ignore_collect"),
        ("import warnings\nwarnings.filterwarnings('ignore')\n", "a warnings filter set to ignore"),
        ("def pytest_runtest_setup(item):\n    pytest.skip('flaky')\n", "skip("),
    ],
)
def test_conftest_weakening(added, expected):
    assert ct.conftest_findings(CONFTEST, CONFTEST + added) == [f"conftest: adds {expected}"]


@pytest.mark.parametrize(
    "added",
    [
        "@pytest.fixture\ndef other():\n    return 2\n",
        "np = pytest.importorskip('numpy')\n",
        "# pytest.skip('not now')\n",
    ],
)
def test_conftest_edits_that_weaken_nothing(added):
    assert ct.conftest_findings(CONFTEST, CONFTEST + added) == []


def test_conftest_moving_a_skip_is_not_a_new_one():
    before = CONFTEST + "def a():\n    pytest.skip('x')\n"
    after = CONFTEST + "def b():\n    pytest.skip('x')\n"
    assert ct.conftest_findings(before, after) == []


@pytest.mark.parametrize(
    "line",
    [
        " " * 200_000 + "x",
        "- " * 100_000 + "x",
        "pytest " + '-k "' * 50_000,
        "pytest " + "-k '" * 50_000,
        "set +" + "a" * 200_000,
        "stages: " + "x" * 200_000,
        "#" + " #" * 100_000,
        "|| " * 70_000,
        "--ignore " * 20_000,
    ],
    ids=lambda line: f"{line[:12]!r}x{len(line)}",
)
def test_text_rules_stay_linear_on_hostile_lines(line):
    start = time.perf_counter()
    for kind in ("workflow", "precommit"):
        ct.line_findings(kind, "", line)
    ct.conftest_findings("", line)
    ct.text_marks("x", [], [line])
    assert time.perf_counter() - start < 3.0
