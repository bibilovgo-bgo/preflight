from __future__ import annotations

import math

import pytest

import config_formats as cf
import toml_lite as tl

tomllib = pytest.importorskip("tomllib")

# The fallback reader must give what tomllib gives: the property, checked on one set of documents.
DOCS = [
    "[tool.ruff]\nline-length = 100\n",
    'a.b.c = 1\n"quoted key".x = "y"\n\'lit\'.z = 2\n',
    '[[tool.mypy.overrides]]\nmodule = "a.*"\nignore_errors = true\n'
    '[[tool.mypy.overrides]]\nmodule = ["b", "c"]\nstrict = false\n',
    'x = """\nline one\nline "two" \\\n   joined"""\ny = \'\'\'raw \\n\'\'\'\n',
    'arr = [\n  "a", # comment\n  "b",\n]\nnested = [[1, 2], ["x"]]\nempty = []\n',
    'inline = { a = 1, b = { c = "d" } }\nnone = {}\n',
    'esc = "tab\\tquote\\" back\\\\ uni\\u00e9 \\U0001F600 \\b\\f\\r\\n"\n',
    "nums = [0x1F, 0o17, 0b11, 1_000, -3.5e2, +7, 0.5]\n",
    "lit = 'C:\\path'\nempty = \"\"\nt = true\nf = false\n",
    "[a]\nx = 1\n[a.b]\ny = 2\n[c]\n",
    's = """ends with ""quotes"""""\nr = \'\'\'it\'\'s\'\'\'\n',
    "# only a comment\n\n",
    '[tool.pytest.ini_options]\naddopts = "-q"  # trailing comment\n',
    "[ spaced . header ]\nk = 1\r\n",
    "[[a.b]]\nx = 1\n[a.b.c]\ny = 2\n[[a.b]]\nx = 3\n",
    'k = """\\\n  trimmed"""\n',
    "x=1\ny=\"s\"\ne = ''\n",
    'm = """tab\\there"""\nq = """one quote""""\n',
    "tight = [1,2]\ninl = {a=1,b=2}\n",
]
BROKEN = [
    "x = \n",
    'x = "unterminated\n',
    "[a\n",
    "x = bareword\n",
    "x = 1 2\n",
    "x = [1 2]\n",
    "x = 'a\nb'\n",
    'x = "\\q"\n',
    'x = "\\u12"\n',
    "x = {a = 1 b = 2}\n",
    "a = 1\n[a.b]\n",
    'x = """open\n',
    "x = [1,\n",
    "x = {a = 1\n",
    "[[a]]\n[[a.b]]\nx = 1\na = 2\n[a]\n= 1\n",
    "a = 1\n[[a]]\n",
    "x = 'open\n",
    "= 1\n",
    'x = "line\nbreak"\n',
    "k = 1 # ok\n[t] junk\n",
    "a = 1 b = 2\n",
    "a x1\n",
    'x = "\\u+123"\n',
    "x = '\n'\n",
    's = """a""""""\n',
]


@pytest.mark.parametrize("doc", DOCS)
def test_fallback_reader_matches_tomllib(doc):
    assert tl.TomlReader(doc).document() == tomllib.loads(doc.replace("\r\n", "\n"))


@pytest.mark.parametrize("doc", BROKEN)
def test_fallback_reader_refuses_what_tomllib_refuses(doc):
    with pytest.raises(tomllib.TOMLDecodeError):
        tomllib.loads(doc)
    with pytest.raises(ValueError):
        tl.TomlReader(doc).document()


def test_special_floats_and_dates():
    data = tl.TomlReader("a = inf\nb = -inf\nc = nan\nd = 1979-05-27\n").document()
    assert data["a"] == math.inf and data["b"] == -math.inf and math.isnan(data["c"])
    assert data["d"] == "1979-05-27"  # dates stay text: no rule compares them


def test_without_tomllib_the_fallback_reads(monkeypatch):
    monkeypatch.setattr(cf, "tomllib", None)
    assert cf.read_toml(DOCS[0]) == {"tool": {"ruff": {"line-length": 100}}}
    assert cf.read_toml("x = [\n") is None
    assert cf.read_toml("x = " + "[" * 5000 + "]" * 5000 + "\n") is None  # RecursionError


def test_broken_and_deep_toml_is_none():
    assert cf.read_toml("x = bareword\n") is None
    assert (
        cf.read_toml("x = " + "[" * 5000 + "]" * 5000 + "\n") is None
    )  # RecursionError, not a crash


# --- flat maps -------------------------------------------------------------------


def test_pyproject_keeps_only_check_tools():
    text = (
        '[project]\nname = "x"\n[tool.setuptools.packages.find]\nexclude = ["tests"]\n'
        '[tool.ruff.lint]\nignore = ["E501"]\n[tool.hatch]\nx = 1\n'
    )
    assert cf.parse("pyproject.toml", text) == {("tool", "ruff", "lint", "ignore"): ["E501"]}


def test_ruff_toml_stands_for_tool_ruff():
    flat = cf.parse("ruff.toml", "line-length = 90\n[lint]\nselect = ['E']\n")
    assert flat == {("tool", "ruff", "line-length"): 90, ("tool", "ruff", "lint", "select"): ["E"]}


def test_per_file_table_becomes_glob_code_items():
    flat = cf.parse(
        "ruff.toml", '[lint.per-file-ignores]\n"tests/*" = ["S101", "ANN"]\n"a.py" = "E1"\n'
    )
    assert flat[("tool", "ruff", "lint", "per-file-ignores")] == [
        "tests/*:S101",
        "tests/*:ANN",
        "a.py:E1",
    ]


def test_array_of_tables_is_keyed_by_module_so_a_reorder_changes_nothing():
    one = '[[tool.mypy.overrides]]\nmodule = "a"\nstrict = true\n[[tool.mypy.overrides]]\nmodule = "b"\nignore_errors = true\n'
    two = '[[tool.mypy.overrides]]\nmodule = "b"\nignore_errors = true\n[[tool.mypy.overrides]]\nmodule = "a"\nstrict = true\n'
    assert cf.parse("pyproject.toml", one) == cf.parse("pyproject.toml", two)
    assert ("tool", "mypy", "overrides", "b", "ignore_errors") in cf.parse("pyproject.toml", one)


def test_array_of_tables_without_a_name_is_keyed_by_index():
    assert cf.flatten({"x": [{"k": 1}, {"k": 2}]}) == {("x", "0", "k"): 1, ("x", "1", "k"): 2}


def test_per_file_codes_skip_empty_pieces():
    assert cf.per_file_items({"a.py": "E1, ", "b.py": ["", "E2"]}) == ["a.py:E1", "b.py:E2"]


def test_a_mixed_array_stays_a_value():
    assert cf.flatten({"x": [1, {"k": 2}]}) == {("x",): [1, {"k": 2}]}


@pytest.mark.parametrize(
    "name",
    [
        "pyproject.toml",
        "ruff.toml",
        ".ruff.toml",
        "setup.cfg",
        "tox.ini",
        ".flake8",
        "pytest.ini",
        "mypy.ini",
        ".mypy.ini",
        ".coveragerc",
        ".pylintrc",
        "pylintrc",
        "pyrightconfig.json",
    ],
)
def test_every_documented_file_has_a_format(name):
    assert name in cf.FORMATS


def test_shared_ini_keeps_only_check_sections():
    text = (
        "[metadata]\nname = x\n[options.packages.find]\nexclude = tests\n"
        "[flake8]\nignore = E501  # long lines\n[tool:pytest]\naddopts = -q\n"
        "[mypy-legacy.*]\nignore_errors = True\n[coverage:report]\nfail_under = 90\n[testenv]\ncommands = pytest\n"
    )
    assert cf.parse("setup.cfg", text) == {
        ("flake8", "ignore"): "E501",
        ("tool:pytest", "addopts"): "-q",
        ("mypy-legacy.*", "ignore_errors"): "True",
        ("coverage:report", "fail_under"): "90",
        ("testenv", "commands"): "pytest",
    }


def test_a_dedicated_ini_keeps_every_section_under_its_tool():
    flat = cf.parse(".coveragerc", "[report]\nfail_under = 90\n[run]\nbranch = True\n")
    assert flat == {
        ("coverage", "report", "fail_under"): "90",
        ("coverage", "run", "branch"): "True",
    }
    assert cf.parse(".pylintrc", "[MESSAGES CONTROL]\ndisable = C0114\n") == {
        ("pylint", "messages control", "disable"): "C0114"
    }


@pytest.mark.parametrize("text", ["no header = 1\n", "[a\nb = 1\n"])
def test_unreadable_ini_is_none(text):
    assert cf.parse("setup.cfg", text) is None


def test_pyrightconfig_json():
    assert cf.parse("pyrightconfig.json", '{"typeCheckingMode": "strict"}') == {
        ("pyright", "typecheckingmode"): "strict"
    }
    assert cf.parse("pyrightconfig.json", "// jsonc\n{}") == {}  # pyright accepts comments
    assert cf.parse("pyrightconfig.json", '{"a": ') is None
    assert cf.parse("pyrightconfig.json", "[1]") is None
