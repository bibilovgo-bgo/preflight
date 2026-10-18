"""Check configurations as flat maps: TOML, INI and JSON read into {key path: value}.

The config guard compares a file before and after an edit key by key, so every
format becomes the same shape: a dict from a tuple of lowercased keys to a
scalar or a list. Only the parts that configure a check are kept:
``[tool.ruff]``, ``[tool.pytest.ini_options]`` and their neighbours in
``pyproject.toml``; the ``flake8``, ``mypy``, ``tool:pytest`` and
``coverage:*`` sections of ``setup.cfg`` and ``tox.ini``. Packaging keys such
as ``[tool.setuptools.packages.find] exclude`` configure no check.

TOML is read with ``tomllib`` on Python 3.11 and newer; on 3.9 and 3.10 a small
reader of the same grammar takes over (tables, arrays of tables, dotted and
quoted keys, the four string forms, arrays, inline tables). Whatever a reader
cannot parse is ``None``, and the guard lets the edit through.
"""

from __future__ import annotations

import configparser
import json
import re

import toml_lite

try:
    import tomllib
except ImportError:  # Python 3.9 and 3.10
    tomllib = None

Flat = dict  # {tuple of keys: scalar or list}

# file name -> (format, the key prefix the whole file stands for)
FORMATS = {
    "pyproject.toml": ("toml", ()),
    "ruff.toml": ("toml", ("tool", "ruff")),
    ".ruff.toml": ("toml", ("tool", "ruff")),
    "setup.cfg": ("ini", ()),
    "tox.ini": ("ini", ()),
    ".flake8": ("ini", ()),
    "pytest.ini": ("ini", ()),
    "mypy.ini": ("ini", ()),
    ".mypy.ini": ("ini", ()),
    ".coveragerc": ("ini", ("coverage",)),
    ".pylintrc": ("ini", ("pylint",)),
    "pylintrc": ("ini", ("pylint",)),
    "pyrightconfig.json": ("json", ("pyright",)),
}
CHECK_TOOLS = frozenset(
    "ruff black isort mypy pytest coverage pyright basedpyright pylint flake8 bandit "
    "pydocstyle pycodestyle".split()
)
# Sections of a shared INI file (setup.cfg, tox.ini) that configure a check; a file that
# stands for one tool (.coveragerc, .pylintrc) keeps every section.
INI_SECTIONS = re.compile(
    r"(?:flake8|pycodestyle|pep8|pydocstyle|isort|bandit|tool:pytest|pytest|mypy(?:-.+)?"
    r"|coverage:.+|pylint.*|testenv(?::.+)?|tox(?::tox)?)$"
)
PER_FILE = frozenset(
    {"per-file-ignores", "per_file_ignores", "extend-per-file-ignores", "extend_per_file_ignores"}
)
_CODES = re.compile(r"[,\s]+")
_BLANK = re.compile(r"\s*")
IDENTITY = ("module", "id", "name")  # how an array of tables names its entries


def parse(name: str, text: str) -> Flat | None:
    """The check-configuring keys of a file named `name`, or None when it does not parse."""
    fmt, prefix = FORMATS[name]
    if fmt == "toml":
        data = read_toml(text)
        if data is None:
            return None
        flat = flatten(data, prefix)
        return {
            p: v for p, v in flat.items() if len(p) > 2 and p[0] == "tool" and p[1] in CHECK_TOOLS
        }
    if fmt == "ini":
        sections = read_ini(text)
        if sections is None:
            return None
        return flatten(
            {s: v for s, v in sections.items() if prefix or INI_SECTIONS.match(s)}, prefix
        )
    data = read_json(text)
    return None if data is None else flatten(data, prefix)


def flatten(value: object, prefix: tuple = ()) -> Flat:
    """Nested tables -> {key path: scalar or list}; a per-file table -> ["glob:code", ...]."""
    out: Flat = {}
    if isinstance(value, dict):
        for key, item in value.items():
            name = str(key).lower()
            if name in PER_FILE and isinstance(item, dict):
                out[(*prefix, name)] = per_file_items(item)
            else:
                out.update(flatten(item, (*prefix, name)))
    elif isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
        for index, item in enumerate(value):
            for name in entry_names(item, index):
                out.update(flatten(item, (*prefix, name)))
    else:
        out[prefix] = value
    return out


def entry_names(item: dict, index: int) -> list:
    """An array-of-tables entry once per module it names, so reordering the list, `"a"` vs
    `["a"]` or dropping one module changes nothing for the others; else by its position."""
    for key in IDENTITY:
        if key in item:
            names = item[key]
            return [str(n) for n in names] if isinstance(names, list) else [str(names)]
    return [str(index)]


def split_codes(text: str) -> list:
    return [part for part in _CODES.split(text) if part]


def per_file_items(table: dict) -> list:
    out = []
    for glob, codes in table.items():
        for code in codes if isinstance(codes, list) else split_codes(str(codes)):
            if code:
                out.append(f"{glob}:{code}")
    return out


def per_file_lines(text: str) -> list:
    """flake8's `glob: codes` lines -> ["glob:code", ...]; a line without `:` continues the
    codes of the glob above it."""
    out, glob = [], ""
    for line in text.splitlines():
        if ":" in line:
            glob, _, line = line.partition(":")
            glob = glob.strip()
        out += [f"{glob}:{code}" for code in split_codes(line)] if glob else []
    return out


def read_ini(text: str) -> dict | None:
    parser = configparser.ConfigParser(
        interpolation=None,
        strict=False,
        allow_no_value=True,
        inline_comment_prefixes=("#", ";"),
        default_section="\x00",
    )
    try:
        parser.read_string(text)
    except configparser.Error:
        return None
    # Section names stay as written: flake8, mypy and pytest look theirs up case-sensitively.
    return {s: dict(parser.items(s, raw=True)) for s in parser.sections()}


def read_json(text: str) -> dict | None:
    """JSON with the comments and trailing commas pyright accepts in its config."""
    try:
        data = json.loads(drop_trailing_commas(drop_comments(text)))
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _scan(text: str):
    """(index, char, inside a string) for every character, escapes kept inside strings."""
    inside = escaped = False
    for index, char in enumerate(text):
        yield index, char, inside
        if not inside:
            inside = char == '"'
        elif escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            inside = False


def drop_comments(text: str) -> str:
    out, skip_to = [], 0
    for index, char, inside in _scan(text):
        if index < skip_to:
            continue
        if not inside and text.startswith("//", index):
            end = text.find("\n", index)
            skip_to = len(text) if end < 0 else end
        elif not inside and text.startswith("/*", index):
            end = text.find("*/", index + 2)
            skip_to = len(text) if end < 0 else end + 2
        else:
            out.append(char)
    return "".join(out)


def drop_trailing_commas(text: str) -> str:
    out = []
    for index, char, inside in _scan(text):
        if not inside and char == ",":
            after = _BLANK.match(text, index + 1).end()  # a match, not a slice: linear
            if text[after : after + 1] in ("}", "]"):
                continue
        out.append(char)
    return "".join(out)


def read_toml(text: str) -> dict | None:
    try:
        if tomllib is not None:
            return tomllib.loads(text)
        return toml_lite.TomlReader(text).document()
    except (ValueError, IndexError, RecursionError):  # tomllib.TOMLDecodeError is a ValueError
        return None
