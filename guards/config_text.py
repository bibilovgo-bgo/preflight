"""Weakening found in text: command lines, workflows, pre-commit hooks, conftest.py.

Without a YAML parser, a workflow or a pre-commit config is compared line by
line as a bag of markers: a weak one that appears more often after the edit
(`|| true`, `continue-on-error: true`, `--exit-zero`, `-p no:...` after
pytest), a strict one that appears less often (`--check`, `--strict`,
`set -e`), a limit raised or a floor lowered (`--max-line-length`,
`--cov-fail-under`), a check tool that no longer runs anywhere in the file, a
hook that left. The same markers judge `addopts` and tox `commands` values.
Comments and the prose of `name:` lines do not count.
"""

from __future__ import annotations

import re
from collections import Counter

# Weak anywhere: they switch off a whole script's failures or a commit's hooks.
# Bounded letter runs around the `e` of `set +e`: unbounded ones backtrack quadratically.
_SET = r"\bset\s+{}[a-z]{{0,20}}e[a-z]{{0,20}}\b"
# Between an option and its value: `=`, spaces, or the quotes and commas of a YAML list.
_SEP = r"(?:=|[\"',\s]{1,6})"
_ALWAYS_WEAK = (
    re.compile(_SET.format(r"\+")),
    re.compile(r"(?<![\w-])--no-verify(?![\w-])"),
    re.compile(r"\bSKIP\s*[=:]\s*[\w,-]+"),
)
# Weak only on a line that runs a check tool: `rsync --exclude=.git` and `rm x || true` are not.
_CHECK_WEAK = (
    re.compile(r"\|\|\s*(?:true|:|exit\s+0)(?!\w)"),
    re.compile(r"(?<![\w-])--exit-zero(?![\w-])"),
    re.compile(
        r"(?<![\w-])--(?:extend-)?(?:ignore(?:-glob)?|exclude|disable|deselect"
        r"|per-file-ignores|skip)" + _SEP + r"[^\s,\]\"']+"
    ),
)
# Python's warnings take any prefix of an action: `i`, `ign` and `ignore` all ignore.
_IGNORE = r"(?:ignore|ignor|igno|ign|ig|i)"
_ERROR = r"(?:error|erro|err|er|e)"
# Plugins whose absence changes no verdict: the cache, ordering, parallelism, output.
_HARMLESS_PLUGINS = frozenset(
    "cacheprovider randomly random_order sugar xdist faulthandler pastebin rerunfailures "
    "instafail icdiff clarity legacypath".split()
)
_PYTEST = re.compile(r"(?<![\w.-])(?:py\.test|pytest)(?![\w-])")
_PYTEST_WEAK = (
    re.compile(r"(?<![\w-])-[km]\s*(?:\"[^\"]{0,256}\"|'[^']{0,256}'|[^\s\"']+)"),
    re.compile(r"(?<![\w-])-p\s*no:([\w.-]+)\S*"),
    re.compile(r"(?<![\w-])-W\s*[\"']?" + _IGNORE + r"(?![\w])\S*"),
    re.compile(
        r"(?<![\w-])--(?:no-cov|disable-(?:pytest-)?warnings|continue-on-collection-errors"
        r"|lf|last-failed|co|collect-only)(?![\w-])"
    ),
)
# Anywhere on the line, any case: YAML flow mappings put them after `{run: ...,`.
_YAML_WEAK = (
    re.compile(r"(?i)\bcontinue-on-error:\s*[\"']?(?:true|\$\{\{\s*true\s*\}\})"),
    re.compile(r"(?i)(?<![\w-])if:\s*(?:[\"']?false[\"']?|\$\{\{\s*false\s*\}\})(?![\w])"),
)
_HOOKS_WEAK = (
    re.compile(r"^\s*(?:-\s*)?(?:default_)?stages:.*\bmanual\b.*$"),
    re.compile(r"^\s*(?:-\s*)?exclude:\s*\S.*$"),
)
_STRICT = (
    (re.compile(r"(?<![\w-])--check(?![\w-])"), None),
    (re.compile(r"(?<![\w-])--strict(?:-markers|-config)?(?![\w-])"), None),
    (re.compile(_SET.format("-")), "set -e"),
    (re.compile(r"(?<![\w-])-W\s*[\"']?" + _ERROR + r"(?![\w])"), "-W error"),
)
_NUMBERS = (
    (re.compile(r"(?<![\w-])--(max-line-length|line-length)" + _SEP + r"(\d+)"), "up"),
    (re.compile(r"(?<![\w-])--((?:cov-)?fail-under)" + _SEP + r"(\d+(?:\.\d+)?)"), "down"),
)
_OPTION_DEFAULTS = {"max-line-length": 79.0, "line-length": 88.0}
_TOOLS = (
    re.compile(
        r"(?<![\w.-])(pytest|py\.test|ruff|mypy|flake8|pylint|pyright|basedpyright|black|isort"
        r"|bandit|tox|nox|unittest|coverage|eslint|tsc|prettier|jest|vitest|biome"
        r"|golangci-lint|clippy|pre-commit)(?!\w)"
    ),
    re.compile(r"\b(?:go|cargo)\s+(?:test|vet|clippy)\b"),
    re.compile(r"\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?(?:test|lint|typecheck|type-check|check)\b"),
)
_PROSE_KEY = re.compile(r"^\s*(?:-\s*)?(?:name|description):")
_NOT_A_RUN = re.compile(r"^\s*(?:-\s*)?(?:repo|rev):")
_INSTALL = re.compile(r"\binstall\b|\b(?:uv|poetry)\s+add\b")
_SEGMENTS = re.compile(r"&&|\|\||[;|]")
_HOOK_ID = re.compile(r"^\s*(?:-\s*)?id:\s*[\"']?([\w.-]+)")


def label(match: re.Match) -> str:
    return " ".join(match.group().split()).replace("py.test", "pytest")


def clean_lines(text: str, yaml: bool) -> list:
    """Lines without comments, `\\` continuations joined; in YAML, without the prose of
    `name:` and `description:`."""
    out: list = []
    pieces: list = []  # a continued line, joined once: repeated `+` would be quadratic
    for raw in text.splitlines():
        part = uncomment(raw).rstrip()
        if part.endswith("\\"):
            pieces.append(part[:-1])
            continue
        line = " ".join([*pieces, part])
        pieces = []
        if line and not (yaml and _PROSE_KEY.match(line)):
            out.append(line)
    return out + ([" ".join(pieces)] if pieces else [])


def uncomment(line: str) -> str:
    """The line up to its first `#` that starts a comment: after a space or at the start, and
    outside quotes, so `pytest -q "a #b" || true` keeps its `|| true`."""
    quote = ""
    for index, char in enumerate(line):
        if quote:
            quote = "" if char == quote else quote
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def weak_marks(lines: list, kind: str) -> tuple:
    """(markers weak on any line, pytest options that narrow what runs)."""
    general: Counter = Counter()
    narrowing: Counter = Counter()
    extra = {"workflow": _YAML_WEAK, "precommit": _YAML_WEAK + _HOOKS_WEAK}.get(kind, ())
    for line in lines:
        checks = kind != "workflow" or tools([line])  # hook args and commands are a check's
        rules = _ALWAYS_WEAK + extra + (_CHECK_WEAK if checks else ())
        general.update(label(m) for rx in rules for m in rx.finditer(line))
        found = _PYTEST.search(line)
        if found:
            narrowing.update(pytest_flags(line[found.end() :]))
    return general, narrowing


def pytest_flags(rest: str) -> list:
    flags = []
    for rx in _PYTEST_WEAK:
        for match in rx.finditer(rest):
            if not (match.lastindex and match.group(1) in _HARMLESS_PLUGINS):
                flags.append(label(match))
    return flags


def strict_marks(lines: list) -> Counter:
    marks: Counter = Counter()
    for line in lines:
        for rx, name in _STRICT:
            marks.update(name or label(m) for m in rx.finditer(line))
    return marks


def numbers(lines: list, direction: str) -> dict:
    """{option: its values}, highest first for a limit (`up`), lowest first for a floor."""
    found: dict = {}
    for rx, way in _NUMBERS:
        if way == direction:
            for match in (m for line in lines for m in rx.finditer(line)):
                found.setdefault(match.group(1), []).append(float(match.group(2)))
    return {name: sorted(values, reverse=direction == "up") for name, values in found.items()}


def number_findings(where: str, old: list, new: list) -> list:
    """A limit higher than its counterpart before (or than the default), a floor lower or gone.

    Values are paired in order, so with two jobs at 90 and 60, lowering the 90 to 70 counts.
    """
    found = []
    was, now = numbers(old, "up"), numbers(new, "up")
    for name, values in sorted(now.items()):
        before = was.get(name, []) + [_OPTION_DEFAULTS[name]] * len(values)
        if any(value > limit for value, limit in zip(values, before)):
            found.append(f"{where}: raises --{name} to {values[0]:g}")
    was, now = numbers(old, "down"), numbers(new, "down")
    for name, values in sorted(was.items()):
        after = now.get(name, [])
        if len(after) < len(values) or any(a < b for a, b in zip(after, values)):
            found.append(f"{where}: lowers --{name} from {values[-1]:g}")
    return found


def text_marks(where: str, old: list, new: list, kind: str = "command") -> list:
    """Weak markers that became more frequent, strict ones that became rarer, bad numbers.

    In a workflow, an edit that only adds lines adds a check: a new `pytest -m integration`
    job narrows nothing that ran before, so pytest options count only when a line changed.
    """
    (was, was_narrow), (now, now_narrow) = weak_marks(old, kind), weak_marks(new, kind)
    if kind != "workflow" or Counter(old) - Counter(new):
        was, now = was + was_narrow, now + now_narrow
    found = [f"{where}: adds {m}" for m in sorted(now) if now[m] > was[m]]
    was, now = strict_marks(old), strict_marks(new)
    found += [f"{where}: drops {m}" for m in sorted(was) if now[m] < was[m]]
    return found + number_findings(where, old, new)


def tools(lines: list) -> set:
    """Check tools the lines run; an install command (`pip install pytest`) runs none, but
    `pip install -e . && pytest` still runs pytest."""
    found = set()
    for line in lines:
        if _NOT_A_RUN.match(line):
            continue
        for part in _SEGMENTS.split(line):
            if not _INSTALL.search(part):
                found.update(label(m) for rx in _TOOLS for m in rx.finditer(part))
    return found


def tools_gone(where: str, old: list, new: list, skip: frozenset = frozenset()) -> list:
    gone = sorted(tools(old) - tools(new) - skip)
    return [f"{where}: {tool} no longer runs" for tool in gone]


def line_findings(kind: str, before: str, after: str) -> list:
    """A workflow or a pre-commit config, compared as text."""
    where = "steps" if kind == "workflow" else "hooks"
    old, new = clean_lines(before, yaml=True), clean_lines(after, yaml=True)
    found = text_marks(where, old, new, kind)
    if kind == "precommit":
        found += tools_gone(where, old, new, frozenset({"pre-commit"}))
        return found + [f"{where}: removes hook {h}" for h in hooks_gone(old, new)]
    return found + tools_gone(where, old, new)


def hooks_gone(old: list, new: list) -> list:
    """Hook ids that left the file; a rename that keeps the stem as a word (`ruff` ->
    `ruff-check`, `lint` -> `ruff-lint`) did not."""
    was = {m.group(1) for m in map(_HOOK_ID.match, old) if m}
    now = {m.group(1) for m in map(_HOOK_ID.match, new) if m}
    added = now - was
    words = {word for hook in added for word in hook.split("-")}  # a set: linear in the hooks
    return [h for h in sorted(was - now) if h.split("-")[0] not in words]


# --- conftest.py --------------------------------------------------------------

_CONFTEST = (
    # `pytest.skip(`, `pt.skip (`, a bare `skip(` after `from pytest import skip`.
    (re.compile(r"(?<![\w.])(?:\w+\.)?skip\s*\("), "skip("),
    (re.compile(r"\bmark\.skip(?:if)?\b"), "mark.skip"),
    (re.compile(r"\bmark\.xfail\b|(?<![\w.])(?:\w+\.)?xfail\s*\("), "xfail"),
    (re.compile(r"\bcollect_ignore(?:_glob)?\b"), "collect_ignore"),
    (re.compile(r"\bpytest_ignore_collect\b"), "pytest_ignore_collect"),
    (
        re.compile(r"\b(?:filterwarnings|simplefilter)\W+" + _IGNORE + r"\b"),
        "a warnings filter set to ignore",
    ),
)


def conftest_findings(before: str, after: str) -> list:
    """Skips, xfails, collection ignores and silenced warnings a conftest gained."""

    def count(text: str) -> Counter:
        lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
        return Counter(name for line in lines for rx, name in _CONFTEST for _ in rx.finditer(line))

    was, now = count(before), count(after)
    return [f"conftest: adds {name}" for name in sorted(now) if now[name] > was[name]]
