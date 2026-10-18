"""What counts as weakening a check: the rules the config guard applies.

Structured files (TOML, INI, JSON) are compared key by key on their flat maps
(`config_formats.flatten`); the key's last segment decides the rule, with case,
`-` and `_` ignored, so `extend-ignore`, `extend_ignore` and `extendIgnore` are
one key. Workflows, pre-commit configs, `conftest.py` and command values such
as `addopts` are compared as text: a marker that appears more often after the
edit, a strict flag that appears less often, a check tool that no longer runs.

Every finding reads ``<where>: <what>``. Tightening (a new `select` code, a
lower `line-length`, a new hook) finds nothing.
"""

from __future__ import annotations

import re

import config_formats as cf
import config_text as ct

MISSING = object()

GROW = frozenset(
    "ignore extendignore perfileignores extendperfileignores exclude extendexclude omit "
    "excludelines excludealso norecursedirs disable skip skipglob extendskip extendskipglob "
    "ignorepaths ignorepatterns ignorenames skips excludedirs disableerrorcode ignoredmodules "
    "ignoredclasses generatedmembers untypedcallsexclude".split()
)
SHRINK = frozenset(
    "select extendselect enable enableerrorcode testpaths pythonfiles pythonclasses "
    "pythonfunctions include source files strict".split()
)
SHRINK_GONE = frozenset({"select", "extendselect", "enable", "enableerrorcode"})
STRICT_PREFIX = ("strict", "disallow", "warn")
STRICT_BOOL = frozenset(
    {"checkuntypeddefs", "noimplicitoptional", "branch", "extrachecks", "xfailstrict"}
)
DEFAULT_TRUE = frozenset(
    {"strictoptional", "warnnoreturn", "strictparameternonevalue", "analyzeunannotatedfunctions"}
)
LAX_BOOL = frozenset(
    "ignoremissingimports ignoreerrors ignoreoutcome skipmissinginterpreters allowuntypedglobals "
    "allowredefinition followuntypedimports implicitoptional skiplibcheck".split()
)
RANKS = {
    "typecheckingmode": ({"off": 0, "basic": 1, "standard": 2, "strict": 3}, 2),
    "followimports": ({"skip": 0, "silent": 1, "normal": 2, "error": 3}, 2),
}
REPORT_RANK = {"none": 0, "false": 0, "information": 1, "warning": 2, "error": 3, "true": 3}
COMMAND = frozenset({"addopts", "commands"})
# Keys that are one setting under two names: compared as one pool.
FAMILY = {
    "extendignore": "ignore",
    "extendselect": "select",
    "extendperfileignores": "perfileignores",
    "extendexclude": "exclude",
    "extendskip": "skip",
    "extendskipglob": "skipglob",
    "commandspre": "commands",
    "commandspost": "commands",
}
POOLED = GROW | SHRINK | COMMAND | {"filterwarnings"}
ACTIONS = ("default", "always", "ignore", "module", "once", "error")  # the order Python matches
LINE_DEFAULTS = (("ruff", 88), ("black", 88), ("flake8", 79), ("pycodestyle", 79), ("pylint", 100))
_TRUE = frozenset({"true", "yes", "on", "1"})
_FALSE = frozenset({"false", "no", "off", "0"})


def norm(key: str) -> str:
    """`extend-ignore`, `extend_ignore` -> `extendignore`; keys arrive lowercased."""
    return re.sub(r"[-_]", "", key)


def items(value: object, key: str) -> list:
    if value is MISSING or value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value)
    if key == "filterwarnings":
        return [line.strip() for line in text.splitlines() if line.strip()]
    if key == "perfileignores":
        return cf.per_file_lines(text)
    return cf.split_codes(text)


def as_bool(value: object) -> bool | None:
    """TOML booleans and INI words; `bool` is an `int`, so `True` reads as "true"."""
    text = str(value).strip().lower() if isinstance(value, (str, int)) else ""
    return True if text in _TRUE else False if text in _FALSE else None


def as_num(value: object) -> float | None:
    """A number, or None for anything else (`True`, MISSING and None do not parse)."""
    try:
        return float(str(value))
    except ValueError:
        return None


def show(value: object) -> str:
    return "unset" if value is MISSING else str(value)


# --- structured files ----------------------------------------------------------


def weakened(before: dict, after: dict) -> list:
    """Every weakening between two flat maps of one file."""
    old_pool, old_exact, old_names = pools(before)
    new_pool, new_exact, new_names = pools(after)
    names = {**old_names, **new_names}
    found = []
    for key in sorted(set(old_pool) | set(new_pool)):
        old, new = old_pool.get(key, MISSING), new_pool.get(key, MISSING)
        found += judge_pool(names[key], key[-1], old, new)
    for path in sorted(set(old_exact) | set(new_exact)):
        found += judge(path, old_exact.get(path, MISSING), new_exact.get(path, MISSING), after)
    found += ct.tools_gone("commands", commands_of(old_pool), commands_of(new_pool))
    return found


def tool_of(path: tuple) -> tuple:
    """Whose setting a key is: `tool.ruff` for `tool.ruff.lint.ignore`, `testenv` for any
    tox environment, `coverage` for `coverage:run`; a mypy per-module section stays itself."""
    if path[0] == "tool":
        return path[:2]
    head = path[0]
    if head.startswith("testenv"):
        return ("testenv",)
    return (head.split(":")[0],) if head.startswith("coverage:") else (head,)


def pools(flat: dict) -> tuple:
    """Lists and commands pooled by tool and key family, so a key that moves (`[tool.ruff]`
    to `[tool.ruff.lint]`, `ignore` to `extend-ignore`, one tox env to another) or gets
    split is compared as one value; everything else stays at its exact path. The third map
    names each pool by the first key path it holds, for the message."""
    pooled: dict = {}
    exact: dict = {}
    names: dict = {}
    for path, value in sorted(flat.items()):
        key = norm(path[-1])
        family = FAMILY.get(key, key)
        if family in POOLED and not (is_bool_key(key) and as_bool(value) is not None):
            pool = (*tool_of(path), family)
            pooled.setdefault(pool, []).extend(values(value, family))
            names.setdefault(pool, ".".join(path))
        else:
            exact[path] = value
    return pooled, exact, names


def values(value: object, family: str) -> list:
    if family in COMMAND:
        return command_text(value, family)
    return items(value, family)


def commands_of(pool: dict) -> list:
    return [line for key, lines in sorted(pool.items()) if key[-1] == "commands" for line in lines]


def covers(item: str, seps: str) -> list:
    """The shorter entries that already mean `item`: a rule code without trailing digits (`E5`,
    `E` for `E501`, never `D` for `DTZ`), a path cut at a separator (`tests`, `tests/` for
    `tests/unit`, never `build` for `build*`). Bounded: a cut past 256 characters or more than
    16 trailing digits is not looked for, so a hostile entry costs no more than a short one."""
    if "/.." in item or "\\.." in item:
        return []  # `tests/../src` is not under `tests`
    digits = min(len(item) - len(item.rstrip("0123456789")), 16)
    out = [item[:i] for i in range(max(len(item) - digits, 1), len(item))]
    for index, char in enumerate(item[:256]):
        if char in seps and index:
            out += [item[:index], item[: index + 1]]
    return out


def covered(item: str, others: set, seps: str = "/\\") -> bool:
    """`item` adds or loses nothing next to `others`: it is there, `ALL` is, or a wider entry is."""
    return item in others or "ALL" in others or any(c in others for c in covers(item, seps))


def judge_pool(where: str, family: str, old: object, new: object) -> list:
    was = [] if old is MISSING else old
    now = [] if new is MISSING else new
    if family in COMMAND:
        return ct.text_marks(where, was, now)
    if family == "filterwarnings":
        return judge_filters(where, was, now)
    if family in GROW:
        before = set(was)
        added = sorted({i for i in now if not covered(i, before)})
        return [f"{where}: adds {', '.join(added)}"] if added else []
    if new is MISSING:
        return [f"{where}: removed"] if family in SHRINK_GONE and old is not MISSING else []
    after = set(now)
    gone = sorted({i for i in was if not covered(i, after)})
    return [f"{where}: drops {', '.join(gone)}"] if gone else []


def judge(path: tuple, old: object, new: object, after: dict) -> list:
    where, key = ".".join(path), norm(path[-1])
    if is_bool_key(key):  # list-valued `strict` (pyright paths) was pooled, never lands here
        return judge_bool(where, key, old, new)
    if key in RANKS:
        return judge_rank(where, old, new, RANKS[key])
    if key.startswith("report") and any("pyright" in part for part in path):
        mode = after.get((*path[:-1], "typecheckingmode"))
        return judge_rank(where, old, new, (REPORT_RANK, 3 if mode == "strict" else None))
    return judge_number(path, key, old, new)


def is_bool_key(key: str) -> bool:
    return key.startswith(STRICT_PREFIX) or key in STRICT_BOOL or key in LAX_BOOL


def judge_bool(where: str, key: str, old: object, new: object) -> list:
    was, now = as_bool(old), as_bool(new)
    if key in LAX_BOOL:
        weaker = now is True and was is not True
    elif old is MISSING:
        weaker = key in DEFAULT_TRUE and now is False
    else:
        unset_is_lax = new is MISSING and key not in DEFAULT_TRUE
        weaker = was is True and (now is False or unset_is_lax)
    return [f"{where}: {show(old)} -> {show(new)}"] if weaker else []


def action(spec: str) -> str:
    """A warnings filter with its action spelled out: Python takes any prefix (`i::X` ignores)."""
    head, sep, rest = spec.partition(":")
    name = next((a for a in ACTIONS if head and a.startswith(head)), head)  # items arrive stripped
    return name + sep + rest


def judge_filters(where: str, old: list, new: list) -> list:
    """A new `ignore` filter that no old one already covered (`ignore::X:mod` is narrower than
    `ignore::X`); an `error` filter that left with nothing left to cover it."""
    old, new = [action(f) for f in old], [action(f) for f in new]
    ignores = {f for f in old if f.startswith("ignore")}
    errors = {f for f in new if f.startswith("error")}
    added = [f for f in new if f.startswith("ignore") and not covered(f, ignores, ":")]
    dropped = [f for f in old if f.startswith("error") and not covered(f, errors, ":")]
    return [f"{where}: adds {f}" for f in added] + [f"{where}: drops {f}" for f in dropped]


def judge_rank(where: str, old: object, new: object, scale: tuple) -> list:
    """A level that went down. An unset level is the tool's default, when it is known:
    pyright's `standard` mode, and `error` for every report rule in `strict` mode."""
    table, default = scale
    was, now = rank(old, table, default), rank(new, table, default)
    weaker = was is not None and now is not None and now < was
    return [f"{where}: {show(old)} -> {show(new)}"] if weaker else []


def rank(value: object, table: dict, default: int | None) -> int | None:
    if value is MISSING:
        return default
    return table.get(str(value).lower())


def judge_number(path: tuple, key: str, old: object, new: object) -> list:
    where, was, now = ".".join(path), as_num(old), as_num(new)
    if key == "failunder":
        weaker = was is not None and (new is MISSING or (now is not None and now < was))
        return [f"{where}: {show(old)} -> {show(new)}"] if weaker else []
    if key not in ("linelength", "minsimilaritylines") and not key.startswith("max"):
        return []
    if key == "maxcomplexity" and new is MISSING and was is not None:
        # flake8 has no complexity check without it; ruff falls back to its default of 10.
        no_limit = not any("ruff" in part for part in path)
        return [f"{where}: {show(old)} -> unset"] if no_limit else []
    if old is MISSING:
        was = default_line_length(path, key)
    if was is None or now is None or now <= was:
        return []
    return [f"{where}: {show(old) if old is not MISSING else f'default {was:g}'} -> {show(new)}"]


def default_line_length(path: tuple, key: str) -> float | None:
    if key not in ("linelength", "maxlinelength"):
        return None
    for tool, length in LINE_DEFAULTS:
        if any(tool in part for part in path):
            return float(length)
    return None


def command_text(value: object, family: str) -> list:
    """A command value as lines; `addopts` is one pytest command line. None carries no marker."""
    text = " ".join(map(str, value)) if isinstance(value, list) else str(value)
    if family == "addopts":
        text = "pytest " + " ".join(text.split())
    return text.splitlines()
