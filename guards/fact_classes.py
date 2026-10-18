"""Which files the facts guard asks about, and what to call each of them.

The guard is narrow on purpose: it speaks only before the first edit of a
file in one of four classes, and says nothing about everything else.

* ``money``  — payments, billing, invoices, ledgers, refunds;
* ``auth``   — login, sessions, permissions, tokens;
* ``schema`` — migrations, models, SQL;
* ``config`` — the files that configure linters, type checkers, tests and CI:
  an agent that edits those to make a check pass is fixing the wrong thing.

A class comes from a whole path segment (``src/payments/charge.py``), never
from a substring (``paymentutils.py`` is ordinary), or, when the path says
nothing, from what the edit writes (``op.add_column(`` makes a schema edit
wherever the file lives). Tests, prose, agent instruction files, Claude Code
settings and anything in ``PREFLIGHT_FACTS_EXEMPT`` are never classed. Secret
files (``.env``, keys, credentials) are left to the keys guard.

The path is judged twice: as given and at its real location, so a symlink
``src/tools -> ../auth`` does not hide ``auth``. When the real location
cannot be decided, the stricter answer wins and the file counts as ``auth``.
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import NamedTuple

import secret_files as sf

MONEY_DIRS = frozenset(
    "payment payments billing invoice invoices checkout pricing ledger treasury "
    "revenue wallet subscription subscriptions refund refunds payout payouts".split()
)
AUTH_DIRS = frozenset(
    "auth authn authz login oauth sso session sessions permissions acl rbac security".split()
)
# `schemas/` holds pydantic request models as often as tables and `models/` holds networks as
# often as ORM classes, so neither is a class by path: there, as anywhere, the edit's own
# text decides (`Column(`, `models.Model`, DDL).
SCHEMA_DIRS = frozenset({"migrations", "migration", "alembic"})
_TEST_NAME = r"(?:^test_|_test\.(?:py|go|rb|ts|js|mjs)$|_spec\.rb$|\.(?:test|spec)\.[^.]+$)"
SCHEMA_EXT = frozenset({".sql", ".prisma"})
TEST_DIRS = frozenset({"tests", "test", "__tests__", "spec"})
PROSE_EXT = frozenset({".md", ".mdx", ".txt", ".rst", ".adoc"})
INSTRUCTION_NAMES = frozenset(
    "claude.md agents.md agent.md gemini.md skill.md copilot-instructions.md "
    ".cursorrules .windsurfrules".split()
)
INSTRUCTION_DIRS = frozenset({".claude", ".cursor", ".codex", ".opencode", ".gemini"})
CONFIG_NAMES = frozenset(
    "pyproject.toml ruff.toml setup.cfg pytest.ini tox.ini mypy.ini conftest.py "
    ".pre-commit-config.yaml .gitlab-ci.yml hooks.json .flake8 .pylintrc pyrightconfig.json "
    "jest.config.js jest.config.ts vitest.config.ts vitest.config.js .editorconfig".split()
)
CONFIG_PATTERNS = (".eslintrc*", "eslint.config.*", ".prettierrc*", "tsconfig*.json")
WORKFLOW_DIR = ".github/workflows/"
# Stems that name nothing on their own: a search for `utils` proves no investigation.
GENERIC_STEMS = frozenset(
    "index main init __init__ utils util types readme test tests config mod lib setup app "
    "spec helpers common models model schema auth base core api views urls".split()
)
MIN_STEM = 4

# Money by content needs two signals: one money word is everywhere (`total = len(items)`),
# two of them next to arithmetic, or one next to a currency, Decimal, rounding or a store write,
# is a money path.
_MONEY_WORD = re.compile(r"\b(amount|price|total|balance|currency|vat|discount|fee)s?\b", re.I)
_MONEY_OP = re.compile(r"[*/]|\+=|-=")
_MONEY_SIGNAL = re.compile(
    r"\bround\(|\bDecimal\(|\bINSERT\b|\bUPDATE\b|\.save\(|\.commit\("
    r"|\b(?:usd|eur|gbp|rub|cents?|currency)\b|[$€£₽]",
    re.I,
)
_AUTH = re.compile(
    r"\b(?:password|passwd|jwt|hmac|verify_token|is_admin|is_staff|has_perm|check_password)\b"
    r"|@login_required\b|\bverify\s*=\s*False\b|set_cookie\([^)]*\b(?:httponly|secure)\b",
    re.I,
)
_SCHEMA = re.compile(
    r"\b(?:CREATE|ALTER)\s+TABLE\b|\bDROP\s+COLUMN\b|\bop\.(?:add|drop)_column\("
    r"|\bdb\.Column\(|(?<![\w.])Column\(|\bmodels\.Model\b|@Entity\b|\bcreateTable\(",
    re.I,
)
_MAKE_TARGET = re.compile(r"^(?:test|tests|lint|check|ci)\w*\s*:", re.M | re.I)
_TABLE = re.compile(
    r"(?:CREATE|ALTER)\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?[`\"\[]?(\w+)"
    r"|op\.(?:add|drop)_column\(\s*['\"](\w+)"
    r"|createTable\(\s*['\"](\w+)"
    r"|class\s+(\w+)\s*\([^)]*\b(?:Base|Model)\b",
    re.I,
)
_SYMBOL = re.compile(
    r"^\s*(?:async\s+)?def\s+(\w+)|^\s*class\s+(\w+)|\bfunction\s+(\w+)"
    r"|^\s*export\s+(?:default\s+)?(?:async\s+)?(?:const|let|function|class)\s+(\w+)"
    r"|^\s*func\s+(?:\([^)]*\)\s*)?(\w+)",
    re.M,
)
_STREAM = re.compile(r"::\$.*$")


class Target(NamedTuple):
    cls: str  # "" when the guard has nothing to ask
    rel: str  # the judged path: project-relative when inside the root, else absolute
    stem: str
    table: str
    symbol: str
    parent: (
        str  # the folder's own name: the last word to search for when nothing else names the file
    )


NOTHING = Target("", "", "", "", "", "")


def _segment(part: str) -> str:
    """One path segment as Windows will see it: `CLAUDE.md.`, `x.py::$DATA`."""
    if part in (".", ".."):
        return part
    return _STREAM.sub("", part).rstrip(" .")


def _clean(file_path: str) -> str:
    """`/`-separated; Windows trailing dots and streams dropped only for Windows paths."""
    windows = os.name == "nt" or "\\" in file_path or re.match(r"[A-Za-z]:", file_path)
    parts = file_path.replace("\\", "/").split("/")
    return "/".join(_segment(p) if windows else p for p in parts)


def _relative(path: str, root: Path) -> str:
    """Lowercased, `/`-separated; relative to the root when inside it, else absolute."""
    absolute = os.path.abspath(os.path.join(str(root), path))
    try:
        rel = os.path.relpath(absolute, str(root))
    except ValueError:  # another drive on Windows
        rel = ".."
    inside = rel != ".." and not rel.startswith(".." + os.sep)
    text = rel if inside else absolute
    return text.replace("\\", "/").lower()


def _strip_worktree(rel: str, root: Path) -> str:
    """`.claude/worktrees/<name>/x` mirrors the project, when that worktree is real."""
    match = re.match(r"\.claude/worktrees/([^/]+)/(.+)$", rel)
    if match and (root / ".claude" / "worktrees" / match.group(1) / ".git").exists():
        return match.group(2)
    return rel


def exempt_globs() -> list[str]:
    raw = os.environ.get("PREFLIGHT_FACTS_EXEMPT", "")
    return [g.strip().replace("\\", "/") for g in raw.split(";") if g.strip()]


def is_exempt(rel: str, globs: list[str]) -> bool:
    """Tests, prose, agent instructions, Claude Code settings, operator globs."""
    parts = rel.split("/")
    name, ext = parts[-1], os.path.splitext(parts[-1])[1]
    dirs = set(parts[:-1])
    if dirs & TEST_DIRS or re.search(_TEST_NAME, name):
        return True
    if ext in PROSE_EXT or name in INSTRUCTION_NAMES or ext == ".mdc":
        return True
    if dirs & INSTRUCTION_DIRS or name == ".claude.json":
        return True  # settings, hooks, skills and worktrees of the agent itself
    lowered = [g.lower() for g in globs]
    return any(fnmatch.fnmatchcase(rel, g) or fnmatch.fnmatchcase(name, g) for g in lowered)


def is_secret(name: str) -> bool:
    """Left to the keys guard: a second block on the same call is noise."""
    return (
        sf.is_env_name(name)
        or sf.is_key_name(name)
        or name in sf.CREDENTIAL_NAMES
        or name.startswith(("credentials", "secrets."))
        or name.endswith((".p12", ".pfx"))
    )


def _is_config_name(name: str, text: str) -> bool:
    if name in CONFIG_NAMES or any(fnmatch.fnmatchcase(name, p) for p in CONFIG_PATTERNS):
        return True
    return name == "makefile" and bool(_MAKE_TARGET.search(text))


def by_path(rel: str, text: str = "") -> str:
    """The class a path names, or ""."""
    parts = rel.split("/")
    name, ext = parts[-1], os.path.splitext(parts[-1])[1]
    dirs = set(parts[:-1])
    if "/" + WORKFLOW_DIR in "/" + rel:
        return "config"
    if _is_config_name(name, text):
        return "config"
    if dirs & SCHEMA_DIRS or ext in SCHEMA_EXT:
        return "schema"
    if dirs & AUTH_DIRS:
        return "auth"
    if dirs & MONEY_DIRS:
        return "money"
    return ""


def by_content(text: str) -> str:
    """The class an edit's text names when its path does not; most specific first."""
    if _SCHEMA.search(text):
        return "schema"
    if _AUTH.search(text):
        return "auth"
    words = {m.group(1).lower() for m in _MONEY_WORD.finditer(text)}
    if words and (_MONEY_SIGNAL.search(text) or (len(words) >= 2 and _MONEY_OP.search(text))):
        return "money"
    return ""


def is_network(file_path: str, cleaned: str, root: Path) -> bool:
    """`//host/share/x`, `\\\\host\\x`, `smb://...`, as given or once joined to the root.

    The guard classifies by name and never opens the file, but `exists()` and
    `realpath` on a network path make Windows connect to the host and offer the
    user's NTLM hash; a planted instruction only needs the model to name such a
    path. The keys guard refuses them for the same reason.
    """
    joined = os.path.abspath(os.path.join(str(root), cleaned))
    return any(sf.is_network_path(p) for p in (file_path, cleaned, joined, str(root)))


def _real_relative(path: str, root: Path) -> str | None:
    """The path at its real location, relative to the real root; None on any error."""
    try:
        absolute = Path(os.path.abspath(os.path.join(str(root), path)))
        existing, rest = absolute, []
        while not existing.exists():
            if existing.parent == existing:
                return None
            rest.insert(0, existing.name)
            existing = existing.parent
        real = Path(os.path.realpath(existing)).joinpath(*rest)
        return _relative(str(real), Path(os.path.realpath(str(root))))
    except (OSError, ValueError):
        return None


def table_name(text: str, stem: str) -> str:
    match = _TABLE.search(text)
    if not match:
        return stem
    return next(g for g in match.groups() if g)


def symbol_name(text: str) -> str:
    """The first function or class the edit touches, so a generic stem has a name to search."""
    match = _SYMBOL.search(text)
    return next((g for g in match.groups() if g), "") if match else ""


def stem_of(rel: str) -> str:
    """The file name without its last extension; "" when it names nothing worth searching."""
    stem = os.path.splitext(rel.rsplit("/", 1)[-1])[0]
    return "" if len(stem) < MIN_STEM or stem in GENERIC_STEMS else stem


def classify(file_path: str, text: str, root: Path, globs: list[str] | None = None) -> Target:
    """Everything the guard needs to know about one edit target.

    `text` is what the edit writes (new content), used only when the path is
    silent. The class of a symlinked file is judged at its real location too.
    """
    if not file_path:
        return NOTHING
    cleaned = _clean(file_path)
    rel = _strip_worktree(_relative(cleaned, root), root)
    name = rel.rsplit("/", 1)[-1]
    if is_exempt(rel, exempt_globs() if globs is None else globs) or is_secret(name):
        return NOTHING._replace(rel=rel)
    if is_network(file_path, cleaned, root):
        return NOTHING._replace(rel=rel)  # never stat it: Windows would hand the host an NTLM hash
    cls = by_path(rel, text)
    if not cls:
        real = _real_relative(_clean(file_path), root)
        cls = "auth" if real is None else by_path(real, text)
    if not cls:
        cls = by_content(text)
    stem = stem_of(rel)
    table = table_name(text, stem) if cls == "schema" else ""
    parent = rel.rsplit("/", 2)[-2] if "/" in rel else ""
    return Target(cls, rel, stem, table, symbol_name(text), parent)
