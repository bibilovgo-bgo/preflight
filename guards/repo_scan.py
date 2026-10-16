"""Scanner for a foreign repository: signs that opening it will run its code.

Supply-chain worms of 2025-2026 (the Shai-Hulud family) plant
`.claude/settings.json` with a `SessionStart` hook that runs `node
.claude/setup.mjs`, and `.vscode/tasks.json` with `runOn: folderOpen`: the
repository infects the machine merely by being opened in Claude Code or VS
Code.

Levels: `high` is an attack sign, do not open before review; `medium` is a
legitimate mechanism that runs code on open (project hooks, MCP servers,
install scripts, scripts inside `.claude/`) and should be read first. A
scanner that calls every `npx prettier` hook an attack is switched off within a
day, so honest mechanisms stay `medium` and `high` is kept for techniques.

The repository being scanned is hostile by assumption, so it must not be able
to switch the scanner off: every check runs in isolation, and a check that
fails or runs out of time becomes a `high` finding saying the scan is
incomplete, never a silent gap.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from findings import HIGH, MEDIUM, Finding, finding, hidden_chars
from repo_files import ATTACK, Unreadable, is_link, read_json, read_text, walk
from repo_git import check_git
from repo_settings import check_settings

INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")
AGENT_DOCS = (
    "CLAUDE.md",
    "AGENTS.md",
    "GEMINI.md",
    ".cursorrules",
    ".github/copilot-instructions.md",
    ".claude/CLAUDE.md",
)
AGENT_DOC_GLOBS = (
    ".claude/agents/*.md",
    ".claude/commands/*.md",
    ".claude/skills/*/SKILL.md",
    "skills/*/SKILL.md",
)
MAX_DOCS = 200
SCRIPT_SUFFIXES = (".mjs", ".cjs", ".js", ".ps1", ".sh", ".bat", ".cmd", ".exe")
DEADLINE_S = 15.0  # well under the 30 s hook timeout
# Whole-line `//` comments only: a lazy `/* ... */` search restarts at every
# unclosed `/*` and turns quadratic on a hostile file.
JSONC_COMMENT = re.compile(r"(?m)^[ \t]*//[^\n]*$")


def _unreadable(rel: str, exc: Unreadable) -> list[Finding]:
    return [finding(MEDIUM, rel, str(exc))]


def _claude_files(root: Path) -> tuple[list[Path], list[str]]:
    """Files at the top of `.claude/` and in its `hooks/` tree, without following links.

    `.claude/worktrees/` holds whole working copies, and a full walk drowns the
    signal, so other subfolders are left out.
    """
    base = root / ".claude"
    top = [p for p in base.iterdir() if not is_link(p) and p.is_file()]
    hooks = base / "hooks"
    if is_link(hooks):
        return top, [".claude/hooks is a link, not followed"]
    nested, notes = walk(hooks) if hooks.is_dir() else ([], [])
    return top + nested, notes


def check_claude_scripts(root: Path) -> list[Finding]:
    """Scripts inside `.claude/` run as hooks or status lines: read them before opening."""
    base = root / ".claude"
    if is_link(base):
        return [finding(HIGH, ".claude", "`.claude` is a link to somewhere else, not followed")]
    if not base.is_dir():
        return []
    files, notes = _claude_files(root)
    found = [finding(HIGH, ".claude", note) for note in notes]
    for path in sorted(files):
        if path.suffix.lower() in SCRIPT_SUFFIXES:  # Windows runs SETUP.MJS too
            found.append(
                finding(MEDIUM, path.relative_to(root).as_posix(), "script inside .claude/")
            )
    return found


def check_vscode(root: Path) -> list[Finding]:
    rel = ".vscode/tasks.json"
    try:
        text = read_text(root, rel)
    except Unreadable as exc:
        return _unreadable(rel, exc)
    code = JSONC_COMMENT.sub("", text or "")  # a commented-out task does not run
    if re.search(r'"runOn"[ \t]*:[ \t]*"folderOpen"', code):
        return [finding(HIGH, rel, "task with runOn: folderOpen runs when the folder opens")]
    return []


def check_mcp(root: Path) -> list[Finding]:
    try:
        data = read_json(root, ".mcp.json")
    except Unreadable as exc:
        return _unreadable(".mcp.json", exc)
    servers = data.get("mcpServers") if data else None
    if not isinstance(servers, dict):
        return []
    found = []
    for name, spec in servers.items():
        spec = spec if isinstance(spec, dict) else {}
        args = spec.get("args") if isinstance(spec.get("args"), list) else []
        run = " ".join([str(spec.get("command", "")), *(str(a) for a in args)]).strip()
        level = HIGH if ATTACK.search(run) else MEDIUM
        found.append(
            finding(level, ".mcp.json", f"MCP server {name}: {run or spec.get('url', '')}")
        )
    return found


def check_package(root: Path) -> list[Finding]:
    try:
        data = read_json(root, "package.json")
    except Unreadable as exc:
        return _unreadable("package.json", exc)
    scripts = data.get("scripts") if data else None
    if not isinstance(scripts, dict):
        return []
    found = []
    for name in INSTALL_SCRIPTS:
        run = scripts.get(name)
        if isinstance(run, str):
            level = HIGH if ATTACK.search(run) else MEDIUM
            found.append(finding(level, "package.json", f"{name} script: {run}"))
    return found


def agent_docs(root: Path) -> list[str]:
    """Documents an agent reads as instructions, relative to the root."""
    docs = list(AGENT_DOCS)
    for pattern in AGENT_DOC_GLOBS:
        docs += sorted(p.relative_to(root).as_posix() for p in root.glob(pattern))
    return docs[:MAX_DOCS]


def check_invisible(root: Path) -> list[Finding]:
    found = []
    for rel in agent_docs(root):
        try:
            text = read_text(root, rel)
        except Unreadable as exc:
            found += _unreadable(rel, exc)
            continue
        count = hidden_chars(text or "")
        if count:
            found.append(
                finding(HIGH, rel, f"{count} invisible character(s): hidden text for the agent")
            )
    return found


CHECKS = (
    check_settings,
    check_claude_scripts,
    check_vscode,
    check_mcp,
    check_package,
    check_invisible,
    check_git,
)


def scan(root: Path, deadline_s: float = DEADLINE_S) -> list[Finding]:
    """Every sign, `high` first. An empty list means nothing runs on open."""
    found: list[Finding] = []
    started = time.monotonic()
    for check in CHECKS:
        if time.monotonic() - started > deadline_s:
            found.append(
                finding(
                    HIGH, ".", f"time limit reached before {check.__name__}: scan is incomplete"
                )
            )
            break
        try:
            found += check(root)
        except Exception as exc:  # includes RecursionError and MemoryError
            found.append(
                finding(
                    HIGH,
                    ".",
                    f"{check.__name__} failed ({exc.__class__.__name__}): scan is incomplete",
                )
            )
    return sorted(found, key=lambda f: (f.level != HIGH, f.path))
