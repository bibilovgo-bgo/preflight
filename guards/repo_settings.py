"""What a repository's `.claude/settings*.json` makes Claude Code do on open."""

from __future__ import annotations

import json
import re
from pathlib import Path

from findings import HIGH, MEDIUM, Finding, finding
from repo_files import ATTACK, JS_RUNTIME, Unreadable, read_json

SETTINGS = (".claude/settings.json", ".claude/settings.local.json")
START_EVENTS = frozenset({"SessionStart", "Setup"})
LOCAL_URL = re.compile(r"^https?://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:/|$)", re.I)
# Settings keys Claude Code runs by itself, without any hook.
AUTO_RUN = ("statusLine", "otelHeadersHelper", "awsAuthRefresh", "awsCredentialExport")
PLUGIN_KEYS = ("enabledPlugins", "extraKnownMarketplaces", "enabledMcpjsonServers")
# Environment that redirects traffic or injects code into every child process.
HIJACK_ENV = re.compile(
    r"^(?:ANTHROPIC_\w*(?:BASE|API)_URL|NODE_OPTIONS|(?:HTTPS?|ALL)_PROXY|PYTHONSTARTUP"
    r"|LD_PRELOAD|DYLD_\w+|BASH_ENV|ENV)$",
    re.I,
)


def _hooks(settings: dict) -> list[tuple[str, str, str]]:
    """(event, type, command or url) of every hook; malformed structure is skipped."""
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return []
    found = []
    for event, groups in hooks.items():
        for group in groups if isinstance(groups, list) else []:
            inner = group.get("hooks") if isinstance(group, dict) else None
            for hook in inner if isinstance(inner, list) else []:
                if isinstance(hook, dict):
                    run = hook.get("command") or hook.get("url") or ""
                    found.append((str(event), str(hook.get("type", "")), str(run)))
    return found


def _hook_level(event: str, kind: str, run: str) -> str:
    """High: an HTTP hook to a remote host (it receives every tool call), a
    payload technique, or a JavaScript runtime started when the session starts
    (the worm's `SessionStart: node .claude/setup.mjs`)."""
    if kind == "http":
        return MEDIUM if LOCAL_URL.match(run) else HIGH
    if ATTACK.search(run) or (event in START_EVENTS and JS_RUNTIME.search(run)):
        return HIGH
    return MEDIUM


def _auto_run(rel: str, data: dict) -> list[Finding]:
    found = []
    for key in AUTO_RUN:
        value = data.get(key)
        if value is not None:
            run = value.get("command", value) if isinstance(value, dict) else value
            found.append(finding(HIGH if ATTACK.search(str(run)) else MEDIUM, rel, f"{key}: {run}"))
    if "apiKeyHelper" in data:
        found.append(finding(HIGH, rel, f"apiKeyHelper: {data['apiKeyHelper']}"))
    return found


def _env_and_permissions(rel: str, data: dict) -> list[Finding]:
    found = []
    env = data.get("env") if isinstance(data.get("env"), dict) else {}
    for key, value in env.items():
        if HIJACK_ENV.match(str(key)):
            found.append(finding(HIGH, rel, f"sets {key} = {value}"))
    if data.get("enableAllProjectMcpServers") is True:
        found.append(
            finding(HIGH, rel, "enableAllProjectMcpServers: starts every .mcp.json server unasked")
        )
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    if perms.get("defaultMode") == "bypassPermissions":
        found.append(finding(HIGH, rel, "permissions.defaultMode = bypassPermissions"))
    allow = perms.get("allow") if isinstance(perms.get("allow"), list) else []
    broad = [rule for rule in allow if re.fullmatch(r"(?:Bash|PowerShell)(?:\(\*\))?", str(rule))]
    if broad:
        found.append(
            finding(MEDIUM, rel, f"allows any shell command: {', '.join(map(str, broad))}")
        )
    return found


def settings_findings(rel: str, data: dict) -> list[Finding]:
    found = [
        finding(_hook_level(event, kind, run), rel, f"hook {event} ({kind or '?'}): {run}")
        for event, kind, run in _hooks(data)
    ]
    found += _auto_run(rel, data) + _env_and_permissions(rel, data)
    for key in PLUGIN_KEYS:
        if data.get(key):
            found.append(
                finding(MEDIUM, rel, f"{key}: {json.dumps(data[key], ensure_ascii=False)}")
            )
    return found


def check_settings(root: Path) -> list[Finding]:
    found = []
    for rel in SETTINGS:
        try:
            data = read_json(root, rel)
        except Unreadable as exc:
            found.append(finding(MEDIUM, rel, str(exc)))
            continue
        if data is not None:
            found += settings_findings(rel, data)
    return found
