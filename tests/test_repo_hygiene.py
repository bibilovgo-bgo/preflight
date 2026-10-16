"""The repository holds itself to what its guards check in others."""

from __future__ import annotations

import json
import re
import unicodedata

import pytest

from conftest import GUARDS, ROOT

SOURCES = sorted(
    p
    for pattern in (
        "guards/*.py",
        "tests/*.py",
        "hooks/*",
        "commands/*.md",
        ".claude-plugin/*.json",
        "*.md",
        "*.toml",
    )
    for p in ROOT.glob(pattern)
    if p.is_file()
)


def invisible(text: str) -> list[str]:
    """Format, control and separator characters other than newline and tab.

    Trojan-source style text hides in exactly these; escapes like \\u200b in a
    string literal are fine, the raw character is not.
    """
    return [
        f"U+{ord(ch):04X}"
        for ch in text
        if ch not in "\n\t\r" and unicodedata.category(ch) in {"Cf", "Cc", "Zl", "Zp", "Co"}
    ]


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_no_invisible_characters(path):
    assert invisible(path.read_text(encoding="utf-8")) == []


def test_sources_were_found():
    assert len(SOURCES) > 10


def hook_commands() -> list[tuple[str, str, str]]:
    config = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    return [
        (event, group["matcher"], hook["command"])
        for event, groups in config["hooks"].items()
        for group in groups
        for hook in group["hooks"]
    ]


def test_every_hook_runs_an_existing_guard_through_the_launcher():
    for _event, _matcher, command in hook_commands():
        m = re.fullmatch(r'sh "\$\{CLAUDE_PLUGIN_ROOT\}/hooks/run\.sh" (\w+)', command)
        assert m, command
        assert (GUARDS / f"{m.group(1)}.py").is_file(), command


def test_every_guard_is_wired():
    wired = {command.rsplit(" ", 1)[1] for _e, _m, command in hook_commands()}
    assert wired == {
        "edit_guard",
        "safety_guard",
        "secret_scan",
        "browser_guard",
        "clone_scan",
    }


def test_launcher_is_checked_out_with_lf_everywhere():
    """With core.autocrlf on Windows, a CRLF run.sh breaks every hook under sh."""
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert "*.sh text eol=lf" in attributes
    assert b"\r" not in (ROOT / "hooks" / "run.sh").read_bytes()


def test_manifests_agree():
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert [p["name"] for p in market["plugins"]] == [plugin["name"]]
    assert f'version = "{plugin["version"]}"' in pyproject
    assert not plugin["name"].startswith(("claude", "anthropic"))
