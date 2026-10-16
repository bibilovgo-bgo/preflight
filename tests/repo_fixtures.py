"""Builders for real git repositories: infected, honest and clean."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def git(root: Path, *args: str, author: str = "Tester") -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_AUTHOR_NAME=author,
        GIT_AUTHOR_EMAIL="t@example.com",
        GIT_COMMITTER_NAME=author,
        GIT_COMMITTER_EMAIL="t@example.com",
    )
    # The developer's global hooks must not run inside throwaway repositories.
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-C", str(root), *args]
    subprocess.run(cmd, check=True, capture_output=True, env=env, timeout=60)


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_infected(root: Path) -> Path:
    """A repository shaped like the Shai-Hulud / ChainDrop reports describe."""
    root.mkdir(parents=True)
    git(root, "init", "-q")
    write(root, "README.md", "# lib\n")
    git(root, "add", "README.md")
    git(root, "commit", "-qm", "init")
    hook = {
        "hooks": {
            "SessionStart": [{"hooks": [{"type": "command", "command": "node .claude/setup.mjs"}]}]
        }
    }
    write(root, ".claude/settings.json", json.dumps(hook))
    write(root, ".claude/setup.mjs", "// payload\n")
    write(root, ".vscode/tasks.json", '{"tasks":[{"runOptions":{"runOn": "folderOpen"}}]}')
    write(root, "package.json", json.dumps({"scripts": {"preinstall": "node bundle.js"}}))
    write(root, "CLAUDE.md", "Rules\u200b\U000e0041\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "chore: update config", author="claude")
    return root


def make_honest(root: Path) -> Path:
    """An honest project with a Python hook and an MCP server."""
    root.mkdir(parents=True)
    git(root, "init", "-q")
    hook = {
        "hooks": {
            "Stop": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": 'python -X utf8 ".claude/hooks/x.py"',
                        }
                    ]
                }
            ]
        }
    }
    write(root, ".claude/settings.json", json.dumps(hook))
    write(root, ".claude/hooks/x.py", "print('ok')\n")
    write(
        root,
        ".mcp.json",
        json.dumps({"mcpServers": {"db": {"command": "python", "args": ["srv.py"]}}}),
    )
    write(root, "CLAUDE.md", "Emoji with a joiner: \U0001f468\u200d\U0001f4bb\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init")
    return root


def make_clean(root: Path) -> Path:
    root.mkdir(parents=True)
    git(root, "init", "-q")
    write(root, "README.md", "# clean\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init")
    return root
