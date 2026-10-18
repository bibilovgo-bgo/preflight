"""PreToolUse on Edit, Write and MultiEdit: no weakening of a check's configuration.

An agent whose lint or test run fails has two ways to make it pass: fix the
code, or edit the configuration of the check. The second is quicker and
almost always wrong: a code added to `ignore`, a test path dropped from
`testpaths`, `continue-on-error: true` on the CI step, a `skip` in
`conftest.py`. This guard reads the file as it is on disk and as it would be
after the edit, compares the two (`config_formats.py` reads TOML, INI and
JSON, `config_rules.py` holds the rules) and blocks the edit when a check got
weaker. Tightening a check, creating a new configuration file and any edit the
guard cannot read pass untouched.

Files: pyproject.toml, ruff.toml, setup.cfg, .flake8, pytest.ini, tox.ini,
mypy.ini, .coveragerc, .pylintrc, pyrightconfig.json, conftest.py (also under
tests/), .pre-commit-config.yaml and .github/workflows/*.yml. The names come
from `fact_classes.CONFIG_NAMES`, where the facts gate asks its questions.

There is no bypass marker (it would land in the file) and no cap on denials:
the block is a fact about the edit, not a question. Only the user lifts it:
PREFLIGHT_CONFIG=0, or PREFLIGHT_CONFIG_EXEMPT (file globs separated by `;`).
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

import _common as c
import config_formats as cf
import config_rules as cr
import config_text as ct
import fact_classes as fc

GUARD = "config"
MAX_BYTES = 1 << 20  # a check configuration is kilobytes; more would only risk the hook timeout
BOM = chr(0xFEFF)
MAX_FINDINGS = 20
MAX_FINDING = 160
_CONTROL = re.compile("[\\x00-\\x1f\\x7f" + "".join(map(chr, (0x85, 0x2028, 0x2029))) + "]")
# What `readlink` returns for a share on Windows: `\??\UNC\host\share`, `\\?\UNC\...`.
_UNC = re.compile(r"(?i)^[\\/]{2}[?.][\\/]unc[\\/]|^\\\?\?\\unc\\")
TOOLS = frozenset({"Edit", "Write", "MultiEdit"})
PRECOMMIT = frozenset({".pre-commit-config.yaml", ".pre-commit-config.yml"})
HINT = (
    "Fix the code the check fails on, or say in the commit why the rule is wrong and ask the "
    "user to allow the change: PREFLIGHT_CONFIG_EXEMPT=<file glob> or PREFLIGHT_CONFIG=0."
)


def kind_of(rel: str) -> str:
    """How the file is compared: a format name from `config_formats`, a text kind, or ""."""
    name = rel.rsplit("/", 1)[-1]
    if name in cf.FORMATS:
        return name
    if name == "conftest.py":
        return "conftest"
    if name in PRECOMMIT:
        return "precommit"
    workflow = "/" + fc.WORKFLOW_DIR in "/" + rel
    return "workflow" if workflow and name.endswith((".yml", ".yaml")) else ""


class Oversize(Exception):
    """The file, before or after the edit, is too large to judge in the hook's time."""


def read_text(path: Path) -> str | None:
    """The file as text; None when it is missing or not a regular file (a FIFO would hang)."""
    try:
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size > MAX_BYTES:
            raise Oversize
        with open(path, "rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except (OSError, ValueError):  # a NUL byte, a path too long for the platform
        return None
    return normal(data.decode("utf-8", errors="replace"))


def _network_target(target: str) -> bool:
    return fc.sf.is_network_path(target) or bool(_UNC.match(target))


def through_network_link(path: Path) -> bool:
    """A symlink on the way to the file that points at a share: opening the file would follow
    it and make Windows offer the user's NTLM hash. `islink` and `readlink` read only the link
    itself; any doubt counts as a share."""
    try:
        absolute = Path(os.path.abspath(path))
        for part in [*reversed(absolute.parents), absolute]:
            probe = str(part)
            for _ in range(8):  # a chain of links, bounded
                if not os.path.islink(probe):
                    break
                target = os.readlink(probe)
                if _network_target(target):
                    return True
                probe = os.path.join(os.path.dirname(probe), target)
    except (OSError, ValueError):
        return True
    return False


def normal(text: str) -> str:
    """LF line ends and no byte-order mark: both would otherwise make a file unparsable."""
    return text.replace("\r\n", "\n").removeprefix(BOM)


def edited(before: str, tool_name: str, tool_input: dict) -> str | None:
    """The file after the edit; None when the edit would not apply as given or is too large."""
    if tool_name == "Write":
        content = tool_input.get("content")
        if isinstance(content, str) and len(content) > MAX_BYTES:
            raise Oversize
        return normal(content) if isinstance(content, str) else None
    edits = tool_input.get("edits") if tool_name == "MultiEdit" else [tool_input]
    if not isinstance(edits, list):
        return None
    text = before
    for edit in edits:
        if not isinstance(edit, dict):
            return None
        old, new = edit.get("old_string"), edit.get("new_string")
        if not isinstance(old, str) or not isinstance(new, str) or not old:
            return None
        old, new = old.replace("\r\n", "\n"), new.replace("\r\n", "\n")
        every = edit.get("replace_all") is True
        times = text.count(old) if every else int(old in text)
        if not times:
            return None
        if len(text) + times * (len(new) - len(old)) > MAX_BYTES:
            raise Oversize  # measured before replacing: a 4 KB `replace_all` can need gigabytes
        text = text.replace(old, new) if every else text.replace(old, new, 1)
    return text


def judge(kind: str, before: str, after: str) -> list:
    if kind == "conftest":
        return ct.conftest_findings(before, after)
    if kind in ("workflow", "precommit"):
        return ct.line_findings(kind, before, after)
    old, new = cf.parse(kind, before), cf.parse(kind, after)
    if old is None:
        return []  # a file the guard cannot read is not a file it can judge
    if new is None:
        # Breaking the file first would let the next edit weaken it unseen.
        return [
            f"{kind}: the edit leaves the file unparsable, and the checks would stop reading it"
        ]
    return cr.weakened(old, new)


def tidy(found: list) -> list:
    """Findings as the model will read them: text from the file can carry newlines and control
    characters that fake a line of the message, and can be long; cut both."""
    lines = [_CONTROL.sub("?", f) for f in found[:MAX_FINDINGS]]
    lines = [f if len(f) <= MAX_FINDING else f[: MAX_FINDING - 3] + "..." for f in lines]
    more = len(found) - MAX_FINDINGS
    return lines + ([f"... and {more} more"] if more > 0 else [])


def decide(payload: dict, tool_name: str, tool_input: dict) -> tuple[list, str]:
    """The weakenings an edit makes, and the file's project-relative path."""
    path = tool_input.get("file_path")
    if tool_name not in TOOLS or not isinstance(path, str) or not path:
        return [], ""
    root = c.base_dir(payload)
    cleaned = fc._clean(path)
    rel = fc._strip_worktree(fc._relative(cleaned, root), root)
    kind = kind_of(rel)
    if not kind or fc.matches_globs(rel, fc.exempt_globs("PREFLIGHT_CONFIG_EXEMPT")):
        return [], rel
    if fc.is_network(path, cleaned, root) or through_network_link(root / cleaned):
        return [], rel  # never open it: Windows would hand the host an NTLM hash
    try:
        before = read_text(root / cleaned)
        if before is None:
            return [], rel  # a new file has nothing to weaken
        after = edited(before, tool_name, tool_input)
    except Oversize:
        return [f"{kind}: over {MAX_BYTES >> 20} MiB, too large to check; ask the user"], rel
    if after is None or after == before:
        return [], rel
    return judge(kind, before, after), rel


def main() -> int:
    if c.off_switch(GUARD):
        return 0
    payload = c.read_payload()
    found, rel = decide(payload, str(payload.get("tool_name") or ""), c.tool_input(payload))
    if not found:
        return 0
    # Rule labels only: the last key, never a module or hook name taken from the file.
    rules = sorted({f.split(":")[0].rsplit(".", 1)[-1] for f in found})
    c.log(GUARD, {"verdict": "block", "file": rel, "rules": rules})
    return c.block(f"preflight config: this edit weakens a check ({rel})", tidy(found), HINT)


if __name__ == "__main__":
    c.run(GUARD, main)
