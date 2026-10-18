"""Does a tool call count as having searched the tree for a file?

Reading the file never counts: Claude Code already reads a file before it
edits it, so a Read proves nothing beyond that. A search does: `Grep`,
`Glob`, or a shell command led by `rg`, `grep`, `git grep`, `git ls-files`,
`find`, `fd`, `findstr` or `Select-String`, also inside `bash -c '...'` and
behind `git -C dir`. The file's stem (its name without the last extension)
must appear as a whole word in what was searched for, or the symbol being
edited when the stem is generic, or the folder name when there is neither.
A search restricted to other file names (`rg -g '*.js'` for a `.py` file),
excluding the file, or confined to the file's own name (`Glob **/charge.py`
finds only the file) is not a search for it.

Deliberately small. Scope by path operands and the full type grammar of
every tool are left out; a search anywhere in the project for the right
word is credited.
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import NamedTuple

import git_commands as gc
import secret_files as sf
import shell_pipes as sp
import shell_words as sw
import wrappers

SHELL_TOOLS = frozenset({"Bash", "PowerShell"})
SEARCHERS = frozenset("rg grep egrep fgrep find fd fdfind findstr select-string sls".split())
GIT_SEARCHERS = frozenset({"grep", "ls-files"})
# A stage that lists the tree feeds a piped search with file names, not with text.
LISTERS = frozenset("get-childitem gci ls dir find fd fdfind".split())
MAX_COMMAND = 8192
MAX_DEPTH = 3
_SUBSTITUTION = re.compile(r"\$\(|`|<\(|>\(|<<")
# Per tool: option -> what its value means. "glob" restricts to file names, "type" to
# `*.<ext>`, "not" excludes names, "skip" is a value that is neither (a pattern, a count).
_GREP = {"--include": "glob", "--exclude": "not", "--exclude-dir": "not"}
_GREP.update(dict.fromkeys("-e --regexp -f --file -m --max-count -A -B -C -d".split(), "skip"))
_RG = {"-g": "glob", "--glob": "glob", "--iglob": "glob", "-t": "type", "--type": "type",
       "-T": "type-not", "--type-not": "type-not"}  # fmt: skip
_RG.update(dict.fromkeys("-e --regexp -f --file -m --max-count -A -B -C -j --threads "
                         "-E --encoding --pre --context -d --max-depth".split(), "skip"))  # fmt: skip
_FIND = {"-name": "glob", "-iname": "glob"}
_FIND.update(
    dict.fromkeys("-maxdepth -mindepth -type -newer -size -user -path -ipath".split(), "skip")
)
_FD = {"-e": "type", "--extension": "type", "-E": "not", "--exclude": "not"}
_FD.update(dict.fromkeys("-d --max-depth -j --threads -x --exec -X --exec-batch".split(), "skip"))
_PS = {"-include": "glob", "-filter": "glob", "-exclude": "not"}
_PS.update(dict.fromkeys("-pattern -path -literalpath -context -encoding".split(), "skip"))
_OPTIONS = {
    "grep": _GREP, "egrep": _GREP, "fgrep": _GREP, "git grep": _GREP, "git ls-files": {},
    "rg": _RG, "find": _FIND, "fd": _FD, "fdfind": _FD, "findstr": {},
    "select-string": _PS, "sls": _PS,
}  # fmt: skip
_CASE_SENSITIVE = frozenset(
    {"-t", "-T", "-e", "-E", "-A", "-B", "-C", "-d", "-j", "-m", "-f", "-g"}
)


class Search(NamedTuple):
    label: str  # how the credit is described: "Grep 'charge'"
    text: str  # where the word must appear
    restrict: list[str]  # file-name globs the search was limited to
    exclude: list[str]  # file-name globs or words the search left out
    lookup: bool  # confined to one file name: a look, not a search


def searches(name: str, tool_input: dict) -> list[Search]:
    """The searches one tool call performed; [] when it is not a search."""
    if name == "Grep":
        pattern = str(tool_input.get("pattern") or "")
        globs = _globs(str(tool_input.get("glob") or ""))
        kinds = [str(tool_input.get("type"))] if tool_input.get("type") else []
        restrict = [g for g in globs if not g.startswith("!")] + [f"*.{k}" for k in kinds]
        exclude = [g[1:] for g in globs if g.startswith("!")]
        lookup = bool(restrict) and all(_is_one_name(g) for g in restrict)
        return [Search(f"Grep '{pattern}'", pattern, restrict, exclude, lookup)]
    if name == "Glob":
        pattern = str(tool_input.get("pattern") or "")
        return [Search(f"Glob '{pattern}'", pattern, [], [], _is_one_name(pattern))]
    if name in SHELL_TOOLS:
        return shell_searches(str(tool_input.get("command") or ""), name == "PowerShell")
    return []


def _globs(raw: str) -> list[str]:
    """Comma-separated globs; a comma inside braces separates alternatives, not globs."""
    parts, depth, current = [], 0, ""
    for char in raw:
        depth += (char == "{") - (char == "}" and depth > 0)
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    return [alt for part in parts if part.strip() for alt in sf.alternatives(part.strip())]


def _is_one_name(glob: str) -> bool:
    """`**/charge.py`, `charge.py`, `src/charge.py`: the last segment names one file."""
    last = glob.replace("\\", "/").rsplit("/", 1)[-1]
    return bool(last) and not re.search(r"[*?\[{]", last)


def shell_searches(command: str, powershell: bool, depth: int = 0) -> list[Search]:
    """Search commands in a shell call, one Search per searching stage.

    A stage that reads stdin (`grep x < file`, `cat f | grep x`) searched no
    tree, unless the stage before it listed the tree (`gci -r | sls x`).
    Commands with substitutions or heredocs are not read at all.
    """
    if len(command) > MAX_COMMAND or _SUBSTITUTION.search(command) or depth >= MAX_DEPTH:
        return []
    groups = sp.pipelines(command, powershell)
    if groups is None:
        return []
    found: list[Search] = []
    for group in groups:
        for index, stage in enumerate(group):
            words = sw.command_head(stage.words)[1]
            inner = wrappers.inner_command(words)
            fed = bool(stage.inputs) or (index > 0 and not _lists_tree(group[index - 1].words))
            if inner is not None:
                found += shell_searches(inner[0], inner[1], depth + 1)
            elif search := _stage_search(words, piped=fed):
                found.append(search)
    return found


def _lists_tree(words: list[str]) -> bool:
    words = sw.command_head(words)[1]
    git = gc.git_subcommand(words, Path("."))
    if git is not None:
        return git[0].lower() == "ls-files"
    return bool(words) and sw.command_name(words[0]) in LISTERS


def _stage_search(words: list[str], piped: bool) -> Search | None:
    if not words:
        return None
    name = sw.command_name(words[0])
    git = gc.git_subcommand(words, Path("."))
    if git is not None and git[0].lower() in GIT_SEARCHERS:
        name, args = "git " + git[0].lower(), git[1]
    elif name in SEARCHERS:
        args = words[1:]
    else:
        return None
    restrict, exclude, operands = _options(name, args)
    if piped and not operands:
        return None  # it read stdin, not the tree
    text = " ".join(args)
    return Search(f"{name} '{text[:60]}'", text, restrict, exclude, False)


def _split_option(word: str, table: dict) -> tuple[str, bool, str]:
    """(key, has a value in the word, value): `--include=*.py`, `-g*.js`, `-g`."""
    key, inline, value = word.partition("=")
    if not inline and len(word) > 2 and word[0] == "-" and word[1] != "-" and word[:2] in table:
        return word[:2], True, word[2:]  # a short option with its value glued on
    if key not in _CASE_SENSITIVE:
        key = key.lower()
    return key, bool(inline), value


def _options(name: str, args: list[str]) -> tuple[list[str], list[str], list[str]]:
    """(file-name restrictions, exclusions, path operands) of a search command's arguments.

    The first operand is the pattern (`grep charge src`), except for `find`
    and `git ls-files`, whose operands are all paths.
    """
    table = _OPTIONS[name]
    restrict: list[str] = []
    exclude: list[str] = []
    operands: list[str] = []
    skip = False
    for index, word in enumerate(args):
        if skip:
            skip = False
            continue
        key, inline, value = _split_option(word, table)
        if not inline:
            value = args[index + 1] if index + 1 < len(args) else ""
        meaning = table.get(key)
        if meaning:
            skip = not inline
            _record(meaning, value, restrict, exclude)
        elif name == "git grep" and word.startswith((":!", ":^", ":(exclude)")):
            exclude.append(word.split(")")[-1].lstrip(":!^"))
        elif not word.startswith("-"):
            operands.append(word)
    return restrict, exclude, operands if name in ("find", "git ls-files") else operands[1:]


def _record(meaning: str, value: str, restrict: list[str], exclude: list[str]) -> None:
    if meaning == "glob":
        (exclude if value.startswith("!") else restrict).append(value.lstrip("!"))
    elif meaning == "type":
        restrict.append(f"*.{value}")
    elif meaning == "type-not":
        exclude.append(f"*.{value}")
    elif meaning == "not":
        exclude.append(value)


def mentions(text: str, word: str) -> bool:
    """`word` as a whole word of `text`: `payment` in `payment_service`, not in `payments`."""
    if not word:
        return False
    return (
        re.search(r"(?<![A-Za-z0-9])" + re.escape(word) + r"(?![A-Za-z0-9])", text, re.I)
        is not None
    )


def credits(search: Search, words: list[str], file_name: str) -> bool:
    """Whether the search counts for a file: it looked for one of `words` and
    could have found `file_name`."""
    if search.lookup or not any(mentions(search.text, w) for w in words):
        return False
    low = file_name.lower()
    if search.restrict and not any(fnmatch.fnmatchcase(low, g.lower()) for g in search.restrict):
        return False
    for left_out in search.exclude:
        if fnmatch.fnmatchcase(low, left_out.lower()) or any(mentions(left_out, w) for w in words):
            return False
    return True


def crediting_label(calls, words: list[str], file_name: str, batch: str) -> str:
    """The first completed call of the turn that credits the file, as a label; "" if none.

    Calls sent in the same assistant message as the gated edit (`batch`) are
    skipped: their results were not seen when the edit was decided.
    """
    words = [w for w in words if w]
    for call in calls:
        if batch and call.batch == batch:
            continue
        for search in searches(call.name, call.input):
            if credits(search, words, os.path.basename(file_name)):
                return search.label
    return ""
