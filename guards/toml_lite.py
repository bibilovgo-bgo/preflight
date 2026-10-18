"""TOML for Python 3.9 and 3.10, where the standard library has no `tomllib`.

Only what a check configuration uses: tables, arrays of tables, dotted and
quoted keys, the four string forms with their escapes, numbers, booleans,
arrays and inline tables. Dates stay text. Anything outside that grammar
raises ValueError, and the config guard lets the edit through. The tests run
the same documents through this reader and through `tomllib`.
"""

from __future__ import annotations

import re

_BARE = re.compile(r"[A-Za-z0-9_-]+")
# A datetime may carry one space (`1979-05-27 07:32:00`); everything else is one bare token.
_SCALAR = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}[0-9:.Zz+-]*|[0-9A-Za-z_:.+-]+")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}")
_LINE_END = re.compile(r"\\[ \t]*\n[ \t\n]*")
_ESCAPES = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}


def scalar(token: str) -> object:
    if token in ("true", "false"):
        return token == "true"
    plain = token.replace("_", "")
    try:
        return int(plain, 0)
    except ValueError:
        pass
    try:
        return float(plain)
    except ValueError:
        pass
    if _DATE.match(token):
        return token  # dates and times stay text: no rule compares them
    raise ValueError(f"toml: bare word {token!r}")


class TomlReader:
    """Recursive descent over the TOML grammar a check configuration uses."""

    def __init__(self, text: str) -> None:
        self.s = text.replace("\r\n", "\n")
        self.i = 0
        self.root: dict = {}

    def fail(self) -> None:
        raise ValueError(f"toml: unexpected text at offset {self.i}")

    def at(self, text: str) -> bool:
        return self.s.startswith(text, self.i)

    def skip_ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1

    def skip_blank(self) -> None:
        """Whitespace, newlines and comments."""
        while self.i < len(self.s):
            if self.s[self.i] in " \t\n":
                self.i += 1
            elif self.s[self.i] == "#":
                end = self.s.find("\n", self.i)
                self.i = len(self.s) if end < 0 else end
            else:
                return

    def document(self) -> dict:
        table = self.root
        while True:
            self.skip_blank()
            if self.i >= len(self.s):
                return self.root
            if self.at("[["):
                self.i += 2
                table = self.array_table(self.header("]]"))
            elif self.at("["):
                self.i += 1
                table = self.descend(self.root, self.header("]"))
            else:
                self.pair(table)
            self.skip_ws()
            if self.at("#"):
                self.skip_blank()
            elif self.i < len(self.s) and not self.at("\n"):
                self.fail()

    def header(self, closer: str) -> list:
        path = self.key()
        if not self.at(closer):
            self.fail()
        self.i += len(closer)
        return path

    def key(self) -> list:
        parts = []
        while True:
            self.skip_ws()
            if self.at('"'):
                parts.append(self.basic())
            elif self.at("'"):
                parts.append(self.literal())
            else:
                match = _BARE.match(self.s, self.i) or self.fail()
                parts.append(match.group())
                self.i = match.end()
            self.skip_ws()
            if not self.at("."):
                return parts
            self.i += 1

    def descend(self, table: dict, path: list) -> dict:
        for part in path:
            table = table.setdefault(part, {})
            if isinstance(table, list):
                table = table[-1]  # [a.b] after [[a]] continues the last entry
            if not isinstance(table, dict):
                self.fail()
        return table

    def array_table(self, path: list) -> dict:
        entries = self.descend(self.root, path[:-1]).setdefault(path[-1], [])
        if not isinstance(entries, list):
            self.fail()
        entries.append({})
        return entries[-1]

    def pair(self, table: dict) -> None:
        path = self.key()
        if not self.at("="):
            self.fail()
        self.i += 1
        self.skip_ws()
        self.descend(table, path[:-1])[path[-1]] = self.value()

    def value(self) -> object:
        for quote in ('"""', "'''"):
            if self.at(quote):
                return self.multiline(quote)
        if self.at('"'):
            return self.basic()
        if self.at("'"):
            return self.literal()
        if self.at("["):
            return self.array()
        if self.at("{"):
            return self.inline()
        match = _SCALAR.match(self.s, self.i) or self.fail()
        self.i = match.end()
        return scalar(match.group())

    def escape(self) -> str:
        code = self.s[self.i + 1 : self.i + 2]
        if code in _ESCAPES:
            self.i += 2
            return _ESCAPES[code]
        width = {"u": 4, "U": 8}.get(code) or self.fail()
        digits = self.s[self.i + 2 : self.i + 2 + width]
        if not re.fullmatch(rf"[0-9A-Fa-f]{{{width}}}", digits):
            self.fail()
        self.i += 2 + width
        return chr(int(digits, 16))

    def basic(self) -> str:
        self.i += 1
        out = []
        while not self.at('"'):
            if self.i >= len(self.s) or self.at("\n"):
                self.fail()
            if self.at("\\"):
                out.append(self.escape())
            else:
                out.append(self.s[self.i])
                self.i += 1
        self.i += 1
        return "".join(out)

    def literal(self) -> str:
        end = self.s.find("'", self.i + 1)
        newline = self.s.find("\n", self.i + 1)
        if end < 0 or 0 <= newline < end:
            self.fail()
        text, self.i = self.s[self.i + 1 : end], end + 1
        return text

    def multiline(self, quote: str) -> str:
        self.i += 3
        if self.at("\n"):
            self.i += 1
        out = []
        while not self.at(quote):
            if self.i >= len(self.s):
                self.fail()
            trim = _LINE_END.match(self.s, self.i) if quote == '"""' else None
            if trim:
                self.i = trim.end()
            elif quote == '"""' and self.at("\\"):
                out.append(self.escape())
            else:
                out.append(self.s[self.i])
                self.i += 1
        extra = 0
        while extra < 2 and self.s.startswith(quote[0], self.i + 3 + extra):
            extra += 1  # `""""` ends the string with one quote inside it
        self.i += 3 + extra
        return "".join(out) + quote[0] * extra

    def array(self) -> list:
        self.i += 1
        items = []
        while True:
            self.skip_blank()
            if self.at("]"):
                self.i += 1
                return items
            items.append(self.value())
            self.skip_blank()
            if self.at(","):
                self.i += 1
            elif not self.at("]"):
                self.fail()

    def inline(self) -> dict:
        self.i += 1
        table: dict = {}
        self.skip_ws()
        while not self.at("}"):
            self.pair(table)
            self.skip_ws()
            if self.at(","):
                self.i += 1
            elif not self.at("}"):
                self.fail()
        self.i += 1
        return table
