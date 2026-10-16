"""A finding of the repository scanner, and how its text is made safe to show.

Everything inside a finding (an MCP server name, a hook command, a path) was
written by whoever controls the repository, and the guard hands it to the
model as trusted hook context. A `.mcp.json` key with embedded newlines could
otherwise forge a line like "[SYSTEM] scan clean" inside that context. So every
string goes through `clip`: control and invisible characters become spaces,
and the length is capped.

The character sets are built from code point ranges so that this source file
itself stays free of invisible characters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

HIGH, MEDIUM = "high", "medium"
CLIP = 160


def _char_class(ranges: list[tuple[int, int]]) -> re.Pattern[str]:
    return re.compile(
        "[" + "".join(re.escape(chr(a)) + "-" + re.escape(chr(b)) for a, b in ranges) + "]"
    )


# Characters that render as nothing (or as blank) and are used to hide text
# from a human reviewer while an agent still reads it.
INVISIBLE = _char_class(
    [
        (0x00AD, 0x00AD),  # soft hyphen
        (0x034F, 0x034F),  # combining grapheme joiner
        (0x061C, 0x061C),  # Arabic letter mark
        (0x115F, 0x1160),  # Hangul fillers
        (0x17B4, 0x17B5),  # Khmer inherent vowels
        (0x180B, 0x180F),  # Mongolian selectors and vowel separator
        (0x200B, 0x200C),  # zero width space, non-joiner (U+200D is left out: emoji)
        (0x200E, 0x200F),  # direction marks
        (0x202A, 0x202E),  # bidi embeddings and overrides
        (0x2060, 0x206F),  # word joiner, invisible operators, isolates, deprecated
        (0x2800, 0x2800),  # braille blank
        (0x3164, 0x3164),  # Hangul filler
        (0xFE00, 0xFE0D),  # variation selectors (FE0E/FE0F are text/emoji style)
        (0xFEFF, 0xFEFF),  # BOM in the middle of text
        (0xFFA0, 0xFFA0),  # halfwidth Hangul filler
        (0xE0000, 0xE007F),  # tag characters
        (0xE0100, 0xE01EF),  # variation selectors supplement
    ]
)
# Subdivision flags (England, Scotland, Wales) are U+1F3F4 + tag characters +
# U+E007F and are legitimate.
FLAG_SEQUENCE = re.compile(
    chr(0x1F3F4) + _char_class([(0xE0020, 0xE007E)]).pattern + "+" + chr(0xE007F)
)
RTL_LETTER = _char_class([(0x0590, 0x08FF), (0xFB1D, 0xFDFF), (0xFE70, 0xFEFC)])
RTL_MARKS = _char_class([(0x061C, 0x061C), (0x200C, 0x200C), (0x200E, 0x200F)])
# C0 and C1 controls (C1 includes terminal CSI/OSC introducers), line and
# paragraph separators.
CONTROL = _char_class([(0x00, 0x1F), (0x7F, 0x9F), (0x2028, 0x2029)])


@dataclass(frozen=True)
class Finding:
    level: str
    path: str  # relative to the repository root
    what: str


def clip(text: object, limit: int = CLIP) -> str:
    """Untrusted text -> one visible line no longer than `limit`."""
    flat = INVISIBLE.sub(" ", CONTROL.sub(" ", str(text)))
    flat = re.sub(r" {2,}", " ", flat).strip()
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def finding(level: str, path: str, what: str) -> Finding:
    return Finding(level, clip(path, 120), clip(what))


def hidden_chars(text: str) -> int:
    """Invisible characters in the text, not counting legitimate uses.

    Subdivision flags are legitimate, and so are direction marks and the
    zero width non-joiner in Arabic, Persian or Hebrew text, where they are
    part of ordinary spelling.
    """
    text = FLAG_SEQUENCE.sub("", text)
    # The marks sit inside the Arabic block themselves: look for letters without them.
    if RTL_LETTER.search(RTL_MARKS.sub("", text)):
        text = RTL_MARKS.sub("", text)
    return len(INVISIBLE.findall(text))
