"""What a secret looks like, and how added lines are read out of a diff.

Every pattern is linear in the line length, and long lines are scanned in
overlapping windows: one minified or generated line must not push the guard
past the hook timeout, because a timed-out guard lets the commit through.
"""

from __future__ import annotations

import re

from findings import clip

PRAGMA = "pragma: allowlist secret"
WINDOW, OVERLAP = 4000, 300

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    # OpenAI / OpenRouter / others: `sk-`, `sk-proj-`, `sk-or-v1-`. A digit is
    # required so kebab-case words like `sk-learn-...` stay out; the lookahead
    # is bounded so `sk-sk-sk-...` costs linear time.
    ("sk- API key", re.compile(r"\bsk-(?=[A-Za-z0-9_-]{0,200}\d)[A-Za-z0-9_-]{20,}")),
    (
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    ),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Groq key", re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{33,}")),
    # Publishable `pk_` keys are meant to ship in frontend code: not listed.
    ("Stripe secret key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("Stripe file link", re.compile(r"\bfl_live_[A-Za-z0-9]{12,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    (
        "private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"),
    ),
    (
        "password in a URL",
        re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@'\"]{1,100}:(?P<value>[^\s@/'\"]{6,100})@"),
    ),
    (
        "assigned secret",
        re.compile(
            # `NAME = "value"`, `NAME=value` (.env), `name: value` (YAML) and
            # `"name": "value"` (JSON). The name is matched inside an
            # identifier (`DB_PASSWORD`) without a leading `\w*`, which made
            # the pattern quadratic, and case-insensitively only there. The
            # value is taken from a secret-like alphabet and must end where
            # the token ends, so `token = get_token(user)` and
            # `TOKEN_URL = "https://..."` do not yield a value at all.
            r"""(?i:api[_-]?key|secret|token|passwd|password)\w{0,40}['"]?[ \t]*[:=][ \t]*['"]?"""
            r"""(?P<value>[A-Za-z0-9_\-+/=.~!@*^]{12,200})(?=['"\s,;#)}\]]|$)"""
        ),
    ),
]
# Labels whose captured value is judged before it counts as a secret.
JUDGED = frozenset({"password in a URL", "assigned secret"})
PLACEHOLDER = re.compile(
    r"your|example|sample|placeholder|changeme|change_me|dummy|redacted|here|fake|xxx|\*\*\*", re.I
)
FILLER = re.compile(r"([xX0*#.])\1{7,}")  # ghp_xxxxxxxx..., 00000000
# Files that are secrets by their name, whatever is inside.
SECRET_FILE = re.compile(
    r"(?:^|/)(?:\.env(?:\.(?!example|sample|template|dist|defaults?)[\w.-]+)?|id_(?:rsa|dsa|ecdsa|ed25519)"
    r"|[^/]+\.(?:pem|key|p12|pfx))$",
    re.I,
)


def looks_fake(value: str) -> bool:
    """A documented example or a placeholder rather than a real credential."""
    return value.endswith("EXAMPLE") or bool(PLACEHOLDER.search(value) or FILLER.search(value))


def plausible(value: str) -> bool:
    """A captured `name = value` value that could be a real credential.

    It needs both letters and digits (`bert-base-uncased`, `password_confirmation`
    are names, not secrets), must not be an env var name (`OPENAI_API_KEY`),
    a path or a module path.
    """
    if re.fullmatch(r"[A-Z0-9_]+", value) or value.startswith(("/", ".")):
        return False
    return bool(re.search(r"\d", value) and re.search(r"[A-Za-z]", value))


def added_lines(diff: str) -> list[tuple[str, str]]:
    """(file, line) for every added line not marked with the allowlist pragma.

    Lines are split on "\\n" only: `str.splitlines` also splits on `\\r`, form
    feeds and U+2028, and the rest of such a line would lose its leading "+"
    and be skipped with the secret in it. NUL bytes are dropped, which makes
    the ASCII text of a UTF-16 file readable.

    The `+++` header is only read before the first `@@` of a file: inside a
    hunk, an added line whose content starts with "++" looks like a header.
    """
    out: list[tuple[str, str]] = []
    in_hunk, current = False, ""
    for raw in diff.split("\n"):
        line = raw.removesuffix("\r").replace("\x00", "")
        if line.startswith("diff --git "):
            in_hunk, current = False, ""
        elif not in_hunk and line.startswith("+++ "):
            current = line[4:].removeprefix("b/")
        elif line.startswith("@@"):
            in_hunk = True
        elif in_hunk and line.startswith("+") and PRAGMA not in line:
            out.append((current, line[1:]))
    return out


def windows(line: str) -> list[str]:
    """The line itself, or overlapping slices of it when it is very long."""
    if len(line) <= WINDOW:
        return [line]
    step = WINDOW - OVERLAP
    return [line[i : i + WINDOW] for i in range(0, len(line) - OVERLAP, step)]


def mask(value: str) -> str:
    return value[:4] + "..." + f"({len(value)} chars)"


def _counts(label: str, m: re.Match) -> bool:
    value = m.group("value") if label in JUDGED else m.group(0)
    if looks_fake(value):
        return False
    return plausible(value) if label in JUDGED else True


def first_match(line: str) -> tuple[str, str] | None:
    """(label, matched text) of the first real-looking secret in the line."""
    for part in windows(line):
        for label, pattern in PATTERNS:
            for m in pattern.finditer(part):
                if _counts(label, m):
                    return label, m.group(0)
    return None


def find_secrets(diff: str) -> list[str]:
    """Masked hits: one per added line carrying a secret, one per secret file."""
    hits, files = [], {}
    for path, line in added_lines(diff):
        files.setdefault(path, None)
        found = first_match(line)
        if found:
            label, value = found
            hits.append(f"{clip(path or '?', 200)}: {label} {mask(value)}")
    for path in files:
        if SECRET_FILE.search(path):
            hits.append(f"{clip(path, 200)}: a file that holds secrets by its name")
    return hits
