"""Which files are secrets: private keys, and files whose whole point is a credential.

Two different questions with two different answers:

* a private key must not reach the transcript at all, so reading one is
  stopped; it is recognised by name and, for a file that exists, by its first
  line (`~/.ssh/hetzner` is a key whatever it is called);
* `.env` and friends are read freely (the agent configures things with them),
  but must not be sent over the network.

Looking at a file is a stat and a 64-byte read on this machine only: a network
path (`//host/share`, `\\\\host\\share`) is never touched, because on Windows that
alone opens an SMB connection and offers the user's NTLM hash to the host.
"""

from __future__ import annotations

import glob
import itertools
import os
import re
from pathlib import Path

import _common as c

# No whitespace: `Authorization: Bearer abc_rsa` is a header, not a file name.
KEY_NAME = re.compile(
    r"id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?|\S+_(?:rsa|dsa|ecdsa|ed25519)|\S+\.(?:key|ppk|p12|pfx)"
    r"|ssh_host_\w+_key",
    re.I,
)
_BEGIN = rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
KEY_HEADER = re.compile(rb"(?:\xef\xbb\xbf)?\s*(?:" + _BEGIN + rb"|PuTTY-User-Key-File-)")
# A PEM bundle (`fullchain.pem`, a `.p12` export) may carry the key after a certificate.
BUNDLE_START = re.compile(rb"(?:\xef\xbb\xbf)?\s*(?:-----BEGIN |Bag Attributes)")
KEY_ANYWHERE = re.compile(rb"^" + _BEGIN, re.M)
HEADER_BYTES = 64
BUNDLE_BYTES = 16_384
MAX_HEADER_READS = 256
MAX_GLOB = 32
ENV_TEMPLATES = frozenset({"example", "sample", "template", "dist", "default", "defaults"})
CREDENTIAL_NAMES = frozenset(
    {".netrc", "_netrc", ".pgpass", ".git-credentials", ".envrc", ".npmrc", ".pypirc",
     ".vault-token"}
)  # fmt: skip
# Credential stores known by their folder: `~/.aws/credentials`, `~/.kube/config`.
CREDENTIAL_PATH = re.compile(
    r"(?:^|[\\/])(?:\.aws[\\/]credentials|\.kube[\\/]config|\.docker[\\/]config\.json"
    r"|gh[\\/]hosts\.yml)$",
    re.I,
)
# Where an argument names a file whose content is sent: curl `@file` and `<file`
# (`-d @.env`, `-F f=@.env;type=x`, `-F 'f=<.env'`), and a command substitution.
_ATTACHED = re.compile(r"[@<]([^\s;,\"'()`|<>@]+)")
SUBSTITUTED = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")
# An option with its value in the same word: `--post-file=.env`, PowerShell
# `-Path:key`, dd `if=key`, socat `FILE:.env`.
_INLINE_VALUE = re.compile(
    r"--?[\w-]*file=(\S+)|-[A-Za-z]+:(\S+)|if=(\S+)|(?:file|open|gopen|create):(\S+)", re.I
)
_ENV_VAR = re.compile(r"\$\{?env:(\w+)\}?", re.I)
# A path with spaces still starts like one: `./`, `~`, `/`, a drive letter.
_PATH_START = re.compile(r"\.{0,2}[\\/]|~|[A-Za-z]:[\\/]")
_BRACES = re.compile(r"\{([^{}]*,[^{}]*)\}")
MAX_BRACES = 16


def base_name(word: str) -> str:
    """Last path component, with either slash (`$env:USERPROFILE\\.ssh\\id_rsa`)."""
    return re.split(r"[\\/]", word.rstrip("\\/"))[-1]


def expand(word: str) -> str:
    """`$HOME`, `${HOME}`, `%USERPROFILE%` and PowerShell `$env:USERPROFILE` expanded."""
    word = _ENV_VAR.sub(lambda m: os.environ.get(m.group(1), m.group(0)), word)
    return os.path.expandvars(word)


def is_network_path(text: str) -> bool:
    return text.startswith(("//", "\\\\")) or "://" in text


def alternatives(word: str) -> list[str]:
    """`~/.ssh/{id_rsa,id_rsa.pub}` -> both words, as the shell expands it (one group, capped)."""
    m = _BRACES.search(word)
    if not m:
        return [word]
    head, tail = word[: m.start()], word[m.end() :]
    return [head + part + tail for part in m.group(1).split(",")[:MAX_BRACES]]


class _Budget:
    """File looks left for this command: a crafted command of 40 000 words must
    not push the hook past its timeout, which would let the command through."""

    left = MAX_HEADER_READS
    seen: dict[str, bool] = {}


def reset_budget() -> None:
    _Budget.left, _Budget.seen = MAX_HEADER_READS, {}


def _has_key_header(path: Path) -> bool:
    key = str(path)
    if key not in _Budget.seen:
        if _Budget.left <= 0 or is_network_path(key):
            return False
        _Budget.left -= 1
        _Budget.seen[key] = _read_header(path)
    return _Budget.seen[key]


def _read_header(path: Path) -> bool:
    try:
        if not path.is_file():
            return False  # a FIFO or a device would block the read
        with path.open("rb") as handle:
            head = handle.read(HEADER_BYTES)
            if KEY_HEADER.match(head):
                return True
            if not BUNDLE_START.match(head):
                return False
            return bool(KEY_ANYWHERE.search(head + handle.read(BUNDLE_BYTES)))
    except (OSError, ValueError):
        return False


def is_key_name(name: str) -> bool:
    """`id_ed25519`, `deploy_rsa`, `server.key`, `privkey.pem`; not `cert.pem` or `id_rsa.pub`."""
    lower = name.lower()
    if lower.endswith(".pem"):
        return not re.search(r"\s", lower) and ("key" in lower or "priv" in lower)
    return bool(KEY_NAME.fullmatch(name))


def is_env_name(name: str) -> bool:
    """`.env`, `.env.local`, `prod.env`; not `.env.example` and the other templates."""
    lower = name.lower()
    if lower.endswith(".env") and not re.search(r"\s", lower):
        return True
    return lower.startswith(".env.") and lower.rsplit(".", 1)[-1] not in ENV_TEMPLATES


def _paths(word: str, base: Path) -> list[Path]:
    """The files a word names: itself, or what a glob in it matches (`~/.ssh/*`)."""
    path = c.resolve_path(base, expand(word))
    if not re.search(r"[*?\[]", word) or is_network_path(str(path)) or _Budget.left <= 0:
        return [path]
    _Budget.left -= 1  # listing a folder costs like a read
    try:
        return [Path(p) for p in itertools.islice(glob.iglob(str(path)), MAX_GLOB)]
    except (OSError, ValueError):  # a NUL byte, a folder that cannot be listed
        return [path]


def is_private_key(word: str, base: Path) -> bool:
    """A private key by its name, or an existing file that starts like one.

    The name is checked even on a network share (`//host/keys/id_rsa`): that
    needs no file access. Only the look inside is skipped there.
    """
    if not word or word.startswith("-") or "://" in word:
        return False
    return any(_is_key(alt, base) for alt in alternatives(word))


def _is_key(word: str, base: Path) -> bool:
    if is_key_name(base_name(expand(word))):
        return True
    return any(is_key_name(p.name) or _has_key_header(p) for p in _paths(word, base))


def is_secret_file(word: str, base: Path) -> bool:
    """A file that must not leave the machine: `.env`, a private key, a credentials store."""
    if not word or word.startswith("-") or "://" in word:
        return False
    names = [expand(alt) for alt in alternatives(word)]
    for path in names + [str(p) for alt in alternatives(word) for p in _paths(alt, base)]:
        name = base_name(path)
        if is_env_name(name) or name.lower() in CREDENTIAL_NAMES:
            return True
        if CREDENTIAL_PATH.search(path.replace("\\", "/")):
            return True
    return is_private_key(word, base)


def option_values(word: str) -> list[str]:
    """The file named inside an option word: `--post-file=.env`, `-Path:key`, `if=key`."""
    m = _INLINE_VALUE.fullmatch(word)
    return [next(g for g in m.groups() if g)] if m else []


def pieces(word: str) -> list[str]:
    """Paths an argument hands over to be read: the word itself, `@file` and `<file`
    (curl's data and form syntax), and the words of a `$(...)` or backtick substitution.

    Text after `=` or inside a JSON body is not a file: `?f=.env` in a URL and
    `{"name": "foo.key"}` are sent as they are.
    """
    found = _ATTACHED.findall(word)
    inline = option_values(word)
    if inline:
        found += inline
    elif "=" not in word and (not re.search(r"\s", word) or _PATH_START.match(word)):
        # A path, maybe with spaces; not `a=b`, a header line or prose ending
        # in `config/.env` (a PR title, release notes). Unquoted
        # `` `cat .env` `` and `$(cat .env)` reach here split in two words.
        found.append(word.strip("`$()"))
    for m in SUBSTITUTED.finditer(word):
        found += (m.group(1) or m.group(2) or "").split()
    return found
