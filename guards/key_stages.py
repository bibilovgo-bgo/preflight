"""One stage of a pipeline, as the key guard sees it: does it print a key,
does it talk to the network, which files does it read and pass on.
"""

from __future__ import annotations

import re
from pathlib import Path

import secret_files as sf
import shell_words as sw
from shell_pipes import Simple

READERS = frozenset(
    {"cat", "tac", "nl", "type", "more", "less", "head", "tail", "bat", "batcat",
     "xxd", "od", "hexdump", "base64", "base32", "strings", "sed", "awk", "grep",
     "egrep", "fgrep", "rg", "cut", "findstr", "gc", "get-content", "select-string",
     "sls", "sort", "uniq", "rev", "fold", "paste", "pr", "column", "diff", "cmp",
     "jq", "yq", "dd"}
)  # fmt: skip
# Readers whose first operand is a search pattern or a script, not a file.
PATTERN_READERS = frozenset(
    {"grep", "egrep", "fgrep", "rg", "sed", "awk", "findstr", "select-string", "sls", "jq"}
)
# Options that take the pattern or script instead (lowercase, PowerShell included).
PATTERN_OPTS = frozenset({"-e", "--regexp", "--expression", "-f", "--file", "-pattern"})
# Other options of those readers that take the next word: in `rg -g '*.py' id_rsa`
# the pattern is `id_rsa`, not `*.py`.
READER_VALUE_OPTS = {
    "grep": frozenset("-A -B -C -m -d -D --max-count --context --after-context "
                      "--before-context --include --exclude --exclude-dir --label".split()),
    "rg": frozenset("-A -B -C -m -g -t -T -M -j -E --glob --iglob --type --type-not "
                    "--max-count --context --after-context --before-context --max-columns "
                    "--threads --encoding --max-depth".split()),
    "awk": frozenset({"-v", "-F"}),
    "sed": frozenset({"-l"}),
}  # fmt: skip
READER_VALUE_OPTS["egrep"] = READER_VALUE_OPTS["fgrep"] = READER_VALUE_OPTS["grep"]
# A positional word that is an address without a scheme: `localhost:8000/.env`.
HOST_PATH = re.compile(r"(?:localhost|\d+(?:\.\d+){3}|[\w-]+(?:\.[\w-]+)+)(?::\d+)?/")
SENDERS = frozenset(
    {"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "http", "https",
     "xh", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"}
)  # fmt: skip
# `gh gist create .env` publishes the file; `gh issue create --body-file .env` posts it.
GH_SENDS = frozenset({"gist", "api", "issue", "pr", "release"})
NET_DEVICES = ("/dev/tcp/", "/dev/udp/")
TERMINALS = frozenset({"/dev/stdout", "/dev/stderr", "/dev/tty", "con"})
# Options whose value is not sent: where a download is saved, or a key used locally (mTLS).
KEEP_OPTS = frozenset(
    {"-o", "-O", "--output", "--output-document", "--key", "--cert", "--cacert", "-E",
     "--proxy-key", "--proxy-cert"}
)  # fmt: skip
SHORT_OUTPUT = re.compile(r"-[A-Za-z]*[oO]")  # `curl -sSLo`, `wget -qO`
INLINE_OUTPUT = re.compile(r"--output(?:-document)?=\S*|-outfile:\S*", re.I)


def name(words: list[str]) -> str:
    return sw.command_name(words[0]) if words else ""


def operands(words: list[str]) -> list[str]:
    """File operands of a reader: options dropped, `-Path:key` and `if=key` unwrapped,
    and the search pattern of grep, sed or awk skipped (`grep -rn id_rsa .` reads no key)."""
    pattern_first = name(words) in PATTERN_READERS
    pattern_first = pattern_first and not any(w.lower() in PATTERN_OPTS for w in words)
    takes_value = PATTERN_OPTS | READER_VALUE_OPTS.get(name(words), frozenset())
    out, skip = [], False
    for word in words[1:]:
        if skip or word.lower() in takes_value or word in takes_value:
            skip = not skip
        elif sf.option_values(word):
            out += sf.option_values(word)
        elif not word.startswith("-"):
            if not pattern_first:
                out.append(word)
            pattern_first = False
    return out


def shown_key(stage: Simple, base: Path) -> str:
    """The private key the stage would print, or an empty string.

    A reader prints its operands; `cp key /dev/stdout` and `$(<key)` (a stage
    that is only an input redirection) do too.
    """
    stage_name = name(stage.words)
    if stage_name in READERS or not stage.words:
        files = operands(stage.words) + stage.inputs
    elif stage_name == "cp" and stage.words[-1].lower() in TERMINALS:
        files = stage.words[1:-1]
    else:
        return ""
    return next((w for w in files if sf.is_private_key(w, base)), "")


def is_sender(stage: Simple) -> bool:
    """The stage talks to the network: curl and friends, `gh gist`, `> /dev/tcp/h/9`."""
    stage_name = name(stage.words)
    if stage_name in SENDERS:
        return True
    if stage_name == "gh" and set(stage.words[1:2]) & GH_SENDS:
        return True
    return any(out.startswith(NET_DEVICES) for out in stage.outputs)


def _skips_next(word: str) -> bool:
    return word in KEEP_OPTS or word.lower() == "-outfile" or bool(SHORT_OUTPUT.fullmatch(word))


def args(words: list[str]) -> list[str]:
    """Arguments of a command, minus what is not sent: the file a download is saved
    into (`curl -sSLo .env`, `wget --output-document=.env`) and a local TLS key."""
    out, skip = [], False
    for word in words[1:]:
        if skip:
            skip = False
        elif _skips_next(word):
            skip = True
        elif not INLINE_OUTPUT.fullmatch(word):
            out.append(word)
    return out


def candidates(stage: Simple) -> list[str]:
    """Paths one pipeline stage may read and pass on.

    Every stage counts, not only the known readers: `tar czf - .env | curl -T -`
    and `gzip -c .env | nc host 9` send the file just the same.
    """
    words = args(stage.words)
    if name(stage.words) == "gh" and stage.words[1:2] == ["api"]:
        words = words[1:]  # the endpoint `repos/o/r/contents/.env` is not a file
    if name(stage.words) in SENDERS:
        words = [w for w in words if not HOST_PATH.match(w)]  # `curl localhost:8000/.env`
    return [p for w in words + stage.inputs for p in sf.pieces(w)]


def dumps_env(raw: list[str]) -> bool:
    """`env`, `printenv`, `set`, `export -p`, PowerShell `gci env:`: every variable, keys included."""
    stage_name = name(raw)
    plain = [w for w in raw[1:] if not w.startswith("-")]
    if stage_name == "set":
        return len(raw) == 1  # `set -e` sets an option, bare `set` lists every variable
    if stage_name in ("env", "printenv", "export", "declare") and not plain:
        return True
    listers = ("gci", "get-childitem", "dir", "ls")
    return stage_name in listers and any(w.lower().startswith("env:") for w in raw[1:])
