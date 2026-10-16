#!/bin/sh
# Run one preflight guard with whatever Python 3.9+ this machine has.
#
# There is no interpreter name that works everywhere: many Linux and macOS
# machines have only `python3`, and on Windows `python3` is often the
# Microsoft Store stub, which prints an install hint and fails. So the first
# working candidate is found once and remembered in the plugin data dir.
#
# Usage: run.sh <guard_module> [args...]   (hook payload on stdin)

guard="$1"
shift
root="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
data="${CLAUDE_PLUGIN_DATA:-$HOME/.claude/preflight}"
cache="$data/python"

works() {
    command -v "$1" >/dev/null 2>&1 &&
        "$1" -c 'import sys; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1
}

py=""
[ -r "$cache" ] && read -r py <"$cache"
# The cache names a command to run: accept only the three names we write.
case "$py" in python3 | python | py) ;; *) py="" ;; esac
if [ -z "$py" ] || ! command -v "$py" >/dev/null 2>&1; then
    py=""
    for candidate in python3 python py; do
        if works "$candidate"; then
            py="$candidate"
            break
        fi
    done
    if [ -z "$py" ]; then
        # Guards are helpers: without Python they step aside, but say so once.
        if [ ! -e "$data/no-python-warned" ]; then
            # In a group, so a failed redirection (read-only or missing data
            # dir) is not fatal: `: >file` is a special builtin, and in a POSIX
            # shell its redirection error would exit with 2, which blocks the call.
            { [ -d "$data" ] || mkdir -p "$data"; } 2>/dev/null
            { printf '' >"$data/no-python-warned"; } 2>/dev/null
            printf '%s\n' '{"systemMessage": "preflight: no Python 3.9+ found on PATH, guards are inactive."}'
        fi
        exit 0
    fi
    { [ -d "$data" ] || mkdir -p "$data"; } 2>/dev/null
    { printf '%s\n' "$py" >"$cache"; } 2>/dev/null
fi

exec "$py" -X utf8 "$root/guards/$guard.py" "$@"
