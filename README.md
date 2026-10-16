# Preflight

Preflight checks for Claude Code tool calls. Five small hooks look at a tool
call before it runs (or right after, for clones) and stop the ones that are
about to fail or do damage, with a reason the model can act on.

| Guard | When | Stops |
|---|---|---|
| `edit` | before `Edit` | an anchor that is no longer in the file, an ambiguous anchor without `replace_all`, an edit that changes nothing |
| `safety` | before `Bash` / `PowerShell` | `rm -rf ~`, `Remove-Item -Recurse -Force C:\`, `DROP TABLE` through a DB client, `git push --force`, `git reset --hard origin/...`, `git clean -fd`, `mkfs` or `dd` onto a disk |
| `secrets` | before `git commit` | API keys, tokens, private keys, passwords in URLs and committed `.env` / key files, in whatever the commit will record |
| `browser` | before Claude's browser tools | reading a page right after loading it, `querySelector(...).x` with no null check |
| `clone_scan` | after `git clone` | nothing is blocked: it tells the model what in the clone would run when the folder is opened |

## Install

```
claude plugin install preflight --marketplace bibilovgo-bgo/preflight
```

Or from inside a session:

```
/plugin marketplace add bibilovgo-bgo/preflight
/plugin install preflight@bibilovgo
```

Requirements: Python 3.9 or newer on `PATH` (`python3`, `python` or `py`; the
first one that works is remembered). On Windows, Claude Code runs hooks through
Git Bash. No packages, no network: every guard is plain standard-library Python.

## Why these five

They come from a log of one developer's daily Claude Code work on Windows
(July 21 to October 15, 2026, 2,113 classified failures). The largest avoidable
classes were:

- **Edits that miss their anchor.** 174 failed `Edit` calls, 144 of them
  "String to replace not found", plus 11 with an ambiguous anchor. The file
  changed after it was read (usually a formatter hook rewrote it right after
  the previous edit) and the model aimed at what it remembered. Each miss costs
  the call plus a re-read; `edit` reads the file first and points at the
  closest line, so the retry is right the first time.
- **Browser automation.** 191 events: 75 reads of a page that was still
  loading, 75 scripts dying on `Cannot read properties of null`, 41 lost tabs.
- **Secrets in commits.** One hardcoded bot token in a throwaway script, pushed
  to a repository that was public for two weeks. `.env` in `.gitignore` did not
  help, because the token was not in `.env`.

`safety` and `clone_scan` are not about saved calls but about the calls you do
not want to happen once. `clone_scan` exists because of the 2025-2026
Shai-Hulud / ChainDrop npm worm waves, which plant a `SessionStart` hook in
`.claude/settings.json` so that opening the repository in Claude Code runs
the payload ([Elastic Security Labs](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain),
[Datadog Security Labs](https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/)).

Your numbers will differ. These are the classes that cost the most here.

## How a block looks

```
preflight/edit: this Edit will not hit its target.
  - old_string is not in the file. The file most likely changed after you read it
    (a formatter or another edit). Read the target region again and aim at the
    current text, not at memory.
    Closest line in the file: 'def alpha():'

Fix the anchor and retry. If this is deliberate, add #edit-ok to new_string.
```

Claude Code shows this to the model as the reason the call was blocked; the
model fixes the call and retries.

## What each guard reads

**secrets** parses the command instead of grepping it, so `git -C other commit`,
`cd other && git commit`, `bash -c '...'`, `powershell -Command "..."` and
`cmd /c ...` commit in the right repository, and the words "git commit" inside
a message commit nothing. It scans the staged diff, unstaged changes for
`commit -a` and named paths, and everything a `git add` earlier in the same
command will stage, untracked files included: `git add -A && git commit` is how
agents usually commit, and the hook runs before either half. The repository's
own diff programs (fsmonitor, external diff, textconv) are switched off for the
scan, binary-looking and UTF-16 files are read as text, and matches are shown
masked so the guard does not copy the secret into the transcript.

**safety** treats heredoc bodies and quoted messages as text, so a commit
message that mentions `rm -rf /` passes, unless the heredoc is fed to a shell
(`bash <<EOF`, `ssh host <<EOF`). Delete targets count only as whole words:
`rm -rf build/` passes, `rm -rf ~` does not.

**clone_scan** reports `high` for payload techniques (a download piped into a
shell, encoded or hidden PowerShell, base64 decoded and run, a reverse shell),
a JavaScript runtime started at `SessionStart`, a remote HTTP hook, settings
that redirect traffic or skip permissions, `folderOpen` tasks, executable git
config and active git hooks, hidden characters in `CLAUDE.md` and agent
files. Ordinary project hooks, MCP servers, install scripts and scripts inside
`.claude/` are `medium`: read before opening. It never follows links, caps every
read, and a check that fails or runs out of time is itself a `high` finding
saying the scan is incomplete.

## Configuration

Everything is an environment variable, so it can live in your shell profile or
in the `env` block of `~/.claude/settings.json`.

| Variable | Effect |
|---|---|
| `PREFLIGHT=0` | turn every guard off |
| `PREFLIGHT_EDIT=0`, `PREFLIGHT_SAFETY=0`, `PREFLIGHT_SECRETS=0`, `PREFLIGHT_BROWSER=0`, `PREFLIGHT_CLONE_SCAN=0` | turn one guard off |
| `PREFLIGHT_BROWSER_SETTLE=5` | seconds a page needs after loading (default 3) |
| `PREFLIGHT_LOG=1` | append each block to `~/.claude/plugins/data/<plugin>/log/<guard>.jsonl` (off by default; file names and rule labels only, never values) |

Deliberate bypass for a single call: `#browser-ok` in any string field of a
browser call; `# pragma: allowlist secret` on a line that only looks like a
secret (the convention detect-secrets uses); `#edit-ok` in `new_string`, which
then ends up in your file, so remove it afterwards or prefer `PREFLIGHT_EDIT=0`.
`safety` has no bypass marker on purpose: narrow the target, or run the command
yourself.

To scan a folder you did not clone (an archive, a client's handover) before
opening it:

```
/preflight:scan path/to/folder
```

## What it is not

These are seatbelts against mistakes, not a sandbox against a hostile agent.
The checks read the command text: the same `rm -rf` written into a script file
and run from there, `find / -delete`, a commit made by a git alias, or a
directory held in a variable (`cd $REPO`) are not followed. For isolation use
Claude Code's sandbox and permission rules; use Preflight so that ordinary work
wastes fewer calls and the classic accidents need a second, deliberate step.

Every guard fails open: if its input is unreadable, the file is binary, git is
missing or anything inside the guard breaks, the tool call goes through. A
guard that breaks your session is worse than no guard. Every pattern is linear
in the input length, so a long command cannot push a guard past its timeout.

## Development

```
python -m pytest
```

The tests run each guard as a real process with a hook payload on stdin,
against real temporary git repositories, including hostile ones: links out of
the repository, nested JSON, executable git config, inputs built to make
regular expressions slow.

## License

Apache-2.0. Copyright Georgiy Bibilov.
