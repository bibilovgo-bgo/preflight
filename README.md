# Preflight

Preflight checks for Claude Code tool calls: the commits, commands and clones
you do not want to happen even once. Four small hooks look at a call before it
runs (or right after, for a clone) and stop the dangerous ones with a reason the
model can act on.

| Guard | When | Stops |
|---|---|---|
| `secrets` | before `git commit` | API keys, tokens, private keys, passwords in URLs, committed `.env` and key files, in whatever the commit will actually record |
| `safety` | before `Bash` / `PowerShell` | `rm -rf ~`, `Remove-Item -Recurse -Force C:\`, `DROP TABLE` through a DB client, `git push --force`, `git reset --hard origin/...`, `git clean -fd`, `mkfs` or `dd` onto a disk |
| `clone_scan` | after `git clone` | nothing is blocked: it tells the model what in the clone would run as soon as the folder is opened |
| `browser` | before Claude's browser tools | reading a page right after loading it, `querySelector(...).x` with no null check |

Plus a command for folders you did not clone: `/preflight:scan path/to/folder`.

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

## How a block looks

This is a real block from a live Claude Code session, where the agent was asked
to run `git add -A && git commit -m test` in a folder with a key in an untracked
file:

```
preflight/secrets: the commit would record what looks like a secret.
  - leak.py: Anthropic API key sk-a...(49 chars)

Move the value to an untracked .env (or a secret store) and unstage the file with
`git restore --staged <file>`. If the line is a deliberate fake, mark it with
`pragma: allowlist secret` in a comment.
```

Claude Code hands this to the model as the reason the call was blocked. Nothing
was committed, and the key never appears in the transcript in full.

## Why these four

**Secrets in commits.** The motivating case was one hardcoded bot token in a
throwaway script, pushed to a repository that was public for two weeks. `.env`
in `.gitignore` did not help, because the token was not in `.env`. The harder
part came later: an agent usually commits with `git add -A && git commit` in one
command, and a hook runs before either half. A scanner that reads the staged
diff at that moment sees an empty index and lets the commit through. Ours did,
until a review caught it. Preflight parses the command and scans what the
`git add` in it is about to stage, untracked files included.

**Irreversible commands.** A wrong `rm -rf`, force push or `git clean` cannot be
undone, so it should need a second, deliberate step. The other half of the job
is not getting in the way: a guard that blocks a commit message mentioning
`rm -rf /` gets switched off within a day, and then it protects nothing.

**Repositories that run code when opened.** The 2025-2026 Shai-Hulud / ChainDrop
npm worm waves plant a `SessionStart` hook in `.claude/settings.json`, so that
opening the repository in Claude Code runs the payload, and a `folderOpen` task
for VS Code ([Elastic Security Labs](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain),
[Datadog Security Labs](https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/)).
Agents clone foreign code all the time. `clone_scan` tells the model what would
run before anyone opens the folder.

**Browser automation.** In a log of one developer's daily Claude Code work
(July 21 to October 15, 2026, 2,113 classified failures) the browser gave 191
failures: 75 reads of a page that was still loading, 75 scripts dying on
`Cannot read properties of null`, 41 lost tabs.

**Why there is no Edit guard.** The same log had 174 failed `Edit` calls whose
anchor had drifted, and the first version of this plugin had a guard for them.
A live test showed that current Claude Code rejects a missing anchor, an
ambiguous one and an edit that changes nothing on its own, before any hook is
called; a probe plugin received no event at all for such a call, not even
`PostToolUseFailure`. Claude Code now does that job itself, so the guard was
removed.

## What each guard reads

**secrets** parses the command instead of grepping it, so `git -C other commit`,
`cd other && git commit`, `bash -c '...'`, `powershell -Command "..."` and
`cmd /c ...` commit in the right repository, and the words "git commit" inside
a message commit nothing. It scans the staged diff, unstaged changes for
`commit -a` and named paths, and everything a `git add` earlier in the same
command will stage. The repository's own diff programs (fsmonitor, external
diff, textconv) are switched off for the scan, binary-looking and UTF-16 files
are read as text, and placeholders such as `your-api-key-here`, documented
examples and publishable `pk_` keys are not reported.

**safety** treats heredoc bodies and quoted messages as text, so a commit
message that mentions `rm -rf /` passes, unless the heredoc is fed to a shell
(`bash <<EOF`, `ssh host <<EOF`). Delete targets count only as whole words:
`rm -rf build/` passes, `rm -rf ~` does not. `git -C dir push --force` and
`sudo rm -rf /` are caught; `dd of=/dev/null` and `git clean -X` are not blocked.

**clone_scan** reports `high` for payload techniques (a download piped into a
shell, encoded or hidden PowerShell, base64 decoded and run, a reverse shell),
a JavaScript runtime started at `SessionStart`, a remote HTTP hook, settings
that redirect traffic or skip permissions, `folderOpen` tasks, executable git
config and active git hooks, hidden characters in `CLAUDE.md` and agent
files. Ordinary project hooks, MCP servers, install scripts and scripts inside
`.claude/` are `medium`: read before opening. The scanned repository is treated
as hostile: links are never followed, every read is capped, git runs with the
repository's program-running config overridden, and a check that fails or runs
out of time is itself a `high` finding saying the scan is incomplete.

## Configuration

Everything is an environment variable, so it can live in your shell profile or
in the `env` block of `~/.claude/settings.json`.

| Variable | Effect |
|---|---|
| `PREFLIGHT=0` | turn every guard off |
| `PREFLIGHT_SAFETY=0`, `PREFLIGHT_SECRETS=0`, `PREFLIGHT_BROWSER=0`, `PREFLIGHT_CLONE_SCAN=0` | turn one guard off |
| `PREFLIGHT_BROWSER_SETTLE=5` | seconds a page needs after loading (default 3) |
| `PREFLIGHT_LOG=1` | append each block to `~/.claude/plugins/data/<plugin>/log/<guard>.jsonl` (off by default; file names and rule labels only, never values) |

Deliberate bypass for a single call: `# pragma: allowlist secret` on a line that
only looks like a secret (the convention detect-secrets uses), and
`#browser-ok` in any string field of a browser call. `safety` has no bypass
marker on purpose: narrow the target, or run the command yourself.

## What it is not

These are seatbelts against mistakes, not a sandbox against a hostile agent.
The checks read the command text: the same `rm -rf` written into a script file
and run from there, `find / -delete`, a commit made by a git alias, or a
directory held in a variable (`cd $REPO`) are not followed. For isolation use
Claude Code's sandbox and permission rules; use Preflight so that the classic
accidents need a second, deliberate step.

Every guard fails open: if its input is unreadable, git is missing or anything
inside the guard breaks, the tool call goes through. A guard that breaks your
session is worse than no guard. Every pattern is linear in the input length, so
a long command cannot push a guard past its timeout.

## Development

```
python -m pytest
```

The tests run each guard as a real process with a hook payload on stdin,
against real temporary git repositories, including hostile ones: links out of
the repository, nested JSON, executable git config, inputs built to make
regular expressions slow. The code went through an independent code review, a
security review and two mutation-testing passes.

## License

Apache-2.0. Copyright Georgiy Bibilov.
