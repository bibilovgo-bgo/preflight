# Preflight

Two things an agent does every day can go wrong in a way you cannot take back:
it commits, and it clones foreign code. Preflight is a Claude Code plugin that
checks both before the damage is done.

- **Secrets in the commit an agent actually makes.** Agents commit with
  `git add -A && git commit` in one command. A hook runs before either half, so
  a scanner that reads the staged diff sees an empty index and lets the key
  through. Preflight parses the command and scans what that `git add` is about
  to stage, untracked files included, and blocks the commit.
- **Repositories that run code when opened.** After every `git clone` it tells
  the model what in the clone would execute as soon as the folder is opened in
  Claude Code or VS Code: the worm-planted `SessionStart` hooks, `folderOpen`
  tasks, payload-style install scripts, hidden text in `CLAUDE.md`.

Three smaller guards come along: a block on irreversible shell commands, one on
printing private keys or sending secret files over the network, and two
browser-automation checks.

| Guard | When | Stops |
|---|---|---|
| `secrets` | before `git commit` | API keys, tokens, private keys, passwords in URLs, committed `.env` and key files, in whatever the commit will actually record |
| `clone_scan` | after `git clone` | nothing is blocked: it tells the model what in the clone would run as soon as the folder is opened |
| `safety` | before `Bash` / `PowerShell` | `rm -rf ~`, `Remove-Item -Recurse -Force C:\`, `DROP TABLE` through a DB client, `git push --force`, `git reset --hard origin/...`, `git clean -fd`, `mkfs` or `dd` onto a disk |
| `keys` | before `Read`, `Grep`, `Bash`, `PowerShell` | printing a private key into the transcript (`cat ~/.ssh/id_rsa`), sending `.env`, a key or a credentials file over the network (`curl -d @.env`, `cat .env \| nc`); reading `.env` and using keys stay allowed |
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

And this is what `/preflight:scan` printed for a test repository built the way
the worm reports describe:

```
[high] .claude/settings.json: hook SessionStart (command): node .claude/setup.mjs
[high] .git: 1 commit(s) by author 'claude' titled 'chore: update config', a known worm signature
[high] .vscode/tasks.json: task with runOn: folderOpen runs when the folder opens
[high] CLAUDE.md: 2 invisible character(s): hidden text for the agent
[medium] .claude/setup.mjs: script inside .claude/
[medium] package.json: preinstall script: node bundle.js
```

## Why

**Secrets in commits.** The motivating case was one hardcoded bot token in a
throwaway script, pushed to a repository that was public for two weeks. `.env`
in `.gitignore` did not help, because the token was not in `.env`. The harder
part came later: an agent usually commits with `git add -A && git commit` in one
command, and a hook runs before either half. A scanner that reads the staged
diff at that moment sees an empty index and lets the commit through. Ours did,
until a review caught it. Preflight parses the command and scans what the
`git add` in it is about to stage, untracked files included.

**Repositories that run code when opened.** The 2025-2026 Shai-Hulud / ChainDrop
npm worm waves plant a `SessionStart` hook in `.claude/settings.json`, so that
opening the repository in Claude Code runs the payload, and a `folderOpen` task
for VS Code ([Elastic Security Labs](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain),
[Datadog Security Labs](https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/)).
Agents clone foreign code all the time. `clone_scan` tells the model what would
run before anyone opens the folder. The scanner treats the repository as
hostile: it never follows links, never runs the repository's own git programs,
and a repository cannot switch it off by crashing one of its checks.

**Irreversible commands.** A wrong `rm -rf`, force push or `git clean` cannot be
undone, so it should need a second, deliberate step. The other half of the job
is not getting in the way: a guard that blocks a commit message mentioning
`rm -rf /` gets switched off within a day, and then it protects nothing. If
destructive commands are your main worry, see the dedicated projects listed
below; `safety` is here so that one install covers the basics.

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
Commands inside `bash -c '...'`, `pwsh -Command ...`, `cmd /c ...`, `su -c`,
`wsl`, `docker exec`, `kubectl exec`, `ssh host '...'` (with `sshpass`,
`autossh` and `mosh` around it, or a heredoc fed to it) are unwrapped and
checked too, and so is the command behind `sudo -u www`. On a remote host the
delete rule is stricter, because there a recursive delete of an absolute path
is usually the site or its data: `ssh prod "rm -rf /var/www"` is blocked,
while `/tmp/...` and `__pycache__` cleanups pass (`/tmp/../etc` does not).

**keys** draws the line where the damage is, so the agent can still set things
up on its own. Reading `.env` is allowed; printing a private key is not: a
`Read` of the key file, `cat`, `head`, `base64`, `Get-Content` and similar
readers, `cat ~/.ssh/*`, `echo "$(cat key)"`, `Grep` through `~/.ssh`. A key
is recognised by its name (`id_ed25519`, `deploy_rsa`, `*.key`, `privkey.pem`,
`.ppk`, `.p12`, `ssh_host_*_key`) and, for a file that exists, by its first
line (OpenSSH, PEM, PGP, PuTTY, a key inside a PEM bundle), so
`~/.ssh/hetzner` counts too; `$HOME`, `$env:USERPROFILE` and `cd` are
followed. A search pattern is not a file: `grep -rn id_rsa .` passes. Using a
key never shows it and passes: `ssh -i`, `scp`, `ssh-add`, `ssh-keygen -y`,
`git`, `curl --key`. The second rule stops a secret file (`.env`, `prod.env`,
keys, `.netrc`, `.npmrc`, `~/.aws/credentials`, `~/.kube/config` and the like)
from leaving the machine through `curl`, `wget`, `nc`, `socat`, `gh gist`,
`> /dev/tcp/...` or `Invoke-WebRequest`: `-d @.env`, `-F file=@.env`,
`-T ~/.aws/credentials`, `-InFile .env`, `cat .env | curl`, `tar cz .env | curl`,
`nc host < .env`, and the whole environment (`env | curl -d @- ...`). That is
the move a planted instruction in a README asks for. `scp .env server:` to
your own server and `curl -sSLo .env` (a download) pass; `.env.example` and
friends are not secrets. Paths on the network (`//host/share`) are never
opened: on Windows that alone would send your NTLM hash to the host.

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
| `PREFLIGHT_SAFETY=0`, `PREFLIGHT_SECRETS=0`, `PREFLIGHT_KEYS=0`, `PREFLIGHT_BROWSER=0`, `PREFLIGHT_CLONE_SCAN=0` | turn one guard off |
| `PREFLIGHT_BROWSER_SETTLE=5` | seconds a page needs after loading (default 3) |
| `PREFLIGHT_LOG=1` | append each block to `~/.claude/plugins/data/<plugin>/log/<guard>.jsonl` (off by default; file names and rule labels only, never values) |

Deliberate bypass for a single call: `# pragma: allowlist secret` on a line that
only looks like a secret (the convention detect-secrets uses), and
`#browser-ok` in any string field of a browser call. `safety` has no bypass
marker on purpose: narrow the target, or run the command yourself.

## Related projects

Preflight is not the only guard plugin, and for some jobs another one is the
better pick.

- **[security-guidance](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/security-guidance)**
  (Anthropic, official marketplace) reviews the code Claude writes for
  vulnerabilities, hardcoded secrets among them, with pattern warnings, a model
  review of the diff and an agentic review on commit. It uses model calls and
  feeds its findings back to Claude. Preflight's secret check is a
  deterministic block with no model calls; the two work side by side.
- **[destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard)**
  and **[cc-safety-net](https://github.com/kenryu42/cc-safety-net)** are
  dedicated, widely used guards against destructive shell and git commands.
  If that is all you need, they are more mature than Preflight's `safety`.
- **[spac](https://github.com/seanrobertwright/spac)** is another plugin that
  blocks commits containing secrets.

What Preflight adds is the secret scan of what a one-command
`git add ... && git commit` will really record, and the scan of fresh clones
for code that runs on open. If you run one of the plugins above, turn off the
overlapping Preflight guard (`PREFLIGHT_SAFETY=0`, see Configuration) so the
same command is not blocked twice.

## What it is not

These are seatbelts against mistakes, not a sandbox against a hostile agent.
The checks read the command text: the same `rm -rf` written into a script file
and run from there, `find / -delete`, `eval "$cmd"`, `echo 'rm -rf ~' | sh`, a
commit made by a git alias, a key opened by a Python one-liner, a secret sent
line by line in a loop, a path or a directory held in a variable
(`f=.env; curl -d @$f`, `cd $REPO`) are not followed, and commands run through
an MCP terminal tool instead of `Bash` or `PowerShell` are not seen at all. For isolation use
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
