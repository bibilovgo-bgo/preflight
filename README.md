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

Five smaller guards come along: a block on irreversible shell commands, one on
printing private keys or sending secret files over the network, two
browser-automation checks, a gate that makes the agent search the tree
before its first edit of a payment, auth, schema or check-configuration file,
and a block on edits that weaken a lint, type or test check instead of fixing
the code it fails on.

| Guard | When | Stops |
|---|---|---|
| `secrets` | before `git commit` | API keys, tokens, private keys, passwords in URLs, committed `.env` and key files, in whatever the commit will actually record |
| `clone_scan` | after `git clone` | nothing is blocked: it tells the model what in the clone would run as soon as the folder is opened |
| `safety` | before `Bash` / `PowerShell` | `rm -rf ~`, `Remove-Item -Recurse -Force C:\`, `DROP TABLE` through a DB client, `git push --force`, `git reset --hard origin/...`, `git clean -fd`, `mkfs` or `dd` onto a disk |
| `keys` | before `Read`, `Grep`, `Bash`, `PowerShell` | printing a private key into the transcript (`cat ~/.ssh/id_rsa`), sending `.env`, a key or a credentials file over the network (`curl -d @.env`, `cat .env \| nc`); reading `.env` and using keys stay allowed |
| `browser` | before Claude's browser tools | reading a page right after loading it, `querySelector(...).x` with no null check |
| `facts` | before `Edit`, `Write`, `MultiEdit`, `NotebookEdit` | the first edit of a money, auth, schema or check-config file until the agent has searched the tree for it (who imports it, which test pins it); everything else passes untouched |
| `config` | before `Edit`, `Write`, `MultiEdit` | an edit that weakens a check: a code added to ruff's `ignore`, a rule dropped from `select`, `line-length` raised, `-p no:...` or `-k` in `addopts`, `testpaths` narrowed, `strict = false`, coverage `fail_under` lowered, `continue-on-error: true` or `\|\| true` in CI, a pre-commit hook removed, `skip` in `conftest.py`; tightening and new config files pass |

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

The `facts` gate reads differently: it is not a block, it is a question. This
is what the model gets on its first edit of `src/payments/charge.py`:

```
preflight facts: first edit of a money path (src/payments/charge.py), show the facts first
  - who reads charge: search the tree for its importers and callers (Grep/rg)
  - where every amount comes from, its currency and rounding, and which store it is written to
  - which test pins the current numbers (search tests/ for charge), or say there is none
  - quote the user's current instruction verbatim

Then retry the edit. Reading the file does not count; a search does.
```

Asking a model "are you sure?" gets "yes". Asking it to list the importers
makes it run a search, and the search changes what it does next. The retry
passes once a `Grep`, `Glob`, `rg`, `grep`, `git grep`, `find` or `fd` in the
current turn looked for the file's name (or the table, or the symbol being
edited); in the same live session, after `rg charge .` the same edit went
through with the note `facts: payments/charge.py credited by rg 'charge .'`.
After two denials without a search the edit passes with a note, so the gate
can never hold an edit for good.

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

**facts** classes a file by a whole path segment, never by a substring:
`src/payments/charge.py` is money, `lib/paymentutils.py` is not. Money is
`payment(s)`, `billing`, `invoice(s)`, `checkout`, `pricing`, `ledger`,
`treasury`, `revenue`, `wallet`, `subscription(s)`, `refund(s)`, `payout(s)`;
auth is `auth`, `authn`, `authz`, `login`, `oauth`, `sso`, `session(s)`,
`permissions`, `acl`, `rbac`, `security`; schema is `migrations`, `alembic`,
any `.sql` or `.prisma`, and a code file under `schema(s)` or `models` when
the edit itself talks to a database (`Column(`, `models.Model`, DDL): a
pydantic request model or a neural network in those folders is not a schema;
check configuration is `pyproject.toml`, `ruff.toml`, `.ruff.toml`, `setup.cfg`,
`pytest.ini`, `tox.ini`, `mypy.ini`, `.coveragerc`, `.flake8`, `.pylintrc`,
`conftest.py`, `.eslintrc*`, `eslint.config.*`, `.prettierrc*`,
`tsconfig*.json`, `.pre-commit-config.yaml`, `.github/workflows/*`,
`hooks.json` and a `Makefile` with a `test` or `lint` target. When the path
says nothing, the text of the edit may, and the old text counts as much as
the new (an edit that removes `@login_required` is the one to ask about):
`CREATE TABLE`, `op.add_column(`, `Column(` make it schema; `password`,
`check_password`, `verify=False`, `@login_required` make it auth; two amount
words (`price`, `total`, `balance`, `fee`…) next to arithmetic, or one next
to a currency, `Decimal(`, `round(` or a database write, make it money
(`average = total / count` does not). The path is judged at its real location
too, so a symlink into `auth/` counts. Tests (`test_*.py`, `*_test.go`,
`*.spec.ts`…), prose, agent instruction files (`CLAUDE.md`, `SKILL.md`,
anything under `.claude/`), Claude Code settings and secret files (those
belong to `keys`) are never gated. Creating a new check-configuration file
passes with a note: there is nothing to weaken yet. A search credits the file
when the file's stem (or the symbol being edited when the stem is generic
like `models`, or the folder name when there is neither) is a whole word of
the pattern: `payment` credits `payment.py`, `payments` does not. `git -C dir
grep`, searches inside `bash -c '...'` and a search fed by a tree listing
(`gci -r | sls x`, `find . | grep x`) count; a search restricted to other
names (`rg -g '*.js'` for a `.py` file), excluding the file, or confined to
the file's own name (`Glob **/charge.py`) does not, and neither does a search
sent in the same message as the edit, one whose result was an error, or one
from a previous turn. Only the model's own tool calls are read: the text of a
tool result is never evidence. Two hook processes of one session merge their
memory instead of overwriting each other.

**config** reads the file as it is on disk and as it would be after the edit,
and compares the two: an agent whose lint or test run fails can fix the code
or edit the check, and the second is quicker. It covers `pyproject.toml`
(only the `[tool.*]` tables of ruff, black, isort, mypy, pytest, coverage,
pyright, pylint, flake8, bandit; packaging keys are not a check), `ruff.toml`,
`setup.cfg` and `tox.ini` (their check sections), `.flake8`, `pytest.ini`,
`mypy.ini`, `.coveragerc`, `.pylintrc`, `pyrightconfig.json`, `conftest.py`
anywhere (also under `tests/`), `.pre-commit-config.yaml` and
`.github/workflows/*.yml`. TOML, INI and JSON are compared setting by
setting. Lists and commands are pooled per tool: `[tool.ruff]` and
`[tool.ruff.lint]`, `ignore` and `extend-ignore`, `select` and
`extend-select`, every tox environment hold one setting each, so the migration
ruff asks for, a split or a move between tox environments is not a change. A
code covered by a wider one (`E` covers `E501`, `ALL` covers everything)
counts as neither new nor lost. Blocked: a new entry in `ignore`,
`per-file-ignores`, `exclude`, `omit`, `disable` (a replaced entry counts as
new: `exclude = ["build"]` to `["dist"]` stops checking `dist`), an entry gone
from `select`, `testpaths` or `include`, a raised `line-length` or `max-*`
limit, a lowered or removed `fail_under`, a strict flag (`strict`,
`disallow_*`, `warn_*`, `xfail_strict`, coverage `branch`) switched off, a lax
one (`ignore_missing_imports`, `ignore_errors`, `ignore_outcome`) switched on,
a mypy override that gains a module, pyright's `typeCheckingMode` lowered or,
in strict mode, a `report*` rule set below `error`, `filterwarnings` gaining
an `ignore` or losing an `error` that no other filter covers. Command values
(`addopts`, tox `commands`), workflows and pre-commit hooks are compared as
text, with `\` continuations joined: `set +e`, `--no-verify`,
`continue-on-error: true`, `if: false` and `SKIP=` anywhere; `|| true`,
`--exit-zero` and `--ignore=`/`--exclude=` on a line that runs a check tool
(not on `rsync` or `rm`); after `pytest` also `-k`, `-m`, `--deselect`,
`-W ignore`, `--lf` and `-p no:...` (not for plugins that change no verdict,
such as `cacheprovider`, `randomly` or `xdist`) count when they become more
frequent. In a workflow, an edit that only adds lines adds a check, so a new
`pytest -m integration` job passes while `-m fast` put on the existing run
does not. `--check`, `--strict`, `set -e` and `-W error` count when they
become rarer; `--max-line-length` raised and `--cov-fail-under` lowered; a
check tool (pytest, ruff, mypy, eslint, `go test`, `npm test`...) that no
longer runs anywhere in the file (`pip install -e . && pytest` still runs
pytest); a pre-commit hook that left (a rename that keeps the stem as a word,
`ruff` to `ruff-check` or `lint` to `ruff-lint`, did not), a new hook
`exclude:` or `stages: [manual]`. In `conftest.py`, a new `pytest.skip(`,
`mark.skip`, `xfail`, `collect_ignore` or a warnings filter set to ignore.
Comments and the `name:` of a step are prose and never count. Warning actions
are read the way Python reads them, so `i::DeprecationWarning` and `-W i` are
ignores. `pyrightconfig.json` may carry the comments and trailing commas
pyright accepts. A file the guard could not parse before the edit passes; an
edit that leaves a parsable file unparsable is blocked, because the next edit
would then weaken it unseen. So is an edit of a check configuration over
1 MiB, before or after: a hook that cannot finish in time lets the edit
through, so the guard refuses to try rather than fail quietly. Text taken from
the file is cut to 160 characters per line and 20 lines, without control
characters, before the model reads it.

## Configuration

Everything is an environment variable, so it can live in your shell profile or
in the `env` block of `~/.claude/settings.json`.

| Variable | Effect |
|---|---|
| `PREFLIGHT=0` | turn every guard off |
| `PREFLIGHT_SAFETY=0`, `PREFLIGHT_SECRETS=0`, `PREFLIGHT_KEYS=0`, `PREFLIGHT_BROWSER=0`, `PREFLIGHT_CLONE_SCAN=0`, `PREFLIGHT_FACTS=0`, `PREFLIGHT_CONFIG=0` | turn one guard off |
| `PREFLIGHT_BROWSER_SETTLE=5` | seconds a page needs after loading (default 3) |
| `PREFLIGHT_FACTS_EXEMPT=src/legacy/*;vendor/*` | file globs the facts gate never asks about (`;`-separated, matched against the project-relative path and the file name) |
| `PREFLIGHT_FACTS_MAX_DENIALS=1` | denials per file and session before the edit passes with a note (default 2) |
| `PREFLIGHT_CONFIG_EXEMPT=tox.ini;legacy/*` | file globs the config guard never blocks (same matching as the facts exemptions, set separately) |
| `PREFLIGHT_LOG=1` | append each block to `~/.claude/plugins/data/<plugin>/log/<guard>.jsonl` (off by default; file names and rule labels only, never values) |

Deliberate bypass for a single call: `# pragma: allowlist secret` on a line that
only looks like a secret (the convention detect-secrets uses), and
`#browser-ok` in any string field of a browser call. `safety` has no bypass
marker on purpose: narrow the target, or run the command yourself. `facts` has
none either, because anything typed into the edit would land in the file:
search, or exempt the path. `config` has no marker and no cap on denials for
the same reason and one more: its block is a fact about the edit, not a
question, and a model asked twice learns to answer "noted". When a rule really
is wrong, the user lifts the block with `PREFLIGHT_CONFIG_EXEMPT` or
`PREFLIGHT_CONFIG=0`.

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

The `facts` gate is deliberately small next to the gates it took the idea
from. It does not scope a shell search by its path operands (`rg charge docs`
credits `src/charge.py`), does not know every tool's type and exclusion
grammar, does not credit a new file by a search of its directory, does not
tell a subagent from the main session, and sees edits made through `sed` or
`python -` in a shell as shell commands, not as edits. In a parallel batch of
edits to one file, the first is denied and its siblings go through: send
dependent edits to a gated file one at a time. Two hook processes of one
session can still race between reading and writing their memory; the merge
narrows the window, it does not close it.

The `config` guard reads Python and GitHub configuration only. ESLint,
Prettier, Jest, Vitest, Biome and `tsconfig*.json` (JavaScript or JSON with
comments), `Makefile` and `.gitlab-ci.yml` are not covered. Workflows and
pre-commit configs are read line by line, not parsed as YAML: a check step
removed while the same tool still runs in another step, a multi-line
`exclude: |` block that grows, a folded `run: >` command, and a hook renamed
to a new stem are not seen; replacing one tool with another (`black` with
`ruff format`) reads as the first one no longer running, and is blocked on
purpose. A code moved from the global ruff `ignore` into `per-file-ignores`
narrows the ignore but reads as a new per-file entry and is blocked. Pooling
by tool means a list entry added to one `[[tool.mypy.overrides]]` table that
the global `[tool.mypy]` already had is not seen. A new `line-length` key is judged against
the tool's default only for ruff, black, flake8, pycodestyle and pylint.
Reading text as words has its edges: `echo pytest` counts as running pytest,
`if: ${{ 1 == 2 }}` is not recognised as a disabled step, an option and its
value on two lines of a YAML block list (`- --ignore` then `- E501`) are not
paired, and an unbalanced quote in a shell line keeps a `#` comment after it
from being dropped. Inline suppressions in code
(`# noqa`, `# type: ignore`, `eslint-disable`) are out of scope, and a config
edited through `sed` or a script in a shell is a shell command, not an edit.

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
