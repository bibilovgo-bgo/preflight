# Changelog

## 0.1.0 (unreleased)

First version: seven guards and a scan command.

- `safety`: blocks recursive deletes of a root, home, current, parent or system
  directory, SQL DROP / TRUNCATE / unconditional DELETE through a database
  client, force push, hard reset to a remote or older commit, `git clean`, disk
  formatters and raw writes to disks. Heredoc and quoted text is not a command.
  Commands inside `bash -c`, `pwsh -Command`, `cmd /c`, `su -c`, `wsl`,
  `docker exec`, `kubectl exec` and `ssh host '...'` (also behind `sshpass`,
  `autossh`, `mosh`, or as a heredoc) are unwrapped, and `sudo -u www` is
  read past; over ssh, a recursive delete of any absolute path except `/tmp`
  and `__pycache__` is blocked. `rd /s` and `del /s` of a drive root in cmd.
- `secrets`: blocks a commit whose content carries a credential, including what
  a `git add` earlier in the same command stages and commits wrapped in
  `bash -c`, `powershell -Command` or `cmd /c`.
- `keys`: blocks printing a private key (by name or by its first line, through
  globs, `$HOME`, `cd` and `$(...)`) and sending `.env`, keys, credentials files
  or the whole environment over the network; reading `.env`, searching for the
  word `id_rsa`, `ssh -i`, `scp`, `curl --key` and downloads into `.env` pass.
  Network paths are never opened.
- `browser`: blocks reading a page right after loading it, and DOM property
  reads that throw on a missing element.
- `facts`: denies the first `Edit`, `Write` or `NotebookEdit` of a money, auth,
  schema or check-configuration file with the facts to show (importers and
  callers, the test that pins the numbers, the rollback, the check being
  weakened), and lets the retry through once a search of the tree for the
  file (`Grep`, `Glob`, `rg`, `grep`, `git grep`, `find`, `fd`,
  `Select-String`) completed in the current turn; two denials per file and
  session at most, then the edit passes with a note. Tests, prose, agent
  instruction files, Claude Code settings and secret files are never gated;
  no state is written about files outside the four classes. The idea is
  GateGuard's (ECC, MIT): deny first, force the facts, allow the retry. Three
  mutation rounds, a code review (17 findings, 16 fixed) and a security review
  (a network path was stat'ed before the edit: fixed) — see `docs/REVIEWS.md`.
- `config`: blocks an `Edit`, `Write` or `MultiEdit` that weakens a lint,
  type or test check instead of fixing the code it fails on. The file is read
  from disk and compared with what the edit would make of it: TOML (with
  `tomllib`, or a small reader of the same grammar on Python 3.9 and 3.10), INI
  and JSON key by key; command values, workflows and pre-commit hooks line by
  line; `conftest.py` by its skips. A new `ignore`, `per-file-ignores` or
  `exclude` entry (a replaced one counts), a rule gone from `select`, a raised
  `line-length`, a lowered `fail_under`, `strict` switched off, `-p no:` or
  `-k` in `addopts`, a narrowed `testpaths`, `continue-on-error: true` or
  `|| true` in CI, a removed pre-commit hook, a check tool that no longer runs:
  blocked, with the recipe "fix the code the check fails on, or say in the
  commit why the rule is wrong". Lists are pooled per tool, so the
  `[tool.ruff]` to `[tool.ruff.lint]` migration, `ignore` to `extend-ignore`
  and a move between tox environments are not changes, and a code covered by a
  wider one (`E` for `E501`, `ALL`) is neither new nor lost. Tightening, new
  config files and a file that was already unparsable pass; an edit that makes
  a file unparsable, or touches one over 1 MiB, is blocked. No cap and no
  marker: `PREFLIGHT_CONFIG=0` or `PREFLIGHT_CONFIG_EXEMPT`. Python and GitHub
  files only; JavaScript configs, `Makefile` and `.gitlab-ci.yml` are not
  covered. Three mutation rounds, a code review (16 findings) and a security
  review (6 groups of findings, among them four inputs that ran the hook past
  its timeout, which lets the edit through): all fixed, see `docs/REVIEWS.md`.
  The idea is config-protection's (ECC, MIT), which blocks every edit of a
  linter config; this one blocks only the weakening. The `facts` gate now asks
  about `.ruff.toml`, `.mypy.ini`, `.coveragerc`, `pylintrc` and
  `.pre-commit-config.yml` too, the same names the config guard reads.
- `clone_scan`: after a clone, reports to the model what in the repository runs
  when the folder is opened; never follows links, never runs the repository's
  programs, never lets a failing check go silent.
- `/preflight:scan <folder>`: the same scan for a folder that was not cloned.

The `keys` guard and the safety unwrapping went through two mutation runs and
three reviews (see `docs/REVIEWS.md`). Each fix of the third review has a
regression test of its own in `tests/test_review3_regressions.py`.

An Edit guard was built and removed before release: a live test showed that
current Claude Code rejects drifted, ambiguous and no-op Edit anchors itself,
before any hook is called.
