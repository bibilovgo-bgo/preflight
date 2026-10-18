# Reviews

Every `feat:` is reviewed twice before the next one starts: correctness and
security, by reviewers who did not write the code, with probes run against
the real guards. A mutation run of the changed lines comes before the reviews.
The commit gate refuses a new `feat:` until the previous one is named here.

## 99678c0 feat: preflight guards for Claude Code tool calls

- Reviews (16.10.2026, Sonnet): code and security, about 35 confirmed findings,
  all fixed in the same commit with a regression test each.
- Mutation runs: e9c6434 and cd93f7e closed the surviving mutants that were
  real gaps; the rest were analysed as equivalent or Linux-only.

## 313128b feat(keys): the keys guard, and safety unwrapping ssh, bash -c and sudo -u

Stage of 17.10.2026: `guards/key_guard.py`, `key_stages.py`, `secret_files.py`,
`shell_pipes.py`, `wrappers.py`, and the safety guard reading wrapped and
remote commands.

- Mutation runs: two, in clones. Every surviving mutant analysed: real gaps
  closed with tests, dead code removed, the rest equivalent (constants read
  by name in tests, a trailing `return None`, FIFO checks seen only on Linux).
- Review 1 (code, Sonnet) and review 2 (security, Sonnet): all confirmed
  findings fixed, with regression tests in `tests/test_key_guard_review.py`,
  `tests/test_wrappers.py` and `tests/test_safety_guard.py`. The most serious
  one: a word like `//host/share` made the guard open an SMB connection on
  Windows, which offers the user's NTLM hash to that host.
- Review 3 (security, Sonnet, of the fixes): confirmed findings fixed in code
  (a `${VAR}` before a dangerous token hid it from the safety rules; search
  options of grep and rg taken for the pattern; prose ending in a secret-like
  path; `set -e` and `printenv HOME` counted as an environment dump; a heredoc
  written to a file named like `ssh-deploy.sh` read as remote; an unbounded
  glob count; quadratic matching of `$(`). **These fixes have no dedicated
  regression tests yet**: writing them was stopped twice by the model's own
  safety classifier, and the owner chose to commit without them. The full
  suite (972 tests) passes on the fixed code.

### Deferred

- Regression tests for the review 3 fixes. Must be written before the first
  line of the next stage that touches `guards/key_*`, `secret_files.py`,
  `shell_pipes.py` or `safety_guard.py`. (The facts stage below only imports
  them, so it did not trigger this.)

## 6b9eed0 feat(facts): fact gate for money, auth, schema and check-config edits

Stage of 18.10.2026, one commit.
`guards/fact_gate.py`, `fact_classes.py`, `search_credit.py`,
`transcript_turn.py`, the `Edit|Write|MultiEdit|NotebookEdit` hook; 1273
tests (was 972). The idea is GateGuard's (ECC, MIT): deny the first edit of a
risky file, force the facts, allow the retry once a search of the tree
happened.

- Mutation runs: three rounds by diff in four parallel clones (one per
  module), plus a spec of 14 hand-written mutants (all killed) and an
  in-place run of the security fix (8 of 8 killed). Round 1: 94 survivors of
  478; 22 were real gaps closed with tests, 4 were dead lines removed, the
  rest constants, prose of the question texts, and equivalents. Round 2 (after
  the fixes): 24 survivors, all constants, prose or equivalents (`return ""`
  vs `None` masked by the caller, `type == "assistant"` where only assistant
  records carry tool_use blocks, case-folding of git subcommands). Round 3 (on
  the review fixes): 14 survivors; one was a dead rule (`schemas/` and
  `models/` folders duplicated the by-content check) and one a redundant
  `continue`, both removed; 4 gaps closed with tests; the rest tolerances.
- Code review (high, 8 angles in context): 17 findings, 16 fixed with a
  regression test each in `tests/test_fact_review.py` (old text of an edit
  classed too; a folder name credits a file with neither stem nor symbol;
  brace globs `*.{ts,tsx}`; merged session state across hook processes;
  `schemas/`/`models/` need database talk; money needs two signals; batch
  fallback without a `tool_use_id`; `git -C` and `bash -c` searches; piped
  searches fed by a listing; glued short options `-g*.js`; `*_test.go`;
  Windows-only path cleaning; MultiEdit; the new-config note remembered; lazy
  state read). One finding withdrawn: the final filter in `completed_calls`
  is live (a duplicated call id is dropped only there); removing it turned
  an existing test red.
- Security review (Sonnet, one finding, confirmed 8/10 by an independent
  filter): the guard stat'ed a model-supplied path, so an Edit on
  `\\attacker\share\x.py` (a planted instruction) made Windows open an SMB
  connection and offer the user's NTLM hash — the same class the keys stage
  called its most serious finding. Fixed: `fact_classes.is_network` refuses
  `//host`, `\\host`, `scheme://` and a root on a share before any
  filesystem call; `fact_gate._exists` the same; tests assert `Path.exists`
  and `realpath` are never called for such paths.
- Live run (`claude -p --plugin-dir`, console Claude Code, Sonnet): the first
  Edit of `payments/charge.py` was denied with the text now in the README;
  after `rg charge .` the same Edit passed with the note `facts:
  payments/charge.py credited by rg 'charge .'`; log lines written with
  `PREFLIGHT_LOG=1`.

### Deferred

- Not covered by design, in the README: scope by path operands, the full
  type grammar of every tool, credit of a new file by a directory search,
  subagents, edits made through `sed` or `python -` in a shell, the residual
  race between two hook processes of one session (merge narrows it).
- Measure: after two weeks of use, count denials, credits and cap pass-throughs
  in the log; if the cap fires more often than a credit, the questions are
  wrong or the cap should go.
- Not covered by design, documented in README: paths held in variables,
  loops that send a file line by line, `echo cmd | sh`, the text of `<<<`
  and unquoted heredoc bodies, commands run through MCP terminal tools.

## feat(config): block edits that weaken a check's configuration

Stage of 18.10.2026, one commit. `guards/config_guard.py`, `config_formats.py`,
`config_rules.py`, `config_text.py`, `toml_lite.py`; the `Edit|Write|MultiEdit`
hook; `fact_classes.exempt_globs(variable)` and `matches_globs`; five names
added to `CONFIG_NAMES`; `_common.log` also swallows `ValueError`. 1619 tests
(was 1273), 336 of them for this guard. The idea is config-protection's (ECC,
MIT); scope chosen by the owner: Python and GitHub files, line-based YAML, no
cap and no marker, a replaced exclude entry counts as weaker.

- Mutation runs, in four parallel clones (one per module) plus a spec of
  manual mutants (`scripts/config_mutants.py`, 20 at the end):
  - Round 1: 95 survivors of 554. Gaps closed with tests (ranks, defaults,
    `|| exit 0`, `-W`, `go test`, the install-line exemption, in-process
    early exits that a hook process would hide behind its crash net); dead
    code removed (`lower`/`strip` on keys already normalised, `if sep`, the
    bool branch of `as_bool`, guards in `as_num` and `command_text`). One was
    a logic flaw: with two `--cov-fail-under` values, lowering one went
    unseen; values are now paired.
  - Round 2: 19 survivors of 530; 4 gaps closed, the rest equivalent
    (`tomllib` parity by design, implicit `return None`, bounds in
    `toml_lite` that an `IndexError` already turns into an error).
  - Round 3, on the review fixes: 38 of 563, none in `config_guard.py`; gaps
    closed (every key family, pools never shared between tools, `tests/`
    covering `tests/unit`, `--no-verify`, a `\` without a space, a comment
    at column 0, a `repo:` line), the bool guard in `judge` and the
    `starts` set of hook renames removed as dead.
  - Spec: 19 of 20 killed; `directories-read` is equivalent on Windows (a
    directory does not open) and is killed on Linux by the FIFO test.
  - Seven `^\s*-?\s*` patterns were quadratic on long lines and were
    rewritten before any review; a test feeds 200 000-character lines.
- Live run, first pass: the weakening of a `pyproject.toml` went THROUGH.
  Windows PowerShell 5.1 writes `Set-Content -Encoding utf8` with a BOM, the
  TOML reader refused the file, and the guard failed open. Fixed (`normal`),
  with a test; the later runs block the `ignore` edit, pass `line-length`
  100 -> 88, block `collect_ignore` in `tests/conftest.py`.
- Code review (Sonnet, 16 findings, all confirmed by probes, all fixed with
  a regression test each in `tests/test_config_review.py`). The heaviest
  were false blocks: the `[tool.ruff]` to `[tool.ruff.lint]` migration ruff
  asks for, `ignore` to `extend-ignore`, a mypy override whose module list
  was reordered, `select = ["ALL"]`, `pip install -e . && pytest`, `rsync
  --exclude`, `-p no:cacheprovider`, a new `pytest -m integration` job, a
  report rule set to its own default, a tox command moved between
  environments. Lists are now pooled per tool and key family, a code covered
  by a wider one is neither new nor lost, exclusion flags count only on a
  line that runs a check tool, a workflow edit that only adds lines may add
  pytest options. Misses fixed: `\` continuations, flake8 per-file codes on
  continuation lines, TOML times in the 3.9 reader.
- Security review (Sonnet, confirmed by probes; a hook past its timeout lets
  the edit through, so every slow input was a bypass), all fixed with tests
  in `tests/test_config_security.py`: the guard went blind on a file over
  1 MiB and on the break-weaken-repair sequence (both now block); four
  super-linear paths (`covered`, `judge_filters`, hook renames, the `set +e`
  regex, `\` continuations) over 10 s; a `replace_all` that needed
  gigabytes; file text with newlines and ESC copied into the message (now
  cut and cleaned); a lone surrogate in a logged path lost the block; a
  symlink to a share would be followed (link targets are read, not
  opened). Evasions fixed: JSON with comments in `pyrightconfig.json`,
  prefixes that crossed a code or path boundary (`D` covered `DTZ`, `build`
  covered `build*`, `tests` covered `tests/../src`), shortened warning
  actions (`i::`, `-W i`), `continue-on-error: True` and flow mappings,
  pre-commit `args` as a list, a quoted `#`, `skip (`, `from pytest import
  skip`, removing flake8's `max-complexity`.

### Deferred

- Not covered by design, in the README: JavaScript configs, `Makefile`,
  `.gitlab-ci.yml`, `tsconfig*.json`; a check step removed while the tool
  still runs elsewhere; `exclude: |` blocks and folded `run: >`; `echo
  pytest`; `if: ${{ 1 == 2 }}`; a YAML block list that splits an option from
  its value; a code moved from the global ruff `ignore` into
  `per-file-ignores` is blocked though it narrows; an entry added to one
  mypy override that the global section already had is not seen.
- Measure after two weeks of use with `PREFLIGHT_LOG=1`: blocks per rule
  label, and how many of them the user lifted with an exemption. A label
  that is mostly lifted is a false block to fix.
