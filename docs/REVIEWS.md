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
  `shell_pipes.py` or `safety_guard.py`.
- Not covered by design, documented in README: paths held in variables,
  loops that send a file line by line, `echo cmd | sh`, the text of `<<<`
  and unquoted heredoc bodies, commands run through MCP terminal tools.
