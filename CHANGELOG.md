# Changelog

## 0.1.0 (unreleased)

First version: five guards and a scan command.

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
- `clone_scan`: after a clone, reports to the model what in the repository runs
  when the folder is opened; never follows links, never runs the repository's
  programs, never lets a failing check go silent.
- `/preflight:scan <folder>`: the same scan for a folder that was not cloned.

The `keys` guard and the safety unwrapping went through two mutation runs and
three reviews (see `docs/REVIEWS.md`). The fixes from the third review are in
the code but have no dedicated regression tests yet; that is the first task of
the next stage that touches these guards.

An Edit guard was built and removed before release: a live test showed that
current Claude Code rejects drifted, ambiguous and no-op Edit anchors itself,
before any hook is called.
