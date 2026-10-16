# Changelog

## 0.1.0 (unreleased)

First version: five guards and a scan command.

- `edit`: blocks an Edit whose anchor is missing, ambiguous without
  `replace_all`, or identical to the replacement; points at the closest line.
- `safety`: blocks recursive deletes of a root, home, current, parent or system
  directory, SQL DROP / TRUNCATE / unconditional DELETE through a database
  client, force push, hard reset to a remote or older commit, `git clean`, disk
  formatters and raw writes to disks. Heredoc and quoted text is not a command.
- `secrets`: blocks a commit whose content carries a credential, including what
  a `git add` earlier in the same command stages and commits wrapped in
  `bash -c`, `powershell -Command` or `cmd /c`.
- `browser`: blocks reading a page right after loading it, and DOM property
  reads that throw on a missing element.
- `clone_scan`: after a clone, reports to the model what in the repository runs
  when the folder is opened; never follows links, never runs the repository's
  programs, never lets a failing check go silent.
- `/preflight:scan <folder>`: the same scan for a folder that was not cloned.
