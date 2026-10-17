from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import git_commands as gc
import secret_patterns as sp
import secret_scan as ss
import wrappers
from conftest import git, run_guard

# Built from parts so this file is not itself a finding for any scanner.
KEY = "sk-or-v1-" + "Ab1" * 10
LINE = f"KEY = '{KEY}'"


def commit_payload(command: str, cwd: Path, tool: str = "Bash") -> dict:
    return {"tool_name": tool, "cwd": str(cwd), "tool_input": {"command": command}}


def stage(repo: Path, name: str, text: str) -> None:
    (repo / name).write_text(text + "\n", encoding="utf-8")
    git(repo, "add", name)


def scan_code(repo: Path, command: str, tool: str = "Bash") -> int:
    return run_guard("secret_scan", commit_payload(command, repo, tool)).returncode


# --- process level: real repositories ----------------------------------------


def test_staged_secret_blocks(repo):
    stage(repo, "conf.py", LINE)
    assert scan_code(repo, "git commit -m 'add config'") == 2


def test_block_message_masks_the_secret(repo):
    stage(repo, "conf.py", LINE)
    done = run_guard("secret_scan", commit_payload("git commit -m x", repo))
    err = done.stderr.decode("utf-8")
    assert "conf.py" in err and KEY not in err and KEY[:4] in err


def test_clean_commit_passes(repo):
    stage(repo, "conf.py", "x = 1")
    assert scan_code(repo, "git commit -m 'x'") == 0


def test_pragma_line_passes(repo):
    stage(repo, "conf.py", LINE + "  # pragma: allowlist secret")
    assert scan_code(repo, "git commit -m x") == 0


def test_content_starting_with_plus_plus_is_content(repo):
    stage(repo, "conf.py", "++" + LINE)
    assert scan_code(repo, "git commit -m x") == 2


def test_next_file_header_is_not_content(repo):
    stage(repo, "a.txt", "hello")
    stage(repo, KEY + ".txt", "hello")
    assert scan_code(repo, "git commit -m x") == 0


def test_color_config_does_not_blind_the_scan(repo):
    git(repo, "config", "color.ui", "always")
    stage(repo, "conf.py", LINE)
    assert scan_code(repo, "git commit -m x") == 2


def test_commit_all_includes_unstaged_tracked_change(repo):
    (repo / "README.md").write_text(LINE + "\n", encoding="utf-8")
    assert scan_code(repo, "git commit -am 'update readme'") == 2
    assert scan_code(repo, "git commit --all -m x") == 2


def test_plain_commit_ignores_unstaged_change(repo):
    (repo / "README.md").write_text(LINE + "\n", encoding="utf-8")
    assert scan_code(repo, "git commit -m x") == 0


def test_commit_with_path_includes_its_unstaged_change(repo):
    (repo / "README.md").write_text(LINE + "\n", encoding="utf-8")
    assert scan_code(repo, "git commit -m x README.md") == 2
    assert scan_code(repo, "git commit -m x -- README.md") == 2


def test_git_dash_c_scans_that_repository(repo, tmp_path):
    stage(repo, "conf.py", LINE)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert scan_code(elsewhere, f'git -C "{repo.as_posix()}" commit -m x') == 2


def test_cd_before_commit_scans_that_repository(repo, tmp_path):
    stage(repo, "conf.py", LINE)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert scan_code(elsewhere, f'cd "{repo.as_posix()}" && git commit -m x') == 2


def test_powershell_commit_is_scanned(repo):
    stage(repo, "conf.py", LINE)
    assert scan_code(repo, "git commit -F C:\\Temp\\msg.txt", tool="PowerShell") == 2


def test_words_git_commit_in_text_do_not_scan(repo):
    stage(repo, "conf.py", LINE)
    assert scan_code(repo, "echo 'remember to git commit later'") == 0
    assert scan_code(repo, "python - <<'EOF'\nprint('git commit')\nEOF") == 0


def test_commit_message_heredoc_still_scans(repo):
    stage(repo, "conf.py", LINE)
    command = "git commit -F - <<'EOF'\nfeat: add config\nEOF"
    assert scan_code(repo, command) == 2


def test_off_switch(repo):
    stage(repo, "conf.py", LINE)
    payload = commit_payload("git commit -m x", repo)
    assert run_guard("secret_scan", payload, env={"PREFLIGHT_SECRETS": "0"}).returncode == 0


def test_outside_a_repository_passes(tmp_path):
    assert scan_code(tmp_path, "git commit -m x") == 0


# --- command parsing ---------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "all_tracked", "paths"),
    [
        ("git commit -m 'msg'", False, ()),
        ("git commit -am 'msg'", True, ()),
        ("git commit -a -m msg", True, ()),
        ("git commit -mfoo", False, ()),
        ("git commit -m msg -- a.py b.py", False, ("a.py", "b.py")),
        ("git commit a.py -m msg", False, ("a.py",)),
        ("git commit -S -m msg", False, ()),
        ("git commit --author 'A <a@b>' -m msg", False, ()),
        ("git commit -va", True, ()),
        ("git commit -F msg.txt", False, ()),
        ("git commit -m x -- -dash.py", False, ("-dash.py",)),
        ('"C:/Program Files/Git/cmd/GIT.EXE" commit -m x', False, ()),
        ("(git commit -m x)", False, ()),
    ],
)
def test_commit_arguments(tmp_path, command, all_tracked, paths):
    commits = gc.find_commits(command, tmp_path, powershell=False)
    assert commits == [gc.Commit(tmp_path, all_tracked, paths)]


@pytest.mark.parametrize(
    "command",
    [
        "git status",
        "git log --grep commit",
        "echo git commit",
        "gitk commit",
        "git -c x=y status",
        "git -C",
        "git --no-pager",
        "git",
    ],
)
def test_not_a_commit(tmp_path, command):
    assert gc.find_commits(command, tmp_path, powershell=False) == []


def test_env_and_timeout_prefixes(tmp_path):
    for command in (
        "FOO=1 git commit -m x",
        "timeout 60 git commit -m x",
        "env -C sub git commit -m x",
    ):
        commits = gc.find_commits(command, tmp_path, powershell=False)
        assert len(commits) == 1, command


def test_unparseable_command_returns_none(tmp_path):
    assert gc.find_commits("git commit -m 'unclosed", tmp_path, powershell=False) is None


# --- patterns ----------------------------------------------------------------

SECRETS = [
    "sk-ant-api03-" + "aB3" * 12,
    "sk-proj-" + "aB3" * 12,
    "sk-or-v1-" + "aB3" * 12,
    "ghp_" + "aB3" * 12,
    "github_pat_" + "aB3_" * 12,
    "xoxb-" + "123456789012-abc",
    "AIza" + "Sy" + "a" * 33,
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "gsk_" + "aB3" * 10,
    "123456789:" + "AA" + "b" * 33,
    "sk_live_" + "aB3" * 8,
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "api_key = '" + "q8Zr2Lm0Xc7Vb" + "'",
    'DB_PASSWORD: "' + "hunter2hunter2" + '"',
    # the config shapes a quoted-only pattern missed
    "GITHUB_TOKEN=" + "aB3" * 10,
    "secret: " + "aB3" * 10,
    '"password": "' + "S3cretPass12" + '"',
    "{'password': '" + "hunter2hunter2" + "'}",
    'DATABASE_URL="postgres://admin:' + "S3cretPass" + '@host/db"',
]

NOT_SECRETS = [
    "the risk-assessment-framework-v2 doc",
    "sk-learn-preprocessing-pipelines-guide",
    'TOKEN_VAR = "OPENAI_API_KEY_NAME"',
    'api_key = "${OPENAI_API_KEY}xyz"',  # pragma: allowlist secret
    'password = "<your-password-here>"',  # pragma: allowlist secret
    "token = os.environ['API_TOKEN']",
    "def get_secret(name):",
    # false positives reported by the code review
    'TOKEN_URL = "https://oauth2.googleapis.com/token"',
    'tokenizer_name = "bert-base-uncased"',
    'PASSWORD_RESET_URL = "/accounts/password/reset/confirm"',
    'secret_path = "/run/secrets/db_password"',
    'api_key_env = "my_service_api_key"',
    'api_key = "your-api-key-here"',  # pragma: allowlist secret
    'csrf_token = "csrf-token-value-here"',  # pragma: allowlist secret
    'password_field = "password_confirmation"',
    "password_hash = 'pbkdf2_sha256$600000$abcdefgh$xyz'",
    "token = get_token(user2, scope)",
    "publishable = 'pk_live_" + "aB3" * 8 + "'",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_" + "x" * 36,
    "acct_" + "aB3" * 5,
    "DATABASE_URL=postgres://postgres:postgres@localhost/db",
    "token_ttl_seconds = 360000000000",
]


@pytest.mark.parametrize(
    "path",
    [".env", "config/.env.production", "certs/server.pem", "deploy/id_ed25519", "keys/app.p12"],
)
def test_secret_file_names_are_reported(path):
    hits = sp.find_secrets(one_line_diff("x = 1", path))
    assert hits == [f"{path}: a file that holds secrets by its name"]


@pytest.mark.parametrize(
    "path", [".env.example", ".env.sample", "id_ed25519.pub", "docs/env.md", "src/key.py"]
)
def test_ordinary_file_names_are_not_reported(path):
    assert sp.find_secrets(one_line_diff("x = 1", path)) == []


@pytest.mark.parametrize("value", SECRETS)
def test_secret_patterns(value):
    diff = f"diff --git a/f b/f\n+++ b/f\n@@ -0,0 +1 @@\n+{value}\n"
    assert sp.find_secrets(diff), value


@pytest.mark.parametrize("value", NOT_SECRETS)
def test_not_secret_patterns(value):
    diff = f"diff --git a/f b/f\n+++ b/f\n@@ -0,0 +1 @@\n+{value}\n"
    assert sp.find_secrets(diff) == [], value


def one_line_diff(value: str, path: str = "f") -> str:
    return f"diff --git a/{path} b/{path}\n+++ b/{path}\n@@ -0,0 +1 @@\n+{value}\n"


# The expected label is spelled out here rather than read from sp.PATTERNS: a
# mutant that drops a pattern from the module would otherwise drop it from the
# test as well. Each value sits exactly at the pattern's minimum length.
AT_MINIMUM = [  # (at the minimum, one short of it, label)
    ("sk-ant-" + "a1" * 10, "sk-ant-" + "a1" * 9 + "a", "Anthropic API key"),
    ("sk-" + "a" * 19 + "1", "sk-" + "a" * 18 + "1", "sk- API key"),
    ("ghp_" + "a" * 30, "ghp_" + "a" * 29, "GitHub token"),
    ("github_pat_" + "a" * 40, "github_pat_" + "a" * 39, "GitHub token"),
    ("xoxb-" + "a" * 10, "xoxb-" + "a" * 9, "Slack token"),
    ("AIza" + "a" * 35, "AIza" + "a" * 34, "Google API key"),
    ("AKIA" + "A" * 16, "AKIA" + "A" * 15, "AWS access key id"),
    ("gsk_" + "a" * 20, "gsk_" + "a" * 19, "Groq key"),
    ("12345678:" + "a" * 33, "12345678:" + "a" * 32, "Telegram bot token"),
    ("sk_live_" + "a" * 16, "sk_live_" + "a" * 15, "Stripe secret key"),
    ("fl_live_" + "a" * 12, "fl_live_" + "a" * 11, "Stripe file link"),
    ("npm_" + "a" * 36, "npm_" + "a" * 35, "npm token"),
    ("SG." + "a" * 22 + "." + "b" * 43, "SG." + "a" * 21 + "." + "b" * 43, "SendGrid key"),
    ("-----BEGIN RSA PRIVATE KEY", "-----BEGIN RSA PUBLIC KEY", "private key block"),
    ("postgres://admin:S3cret@db", "postgres://admin:S3crt@db", "password in a URL"),
    ("token = '" + "a1" * 6 + "'", "token = '" + "a1" * 5 + "a'", "assigned secret"),
]


@pytest.mark.parametrize(("value", "_short", "label"), AT_MINIMUM)
def test_pattern_matches_at_minimum_length(value, _short, label):
    hits = sp.find_secrets(one_line_diff(value))
    assert len(hits) == 1 and hits[0].startswith(f"f: {label} {value[:4]}...")


@pytest.mark.parametrize(("_value", "short", "label"), AT_MINIMUM)
def test_pattern_misses_one_short_of_minimum(_value, short, label):
    # A shorter Anthropic key is still a valid generic `sk-` key; only its own
    # label must not fire.
    assert all(f": {label} " not in hit for hit in sp.find_secrets(one_line_diff(short))), short


def test_every_pattern_is_covered():
    assert {label for _v, _s, label in AT_MINIMUM} == {label for label, _ in sp.PATTERNS}


def test_line_matching_two_patterns_is_reported_once():
    value = "sk-ant-" + "a1" * 12  # also a valid `sk-` key
    hits = sp.find_secrets(one_line_diff(value))
    assert hits == [f"f: Anthropic API key {sp.mask(value)}"]


def test_hit_names_the_file():
    assert sp.find_secrets(one_line_diff(KEY, "conf/app.py"))[0].startswith("conf/app.py: ")


def test_removed_lines_are_ignored():
    diff = f"diff --git a/f b/f\n+++ b/f\n@@ -1 +0,0 @@\n-{KEY}\n"
    assert sp.find_secrets(diff) == []


def test_mask_keeps_only_a_prefix():
    assert sp.mask("sk-abcdefghijklmnop") == "sk-a...(19 chars)"


# --- failure modes found by the mutation run ---------------------------------


def test_external_diff_in_repo_config_cannot_blind_the_scan(repo):
    git(repo, "config", "diff.external", "true")
    stage(repo, "conf.py", LINE)
    assert scan_code(repo, "git commit -m x") == 2


def test_git_failure_reads_as_empty_diff(monkeypatch, tmp_path):
    def boom(*_a, **_k):
        raise OSError("git is missing")

    monkeypatch.setattr(ss.subprocess, "run", boom)
    assert ss._git_diff(tmp_path) == ""
    assert ss.commit_diff(gc.Commit(tmp_path, True, ("a.py",))) == "\n"


def test_unparseable_command_still_scans_the_working_repository(repo):
    stage(repo, "conf.py", LINE)
    assert scan_code(repo, "git commit -m 'unclosed") == 2


def test_unparseable_commit_all_includes_unstaged_change(repo):
    (repo / "README.md").write_text(LINE + "\n", encoding="utf-8")
    assert scan_code(repo, "git commit -a -m 'unclosed") == 2


@pytest.mark.skipif(sys.platform != "win32", reason="backslash paths are a Windows shape")
def test_powershell_backslash_path_to_another_repository(repo, tmp_path):
    stage(repo, "conf.py", LINE)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert scan_code(elsewhere, f"git -C {repo} commit -m x", tool="PowerShell") == 2


def test_block_lists_at_most_ten_hits(repo):
    lines = [f"K{i} = '{KEY}{i}'" for i in range(12)]
    stage(repo, "conf.py", "\n".join(lines))
    done = run_guard("secret_scan", commit_payload("git commit -m x", repo))
    shown = [ln for ln in done.stderr.decode("utf-8").splitlines() if ln.startswith("  - ")]
    assert len(shown) == 10


def test_log_records_only_file_names(repo, tmp_path):
    stage(repo, "conf.py", LINE)
    data = tmp_path / "data"
    payload = commit_payload("git commit -m x", repo)
    run_guard("secret_scan", payload, env={"PREFLIGHT_LOG": "1", "CLAUDE_PLUGIN_DATA": str(data)})
    text = (data / "log" / "secrets.jsonl").read_text(encoding="utf-8")
    assert json.loads(text)["hits"] == ["conf.py"] and KEY[:6] not in text


# --- findings of the security review -------------------------------------------


def untracked(repo: Path, name: str, text: str) -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")


@pytest.mark.parametrize(
    "command",
    [
        "git add -A && git commit -m x",
        "git add leak.py; git commit -m x",
        "git add . && git commit -m x",
        "git add --all\ngit commit -m x",
        "git stage leak.py && git commit -m x",
        "git add -- leak.py && git commit -m x",
    ],
)
def test_add_then_commit_in_one_command_scans_untracked_files(repo, command):
    untracked(repo, "leak.py", LINE)
    assert scan_code(repo, command) == 2


def test_add_of_another_file_does_not_scan_the_untracked_leak(repo):
    untracked(repo, "leak.py", LINE)
    untracked(repo, "ok.py", "x = 1")
    assert scan_code(repo, "git add ok.py && git commit -m x") == 0


def test_ignored_file_is_not_scanned(repo):
    untracked(repo, ".gitignore", ".env")
    untracked(repo, ".env", LINE)
    assert scan_code(repo, "git add -A && git commit -m x") == 0


def test_add_then_commit_includes_modified_tracked_file(repo):
    (repo / "README.md").write_text(LINE + "\n", encoding="utf-8")
    assert scan_code(repo, "git add README.md && git commit -m x") == 2


def test_add_in_another_repository_is_not_carried_over(repo, tmp_path):
    untracked(repo, "leak.py", LINE)
    other = tmp_path / "other"
    other.mkdir()
    git(other, "init", "-q")
    command = f'git -C "{other.as_posix()}" add -A && git commit -m x'
    assert scan_code(repo, command) == 0


@pytest.mark.parametrize(
    ("command", "tool"),
    [
        ("bash -c 'git commit -m x'", "Bash"),
        ('sh -c "git add -A && git commit -m x"', "Bash"),
        ("bash -lc 'git commit -m x'", "Bash"),
        ('powershell -Command "git commit -m x"', "PowerShell"),
        ("pwsh -c git commit -m x", "PowerShell"),
        ("cmd /c git commit -m x", "PowerShell"),
    ],
)
def test_wrapped_commit_is_scanned(repo, command, tool):
    stage(repo, "conf.py", LINE)
    assert scan_code(repo, command, tool=tool) == 2


def test_wrapping_depth_is_limited(tmp_path):
    command = "bash -c 'git commit -m x'"
    for _ in range(5):
        command = "bash -c " + json.dumps(command)
    assert gc.find_commits(command, tmp_path, powershell=False) == []


@pytest.mark.parametrize("before", ["progress 50%\r", "\x0c", "\x0b", "\x1c", "\x1e"])
def test_secret_after_a_line_breaking_control_character_is_found(repo, before):
    (repo / "log.txt").write_bytes((before + LINE + "\n").encode("utf-8"))
    git(repo, "add", "log.txt")
    assert scan_code(repo, "git commit -m x") == 2


def test_utf16_file_is_read(repo):
    (repo / "secrets.ps1").write_bytes(("\ufeff" + LINE + "\r\n").encode("utf-16-le"))
    git(repo, "add", "secrets.ps1")
    assert scan_code(repo, "git commit -m x") == 2


def test_file_with_nul_byte_is_read(repo):
    (repo / "blob.dat").write_bytes(b"\x00\x01" + LINE.encode("utf-8") + b"\n")
    git(repo, "add", "blob.dat")
    assert scan_code(repo, "git commit -m x") == 2


def test_minus_diff_attribute_does_not_hide_the_file(repo):
    untracked(repo, ".gitattributes", "*.lock -diff")
    stage(repo, "deps.lock", LINE)
    assert scan_code(repo, "git commit -m x") == 2


def marker_command(tmp_path: Path) -> tuple[str, Path]:
    """A command line that, if git ever runs it, creates a marker file."""
    marker = tmp_path / "ran.txt"
    script = tmp_path / "evil.py"
    script.write_text(f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8")
    return f'"{Path(sys.executable).as_posix()}" "{script.as_posix()}"', marker


def test_textconv_from_repo_config_is_not_run(repo, tmp_path):
    command, marker = marker_command(tmp_path)
    git(repo, "config", "diff.x.textconv", command)
    untracked(repo, ".gitattributes", "*.txt diff=x")
    stage(repo, "a.txt", LINE)
    assert scan_code(repo, "git commit -m x") == 2
    assert not marker.exists()


def test_fsmonitor_from_repo_config_is_not_run(repo, tmp_path):
    command, marker = marker_command(tmp_path)
    git(repo, "config", "core.fsmonitor", command)
    (repo / "README.md").write_text(LINE + "\n", encoding="utf-8")
    assert scan_code(repo, "git add -A && git commit -am x") == 2
    assert not marker.exists()


HOSTILE_LINES = [
    "sk-" * 40_000,
    "secret" * 20_000,
    "api_key" * 15_000,
    "token" * 20_000 + " ",
    "a" * 200_000,
]


@pytest.mark.parametrize("line", HOSTILE_LINES, ids=range(len(HOSTILE_LINES)))
def test_long_hostile_line_is_scanned_fast(line):
    import time

    started = time.perf_counter()
    sp.find_secrets(one_line_diff(line))
    assert time.perf_counter() - started < 2.0


def test_secret_deep_in_a_long_line_is_found():
    line = "x" * 50_000 + " " + KEY + " " + "y" * 50_000
    assert sp.find_secrets(one_line_diff(line))


@pytest.mark.parametrize("offset", [0, 3_990, 100_000])
def test_secret_anywhere_in_a_long_line_is_found(offset):
    line = "x" * offset + " " + KEY + " " + "y" * 9000
    assert sp.find_secrets(one_line_diff(line))


# --- holes found by the mutation run after the reviews --------------------------

# A zero inside the value: a mutant that turns `[0-9...]` into `[1-9...]` must fail.
WITH_ZERO = [
    ("AIza" + "a0" * 17 + "a", "Google API key"),
    ("AKIA" + "A0" * 8, "AWS access key id"),
    ("npm_" + "a0" * 9 + "b9" * 9, "npm token"),
    ("fl_live_" + "a0a9" * 3, "Stripe file link"),
    ("sk-1" + "a" * 19, "sk- API key"),
    ("s3://user:S3cret1@bucket", "password in a URL"),  # pragma: allowlist secret
]


@pytest.mark.parametrize(("value", "label"), WITH_ZERO)
def test_patterns_accept_zero_digits_and_short_schemes(value, label):
    hits = sp.find_secrets(one_line_diff(value))
    assert len(hits) == 1 and f": {label} " in hits[0]


@pytest.mark.parametrize(
    ("line", "counts"),
    [
        # all-caps key without an underscore
        ('token = "ABCD1234EFGH5678"', True),  # pragma: allowlist secret
        ('token = "API_KEY_V9_NAME9"', False),  # an env var name  pragma: allowlist secret
        ('secret_path = "/run/s3crets/db1"', False),  # a path
        ("token_file = '.config/app1.yml'", False),  # a relative path
    ],
)
def test_plausible_value_rules(line, counts):
    assert bool(sp.find_secrets(one_line_diff(line))) is counts


def test_secret_file_name_hit_is_clipped():
    path = "d" * 300 + "/.env"
    hit = sp.find_secrets(one_line_diff("x = 1", path))[0]
    assert len(hit.split(": ", 1)[0]) == 200


def test_add_args_respects_double_dash_and_value_options():
    assert gc.add_args(["--", "-weird.py"]) == ["-weird.py"]
    assert gc.add_args(["--chmod", "+x", "run.sh"]) == ["run.sh"]
    assert gc.add_args(["-A"]) == [gc.ALL]


def test_only_cmd_takes_a_slash_c_wrapper():
    assert wrappers.inner_command(["ls", "/c", "git commit -m x"]) is None
    assert wrappers.inner_command(["cmd", "/c", "git", "commit"]) == ("git commit", True)


@pytest.mark.parametrize(("wraps", "found"), [(3, 1), (4, 0)])
def test_wrapping_depth_boundary(tmp_path, wraps, found):
    command = "git commit -m x"
    for _ in range(wraps):
        command = "bash -c " + json.dumps(command)
    assert len(gc.find_commits(command, tmp_path, powershell=False)) == found


def test_large_untracked_file_is_skipped(repo):
    untracked(repo, "big.py", LINE + "\n" + "x = 1\n" * 200_000)
    assert scan_code(repo, "git add -A && git commit -m x") == 0


def test_add_from_a_subdirectory_scans_untracked_files_above_it(repo):
    (repo / "sub").mkdir()
    untracked(repo, "leak.py", LINE)
    assert scan_code(repo / "sub", "git add -A && git commit -m x") == 2


def test_hostile_file_name_is_flattened_in_the_message():
    name = "a" + chr(0x202E) + "b" + chr(0x200B) + "c\x1b[31m" + "d" * 400 + ".py"
    hit = sp.find_secrets(one_line_diff(KEY, name))[0]
    path = hit.split(": ", 1)[0]
    assert chr(0x202E) not in path and chr(0x200B) not in path and "\x1b" not in path
    assert len(path) <= 200
