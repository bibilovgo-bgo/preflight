from __future__ import annotations

import time

import pytest

import safety_guard as sg
from conftest import run_guard

MUST_BLOCK = [
    "rm -rf /",
    "rm -rf /*",
    "rm -rf ~",
    "rm -rf ~/",
    "rm -rf $HOME",
    "rm -rf *",
    "rm -fr .",
    "rm -r ..",
    "rm -rf ./*",
    "rm --recursive --force /usr",
    "rm -Rf /etc/",
    "sudo rm -rf /",
    "cd /tmp && rm -rf *",
    "true; rm -rf ~/*",
    "(rm -rf /)",
    "rm -rf /c/",
    "rm -rf C:/",
    "rm -rf '/'",
    "Remove-Item -Recurse -Force C:\\",
    "Remove-Item -Force -Recurse C:\\",
    "Remove-Item -Recurse -Force $HOME",
    "Remove-Item -Recurse -Force $env:USERPROFILE",
    "Remove-Item -Path * -Recurse -Force",
    "Remove-Item -Recurse -Force .",
    "Remove-Item -Recurse -Force ..\\*",
    'sqlite3 data/events.db "DROP TABLE events"',
    'psql -c "TRUNCATE users"',
    'mysql -e "drop database prod"',
    'sqlite3 db.sqlite "DELETE FROM events"',
    'sqlite3 db.sqlite "DELETE FROM events;"',
    'echo "DROP TABLE users;" | psql prod',
    "git -C /repo push --force origin main",
    "git -c core.x=y push -f",
    "git -C /repo reset --hard origin/main",
    "git push -fu origin main",
    "git push -u -f origin main",
    "git --git-dir=/r/.git clean -fd",
    "mkfs.ext4 -F /dev/sdb1",
    "dd if=x.iso of=/dev/mmcblk0",
    "git push --force origin main",
    "git push -f",
    "git push origin +main",
    "git reset --hard origin/main",
    "git reset --hard HEAD~3",
    "git reset --hard HEAD^",
    "git clean -fdx",
    "git clean -f",
    "git clean --force -d",
    "dd if=/dev/zero of=/dev/sda",
    "mkfs.ext4 /dev/sdb1",
    "echo x > /dev/sda",
    "sudo dd if=image.iso of=/dev/disk2 bs=4m",
    ":(){ :|:& };:",
    # prefixes and spellings a careless agent produces
    "/bin/rm -rf /",
    "\\rm -rf ~",
    "env rm -rf ~",
    "command rm -rf /",
    "time rm -rf /",
    "FOO=1 rm -rf /",
    "if true; then rm -rf /; fi",
    "{ rm -rf /; }",
    "ri -r -fo C:\\",
    "Remove-Item -Recurse -Force .",
    # a heredoc fed to a shell runs its body
    "bash <<'EOF'\nrm -rf ~\nEOF",
    "ssh host 'bash -s' <<'EOF'\ngit push --force origin main\nEOF",
]

MUST_PASS = [
    "git rm --cached data/events.db",
    "git commit -m 'guard against rm -rf / and DROP TABLE'",
    'echo "DROP TABLE is dangerous" >> notes.md',
    "rm -rf build/",
    "rm -rf ./node_modules/.cache",
    "rm -rf dist",
    "rm -f ./build/app.tmp",
    "rm -rf /tmp/build-123",
    "rm -f *.tmp",
    "rm *",
    "rm -rf ~/projects/old-clone",
    "rm -rf $HOME/.cache/pip",
    "rm -rf node_modules ",
    "Remove-Item $tempfile",
    "Remove-Item -Recurse -Force .\\build",
    "Remove-Item C:\\Users\\x\\AppData\\Local\\Temp\\msg.txt",
    "Remove-Item -Recurse C:\\",
    "git push origin main",
    "git push --force-with-lease origin feature",
    "git push --force-if-includes --force-with-lease",
    "git reset --hard",
    "git reset --soft HEAD~1",
    "git clean -n",
    "git clean -nfd",
    "git clean --dry-run -f",
    'sqlite3 db.sqlite "DELETE FROM events WHERE id = 3"',
    "python scripts/sync_docs.py",
    "grep -rf patterns.txt /",
    "grep -n 'mkfs' guards/safety_guard.py",
    "man dd",
    "grep -r 'dd if=/dev/zero of=/dev/sda' docs/",
    "",
    # heredoc and here-string bodies are data, not commands
    "git commit -F - <<'EOF'\nfix: refuse rm -rf / and git push --force\n\nrm -rf ~ used to pass.\nEOF",
    "cat > docs/danger.md <<'EOF'\nrm -rf ~\ngit clean -fdx\nEOF",
    "git commit -m @'\nblock rm -rf ~\n'@",
    "python - <<'EOF'\nprint('rm -rf /')\nEOF",
    "farm -rf /",
    "rm -rfv build/",
    # quoted messages and documentation are text (code review)
    "git commit -m 'drop (a); rm -rf /'",
    'git commit -m "fix sqlite3 DROP TABLE handling"',
    'git commit -m "feat: psql wrapper, add TRUNCATE guard"',
    "echo \"run: sqlite3 db 'DROP TABLE x'\" > doc.md",
    "git commit -m \"$(cat <<'EOF'\nfix: handle rm -rf paths\n\nrm -rf /\nEOF\n)\"",
    # not disks
    "dd if=/dev/zero of=/dev/null bs=1M count=100",
    "dd if=/dev/urandom of=/dev/stdout bs=1 count=4",
    "mkfs.ext4 disk.img",
    # only ignored build output
    "git clean -fdX",
]


HOSTILE = [
    "\n" * 100_000 + "rm -rf ~",
    " \n" * 50_000 + "rm -rf ~",
    "(rm -r " * 15_000,
    "psql " * 20_000 + "-c 'select 1'",
    "git push " * 20_000,
    "rm -r " + "a " * 50_000,
    "FOO=1 " * 20_000 + "rm -rf /",
]


@pytest.mark.parametrize("command", HOSTILE, ids=range(len(HOSTILE)))
def test_long_hostile_command_is_scanned_fast(command):
    started = time.perf_counter()
    sg.scan(command)
    assert time.perf_counter() - started < 2.0


def test_long_prefix_still_blocks():
    assert sg.scan("\n" * 100_000 + "rm -rf ~")
    assert sg.scan("FOO=1 " * 20_000 + "rm -rf /")


@pytest.mark.parametrize("command", MUST_BLOCK)
def test_blocks(command):
    assert sg.scan(command), command


@pytest.mark.parametrize("command", MUST_PASS)
def test_passes(command):
    assert sg.scan(command) == [], command


def test_every_rule_is_exercised():
    """Each rule must be reached by at least one blocking example."""
    hit = {label for command in MUST_BLOCK for label in sg.scan(command)}
    assert hit == {label for label, _ in sg.RULES}


def test_process_blocks_with_reason():
    done = run_guard("safety_guard", {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
    assert done.returncode == 2
    assert "preflight/safety" in done.stderr.decode("utf-8")


def test_process_passes_safe_command():
    done = run_guard("safety_guard", {"tool_name": "Bash", "tool_input": {"command": "ls -la"}})
    assert done.returncode == 0
    assert done.stderr == b""


def test_off_switch():
    payload = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
    assert run_guard("safety_guard", payload, env={"PREFLIGHT_SAFETY": "0"}).returncode == 0
