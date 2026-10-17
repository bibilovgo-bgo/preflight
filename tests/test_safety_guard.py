from __future__ import annotations

import shlex
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
    # commands wrapped in a shell, ssh or PowerShell run all the same
    "bash -c 'rm -rf ~'",
    "sh -ec 'rm -rf /'",
    "pwsh -c Remove-Item -Recurse -Force C:/",
    'powershell -Command "Remove-Item -Recurse -Force $HOME"',
    "cmd /c rm -rf /",
    "ssh -p 2222 -i ~/.ssh/k root@1.2.3.4 'rm -rf /'",
    "ssh prod 'git push --force origin main'",
    "ssh prod \"bash -c 'rm -rf ~'\"",
    "ssh prod rm -rf /var",
    "cd /x && ssh prod 'psql -c \"DROP TABLE users\"'",
    # on a remote host any absolute recursive delete is the site or its data
    'ssh prod "rm -rf /var/www"',
    'ssh -p 2222 h "rm -r /srv/data"',
    "ssh prod \"bash -c 'rm -rf /home/app'\"",
    "ssh prod 'cd /x; sudo rm -rf /opt/app/data'",
    "ssh -o StrictHostKeyChecking=no prod 'rm -rf \"/opt/app\"'",
    # options after the host, `--`, launchers around ssh (review findings)
    "ssh host -t 'sudo rm -rf /var/www'",
    "ssh host -tt rm -rf /var/www",
    "ssh user@host -p 22 'rm -rf /var/www'",
    "ssh host -- 'rm -rf /var/www'",
    "sshpass -p x ssh host 'rm -rf /var/www'",
    "mosh host -- rm -rf /var/www",
    "autossh -M 0 host 'rm -rf /var/www'",
    "ssh host 'sudo -u www rm -rf /var/www'",
    "ssh host 'nice -n 5 rm -rf /var/www'",
    "ssh host <<'EOF'\nrm -rf /var/www\nEOF",
    "ssh host bash <<'EOF'\ncd /x\nrm -rf /var/www\nEOF",
    "ssh host 'rm -rf /tmp/../etc'",
    "ssh host 'rm -rf /var/www/__pycache__/../app'",
    "ssh host \"rm -rf '/srv/my app'\"",
    # prefixes with values and other launchers, locally
    "sudo -u root rm -rf /",
    "sudo -n rm -rf /",
    "sudo -u x bash -c 'rm -rf ~'",
    "doas -u root rm -rf /",
    "su -c 'rm -rf /'",
    "su root -c 'rm -rf ~'",
    "wsl rm -rf ~",
    "wsl -d Ubuntu -e rm -rf /",
    "docker exec app sh -c 'rm -rf /'",
    "kubectl exec pod -- rm -rf /",
    "bash -o pipefail -c 'rm -rf ~'",
    'cmd /c "rd /s /q C:\\\\"',
    "rd /S /Q C:\\",
    "del /s /q *",
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
    # wrappers around harmless commands, and deploy cleanups on a server
    "bash -c 'rm -rf build/'",
    'ssh prod "ls -la /var/www"',
    "ssh prod",
    "ssh -p 2222 prod",
    "ssh prod 'rm -rf /opt/metaai/core/__pycache__'",
    "ssh prod 'rm -rf /tmp/upload-123'",
    "ssh prod 'rm -f /var/log/app.log'",
    "ssh prod 'cd /opt/app && rm -rf build'",
    "ssh prod 'rm -rf $RELEASE_DIR'",
    "rm -rf /var/www",
    "bash -c 'rm -rf /var/www'",
    'git commit -m "ssh prod rm -rf /"',
    "echo 'bash -c \"rm -rf ~\"' >> notes.md",
    "ssh host \"rm -rf '/tmp'\"",
    "ssh host 'rm -rf /tmp/build-1 /tmp/build-2'",
    "bash deploy.sh -c 'rm -rf /'",
    "ssh host -t 'ls /var/www'",
    "sudo -u www ls /var/www",
    "docker exec app rm -rf /app/cache",
    "rd /s /q build",
    "cat > notes.md <<'EOF'\nrm -rf /var/www\nEOF",
    "del /q C:\\tmp\\x.log",
    "find . -name '*.pyc' -exec rm -f {} +",
    "rm -rf ./{a,b}",
]


HOSTILE = [
    "\n" * 100_000 + "rm -rf ~",
    " \n" * 50_000 + "rm -rf ~",
    "(rm -r " * 15_000,
    "psql " * 20_000 + "-c 'select 1'",
    "git push " * 20_000,
    "rm -r " + "a " * 50_000,
    "FOO=1 " * 20_000 + "rm -rf /",
    "ssh " * 20_000,
    "bash -c " * 20_000,
    "ssh h " * 10_000 + "rm -rf /x",
    "bash -c 'bash -c \"bash -c " * 3_000,
    "{rm -r " * 8_000,
    "{git push " * 8_000,
    "ssh h '" + "{rm -r " * 5_000 + "'",
    "sudo -u x " * 10_000 + "rm -rf /",
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
    assert hit == {label for label, _ in sg.RULES} | {sg.REMOTE_LABEL}


def test_wrapping_deeper_than_the_limit_is_not_followed():
    """Nesting is followed MAX_DEPTH levels deep, so a crafted command cannot recurse forever."""
    inner = "rm -rf ~"
    for _ in range(sg.MAX_DEPTH):
        inner = "bash -c " + shlex.quote(inner)
    assert sg.scan(inner)
    assert sg.scan("bash -c " + shlex.quote(inner)) == []


def test_powershell_cmd_wrapper_reads_backslashes():
    assert sg.scan("cmd /c rd /s /q C:\\", powershell=True)


def test_process_parses_powershell_by_tool_name():
    """`bash -c \\"rm -rf ~\\"` is one quoted word only in PowerShell, where `\\` is no escape."""
    command = 'bash -c \\"rm -rf ~\\"'
    assert sg.scan(command, powershell=True) != sg.scan(command)
    expected = 2 if sg.scan(command, powershell=True) else 0
    payload = {"tool_name": "PowerShell", "tool_input": {"command": command}}
    assert run_guard("safety_guard", payload).returncode == expected
    payload = {"tool_name": "Bash", "tool_input": {"command": command}}
    assert run_guard("safety_guard", payload).returncode == 2 - expected


def test_remote_rule_names_the_host_case():
    assert sg.scan('ssh prod "rm -rf /var/www"') == [sg.REMOTE_LABEL]
    assert sg.REMOTE_LABEL not in sg.scan("rm -rf /")


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
