from __future__ import annotations

import pytest

import wrappers as w


@pytest.mark.parametrize(
    ("words", "inner"),
    [
        (["bash", "-c", "rm -rf ~"], "rm -rf ~"),
        (["bash", "-o", "pipefail", "-c", "x"], "x"),
        (["bash", "-lc", "x"], "x"),
        (["bash", "deploy.sh", "-c", "x"], None),
        (["bash", "-c"], None),
        (["pwsh", "-NoProfile", "-Command", "Remove-Item", "x"], "Remove-Item x"),
        (["cmd", "/c", "rd", "/s", "x"], "rd /s x"),
        (["su", "root", "-c", "rm -rf ~"], "rm -rf ~"),
        (["su", "-"], None),
        (["wsl", "-d", "Ubuntu", "-e", "rm", "-rf", "/"], "rm -rf /"),
        (["wsl"], None),
        (["git", "commit"], None),
        (["git", "/c", "x"], None),
        (["wsl", "--exec", "ls"], "ls"),
        (["su", "-c"], None),
        ([], None),
    ],
)
def test_local_wrappers(words, inner):
    found = w.inner_command(words)
    assert (found[0] if found else None) == inner


@pytest.mark.parametrize(
    ("words", "inner"),
    [
        (["ssh", "-p", "2222", "-i", "k", "host", "rm -rf /x"], "rm -rf /x"),
        (["ssh", "host", "-t", "-p", "22", "--", "rm", "-rf", "/x"], "rm -rf /x"),
        (["ssh", "host"], None),
        (["autossh", "-M", "0", "host", "ls"], "ls"),
        (["mosh", "host", "--", "ls", "-la"], "ls -la"),
        (["sshpass", "-p", "x", "ssh", "host", "ls"], "ssh host ls"),
        (["docker", "exec", "-u", "root", "app", "sh", "-c", "x y"], "sh -c 'x y'"),
        (["docker", "run", "img"], None),
        (["docker"], None),
        (["ssh", "host", "--", "-weird", "x"], "-weird x"),
        (["kubectl", "exec", "pod", "--", "rm", "-rf", "/"], "rm -rf /"),
        (["kubectl", "exec", "pod"], None),
    ],
)
def test_elsewhere_wrappers_are_opt_in(words, inner):
    assert w.inner_command(words) is None, "a commit made elsewhere is not this repository's"
    found = w.inner_command(words, ssh=True)
    assert (found[0] if found else None) == inner


def test_powershell_flag():
    assert w.inner_command(["pwsh", "-c", "x"]) == ("x", True)
    assert w.inner_command(["cmd", "/c", "x"]) == ("x", True)
    assert w.inner_command(["bash", "-c", "x"]) == ("x", False)


def test_is_remote():
    assert w.is_remote(["/usr/bin/ssh", "h"])
    assert w.is_remote(["mosh", "h"])
    assert not w.is_remote(["sshpass", "ssh"])
    assert not w.is_remote([])
