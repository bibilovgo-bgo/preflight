from __future__ import annotations

import os
import sys

import pytest

import fact_classes as fc


@pytest.fixture
def root(tmp_path):
    (tmp_path / ".git").mkdir()
    return tmp_path


def cls(root, path, text="", globs=None):
    return fc.classify(path, text, root, globs or []).cls


# --- classes by a whole path segment ------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/payments/charge.py", "money"),
        ("billing/invoice.ts", "money"),
        ("app/refunds/handler.go", "money"),
        ("app/auth/login.py", "auth"),
        ("lib/permissions/check.rb", "auth"),
        ("web/security/csrf.js", "auth"),
        ("db/migrations/0042_add_orders.py", "schema"),
        ("alembic/versions/abc.py", "schema"),
        ("sql/orders.sql", "schema"),
        ("prisma/schema.prisma", "schema"),
        ("app/models/order.py", ""),  # a models/ folder counts only with database talk in the edit
        ("pyproject.toml", "config"),
        ("ruff.toml", "config"),
        ("conftest.py", "config"),
        ("sub/conftest.py", "config"),
        (".eslintrc.json", "config"),
        ("eslint.config.mjs", "config"),
        ("tsconfig.build.json", "config"),
        (".github/workflows/ci.yml", "config"),
        ("hooks/hooks.json", "config"),
        ("src/charge.py", ""),
        ("lib/paymentutils.py", ""),
        ("src/author.py", ""),
        ("src/authoring/x.py", ""),
        ("app/models/README.md", ""),
        ("docs/billing.md", ""),
        ("notes/pricing.txt", ""),
    ],
)
def test_class_by_path(root, path, expected):
    assert cls(root, path) == expected


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_auth.py",
        "src/payments/test_charge.py",
        "src/payments/charge_test.py",
        "src/auth/login.test.ts",
        "src/auth/login.spec.js",
        "__tests__/billing.js",
        "CLAUDE.md",
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".claude/hooks/x.py",
        ".claude.json",
        "skills/billing/SKILL.md",
        "rules/payments.mdc",
    ],
)
def test_exempt_paths(root, path):
    assert cls(root, path, "op.add_column('orders', ...)") == ""


def test_secret_files_are_left_to_the_keys_guard(root):
    for name in (".env", ".env.local", "deploy/id_rsa", "certs/server.key", "credentials.json"):
        assert cls(root, name, "password = 1") == ""


def test_makefile_is_config_only_with_a_check_target(root):
    assert cls(root, "Makefile", "test:\n\tpytest\n") == "config"
    assert cls(root, "Makefile", "build:\n\tgo build\n") == ""


def test_exempt_globs_from_the_operator(root, monkeypatch):
    monkeypatch.setenv("PREFLIGHT_FACTS_EXEMPT", "src/payments/*.py; **/legacy/**")
    assert fc.classify("src/payments/charge.py", "", root).cls == ""
    assert fc.classify("app/legacy/auth/x.py", "", root).cls == ""
    assert fc.classify("src/billing/charge.py", "", root).cls == "money"


def test_exempt_globs_match_the_file_name_too(root):
    assert cls(root, "src/payments/charge.py", globs=["charge.py"]) == ""


# --- classes by the text of the edit ------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("op.add_column('orders', sa.Column('x', sa.Integer))", "schema"),
        ("CREATE TABLE orders (id int);", "schema"),
        ("class Order(Base):\n    id = Column(Integer)", "schema"),
        ("if check_password(user, pw):", "auth"),
        ("requests.get(url, verify=False)", "auth"),
        ("@login_required\ndef view():", "auth"),
        ("total = price * qty\n", "money"),
        ("balance -= fee\n", "money"),
        ("db.execute('UPDATE accounts SET balance = ?', (balance,))", "money"),
        ("log.info('price %s', price)", ""),
        ("x = a * b\n", ""),
        ("print('hello')", ""),
    ],
)
def test_class_by_content(root, text, expected):
    assert cls(root, "src/service.py", text) == expected


def test_path_wins_over_content(root):
    assert cls(root, "app/auth/login.py", "total = price * qty") == "auth"


def test_schema_before_auth_before_money_in_content(root):
    text = "password = 1\nop.add_column('t', c)\ntotal = price * 2"
    assert cls(root, "x.py", text) == "schema"


# --- names the questions need -------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("CREATE TABLE orders (id int)", "orders"),
        ('CREATE TABLE IF NOT EXISTS "orders" (', "orders"),
        ("ALTER TABLE `orders` ADD x int", "orders"),
        ("op.add_column('orders', sa.Column('x'))", "orders"),
        ('createTable("orders", t => {})', "orders"),
        ("class Order(Base):", "Order"),
        ("class OrderItem(models.Model):", "OrderItem"),
        ("nothing here", "0042_add_orders"),
    ],
)
def test_table_name(text, expected):
    assert fc.table_name(text, "0042_add_orders") == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("def charge(amount):\n    pass", "charge"),
        ("    async def refund(self):", "refund"),
        ("class Wallet:\n", "Wallet"),
        ("export const total = () => 1", "total"),
        ("export default function Checkout() {}", "Checkout"),
        ("function pay() {}", "pay"),
        ("func (s *Svc) Pay() {}", "Pay"),
        ("x = 1\n", ""),
    ],
)
def test_symbol_name(text, expected):
    assert fc.symbol_name(text) == expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/payments/charge.py", "charge"),
        ("src/auth/models.py", ""),
        ("src/auth/__init__.py", ""),
        ("src/pay.py", ""),
        ("db/migrations/0042_add_orders.py", "0042_add_orders"),
    ],
)
def test_stem_of(path, expected):
    assert fc.stem_of(path) == expected


def test_classify_fills_table_only_for_schema(root):
    target = fc.classify("db/migrations/0042.py", "op.add_column('orders', c)", root, [])
    assert (target.cls, target.table) == ("schema", "orders")
    target = fc.classify("src/payments/charge.py", "def charge(): pass", root, [])
    assert (target.cls, target.table, target.symbol) == ("money", "", "charge")


# --- paths as the file system sees them ---------------------------------------


def test_windows_tails_and_streams_are_dropped(root):
    assert fc.classify("CLAUDE.md.", "", root, []).cls == ""
    assert fc.classify("src/payments/charge.py::$DATA", "", root, []).rel.endswith("charge.py")
    assert cls(root, "src/payments/charge.py::$DATA") == "money"


def test_backslash_and_absolute_paths_inside_the_root(root):
    inside = str(root / "app" / "billing" / "x.py").replace("/", "\\")
    target = fc.classify(inside, "", root, [])
    assert (target.cls, target.rel) == ("money", "app/billing/x.py")


def test_a_file_outside_the_root_is_judged_by_its_absolute_path(root, tmp_path_factory):
    other = tmp_path_factory.mktemp("elsewhere")
    path = str(other / "payments" / "charge.py")
    target = fc.classify(path, "", root, [])
    assert target.cls == "money" and target.rel.startswith(("/", "c:", "d:", "e:"))


@pytest.mark.skipif(os.name != "nt", reason="drive letters")
def test_a_path_on_another_drive_does_not_crash(root):
    drive = "Z:" if str(root).upper().startswith("C:") else "C:"
    assert fc.classify(drive + "\\work\\payments\\x.py", "", root, []).cls == "money"


def test_worktree_prefix_is_stripped_only_for_a_real_worktree(root):
    wt = root / ".claude" / "worktrees" / "w1"
    (wt / "payments").mkdir(parents=True)
    assert cls(root, ".claude/worktrees/w1/payments/x.py") == ""  # not a worktree: agent dir
    (wt / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
    assert cls(root, ".claude/worktrees/w1/payments/x.py") == "money"


def test_project_under_a_tests_folder_is_not_all_tests(tmp_path):
    root = tmp_path / "tests" / "proj"
    (root / "payments").mkdir(parents=True)
    assert cls(root, "payments/charge.py") == "money"


@pytest.mark.skipif(os.name == "nt" and not hasattr(os, "symlink"), reason="no symlinks")
def test_symlink_into_an_auth_folder_is_auth(root):
    (root / "auth").mkdir()
    (root / "auth" / "login.py").write_text("x\n", encoding="utf-8")
    try:
        os.symlink(root / "auth", root / "src" / "tools", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks need privileges here")
    assert cls(root, "src/tools/login.py") == "auth"


def test_realpath_failure_counts_as_auth(root, monkeypatch):
    def boom(path):
        raise OSError("stat")

    monkeypatch.setattr(fc.os.path, "realpath", boom)
    assert cls(root, "src/ordinary.py") == "auth"


def test_empty_path_is_nothing(root):
    assert fc.classify("", "x", root, []) == fc.NOTHING


def test_module_imports_without_the_guards_path(tmp_path):
    """The guard runs as a script with `guards/` on sys.path; nothing else is assumed."""
    assert "fact_classes" in sys.modules


# --- what the mutation run found uncovered -------------------------------------


def test_a_four_letter_stem_is_a_stem():
    assert fc.stem_of("src/payments/cost.py") == "cost"


def test_dot_segments_are_resolved_not_stripped(root):
    assert fc.classify("src/../payments/x.py", "", root, []).rel == "payments/x.py"


def test_exempt_globs_are_case_insensitive(root):
    assert cls(root, "src/payments/charge.py", globs=["SRC/Payments/*.PY"]) == ""


def test_prose_in_a_money_folder_is_prose(root):
    assert cls(root, "src/payments/README.md", "total = price * 2") == ""
    assert cls(root, "src/payments/notes.txt", "total = price * 2") == ""


def test_real_relative_walks_up_to_the_nearest_existing_folder(root):
    assert fc._real_relative("src/new/deep/x.py", root) == "src/new/deep/x.py"
    (root / "src").mkdir()
    (root / "src" / "x.py").write_text("", encoding="utf-8")
    assert fc._real_relative("src/x.py", root) == "src/x.py"


@pytest.mark.skipif(os.name != "nt", reason="drive letters")
def test_real_relative_of_a_missing_drive_is_none(root):
    drive = "Q:" if not os.path.exists("Q:\\") else "Y:"
    assert fc._real_relative(drive + "\\nope\\x.py", root) is None
