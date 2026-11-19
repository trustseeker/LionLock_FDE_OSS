"""MySQL duplicate-key detection, and the PostgreSQL lock around the writer-key upgrade.

No MySQL or PostgreSQL server is used: the driver errors and the connection are fakes. SQLAlchemy
is replaced in ``sys.modules`` by a minimal stand-in, so these tests behave the same with and
without it installed.
"""

import sys
import types
from typing import Any, List

import pytest

from lionlock.utils import sql_writer_keys
from lionlock.utils.sql_batch_writer import commit_stored_nothing, is_duplicate_error


class FakeSAIntegrityError(Exception):
    def __init__(self, orig: BaseException) -> None:
        super().__init__(str(orig))
        self.orig = orig


@pytest.fixture
def fake_sqlalchemy_exc(monkeypatch: pytest.MonkeyPatch) -> type:
    module = types.ModuleType("sqlalchemy.exc")
    for name in ("TimeoutError", "DisconnectionError", "DBAPIError", "OperationalError"):
        setattr(module, name, type(name, (Exception,), {}))
    setattr(module, "IntegrityError", FakeSAIntegrityError)
    monkeypatch.setitem(sys.modules, "sqlalchemy.exc", module)
    return FakeSAIntegrityError


class FakeMySQLIntegrityError(Exception):
    """Shaped like pymysql.err.IntegrityError and MySQLdb.IntegrityError: ``args`` is
    ``(errno, message)``. PyMySQL also sets ``sqlstate`` from the server's error packet."""

    def __init__(self, *args: Any, sqlstate: str | None = None) -> None:
        super().__init__(*args)
        self.sqlstate = sqlstate


def test_mysql_dup_entry_1062_is_a_duplicate(fake_sqlalchemy_exc: type) -> None:
    orig = FakeMySQLIntegrityError(1062, "Duplicate entry '1-1' for key 't.t_writer_key'")
    assert is_duplicate_error(fake_sqlalchemy_exc(orig))


def test_mysql_1062_with_sqlstate_23000_is_a_duplicate(fake_sqlalchemy_exc: type) -> None:
    orig = FakeMySQLIntegrityError(1062, "Duplicate entry '1-1' for key 'k'", sqlstate="23000")
    assert is_duplicate_error(fake_sqlalchemy_exc(orig))


def test_mysql_foreign_key_error_is_not_a_duplicate(fake_sqlalchemy_exc: type) -> None:
    # The message mentions "unique" on purpose: the error number decides, not the text.
    orig = FakeMySQLIntegrityError(1452, "Cannot add or update a child row (unique_ref)")
    assert not is_duplicate_error(fake_sqlalchemy_exc(orig))


def test_sqlstate_23000_alone_is_not_a_duplicate(fake_sqlalchemy_exc: type) -> None:
    orig = FakeMySQLIntegrityError("integrity constraint violation", sqlstate="23000")
    assert not is_duplicate_error(fake_sqlalchemy_exc(orig))


def test_mysql_duplicate_still_counts_as_stored_nothing(fake_sqlalchemy_exc: type) -> None:
    orig = FakeMySQLIntegrityError(1062, "Duplicate entry")
    assert commit_stored_nothing(fake_sqlalchemy_exc(orig))


class FakeInspector:
    def __init__(self, log: List[str]) -> None:
        self.log = log

    def get_columns(self, table: str) -> List[dict[str, str]]:
        self.log.append(f"inspect columns {table}")
        return [{"name": "a"}]

    def get_indexes(self, table: str) -> List[dict[str, Any]]:
        self.log.append(f"inspect indexes {table}")
        return []

    def get_unique_constraints(self, table: str) -> List[dict[str, Any]]:
        return []


class FakeConn:
    def __init__(self, dialect: str, log: List[str]) -> None:
        self.dialect = types.SimpleNamespace(name=dialect)
        self.log = log

    def execute(self, statement: str) -> None:
        self.log.append(f"sql {statement}")


@pytest.fixture
def fake_sqlalchemy(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    log: List[str] = []
    module = types.ModuleType("sqlalchemy")
    setattr(module, "text", lambda sql: sql)
    setattr(module, "inspect", lambda conn: FakeInspector(log))
    monkeypatch.setitem(sys.modules, "sqlalchemy", module)
    return log


def test_postgresql_locks_the_table_before_inspecting_it(fake_sqlalchemy: List[str]) -> None:
    conn = FakeConn("postgresql", fake_sqlalchemy)
    sql_writer_keys.ensure_sqlalchemy_writer_key(conn, "lionlock_signals", ["a"])
    assert fake_sqlalchemy[0] == "sql LOCK TABLE lionlock_signals IN SHARE ROW EXCLUSIVE MODE"
    assert fake_sqlalchemy[1] == "inspect columns lionlock_signals"
    assert any(e.startswith("sql ALTER TABLE lionlock_signals ADD COLUMN") for e in fake_sqlalchemy)
    assert any(e.startswith("sql CREATE UNIQUE INDEX") for e in fake_sqlalchemy)


def test_other_dialects_take_no_lock(fake_sqlalchemy: List[str]) -> None:
    conn = FakeConn("sqlite", fake_sqlalchemy)
    sql_writer_keys.ensure_sqlalchemy_writer_key(conn, "lionlock_signals", ["a"])
    assert not any("LOCK" in entry for entry in fake_sqlalchemy)
    assert fake_sqlalchemy[0] == "inspect columns lionlock_signals"


def test_lock_refuses_an_unsafe_table_name() -> None:
    with pytest.raises(ValueError):
        sql_writer_keys.lock_table_for_key_upgrade_sql("t; DROP TABLE x")


def test_real_sqlalchemy_wrapping_a_mysql_error() -> None:
    exc = pytest.importorskip("sqlalchemy.exc")
    dup = exc.IntegrityError("INSERT", {}, FakeMySQLIntegrityError(1062, "Duplicate entry"))
    fk = exc.IntegrityError(
        "INSERT", {}, FakeMySQLIntegrityError(1452, "foreign key", sqlstate="23000")
    )
    assert is_duplicate_error(dup)
    assert not is_duplicate_error(fk)
