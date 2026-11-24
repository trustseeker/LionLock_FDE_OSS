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


class FakeSchema:
    """What the fake database holds for the sink table, and every statement it saw."""

    def __init__(self) -> None:
        self.log: List[str] = []
        self.has_key_columns = False
        self.has_key_index = False
        # Runs when the LOCK statement executes: another writer may finish the upgrade
        # while this one waits for the lock.
        self.on_lock: Any = None


class FakeInspector:
    def __init__(self, schema: FakeSchema) -> None:
        self.schema = schema

    def get_columns(self, table: str) -> List[dict[str, str]]:
        self.schema.log.append(f"inspect columns {table}")
        names = ["a"] + (["writer_id", "writer_seq"] if self.schema.has_key_columns else [])
        return [{"name": name} for name in names]

    def get_indexes(self, table: str) -> List[dict[str, Any]]:
        self.schema.log.append(f"inspect indexes {table}")
        if not self.schema.has_key_index:
            return []
        return [{"unique": True, "column_names": ["writer_id", "writer_seq"]}]

    def get_unique_constraints(self, table: str) -> List[dict[str, Any]]:
        return []


class FakeConn:
    def __init__(self, dialect: str, schema: FakeSchema) -> None:
        self.dialect = types.SimpleNamespace(name=dialect)
        self.schema = schema

    def execute(self, statement: str) -> None:
        self.schema.log.append(f"sql {statement}")
        if statement.startswith("LOCK TABLE") and self.schema.on_lock is not None:
            self.schema.on_lock()
        if statement.startswith("ALTER TABLE"):
            self.schema.has_key_columns = True
        if statement.startswith("CREATE UNIQUE INDEX"):
            self.schema.has_key_index = True


@pytest.fixture
def schema(monkeypatch: pytest.MonkeyPatch) -> FakeSchema:
    state = FakeSchema()
    module = types.ModuleType("sqlalchemy")
    setattr(module, "text", lambda sql: sql)
    setattr(module, "inspect", lambda conn: FakeInspector(state))
    monkeypatch.setitem(sys.modules, "sqlalchemy", module)
    return state


LOCK = "sql LOCK TABLE lionlock_signals IN SHARE ROW EXCLUSIVE MODE"


def _ddl(log: List[str]) -> List[str]:
    return [e for e in log if e.startswith(("sql ALTER TABLE", "sql CREATE UNIQUE INDEX"))]


def test_postgresql_complete_schema_takes_no_lock(schema: FakeSchema) -> None:
    # A role with only SELECT and INSERT cannot take SHARE ROW EXCLUSIVE, so a table that
    # needs no upgrade must not be locked.
    schema.has_key_columns = schema.has_key_index = True
    sql_writer_keys.ensure_sqlalchemy_writer_key(
        FakeConn("postgresql", schema), "lionlock_signals", ["a"]
    )
    assert not any(e.startswith("sql ") for e in schema.log)


def test_postgresql_locks_before_upgrading_and_inspects_again(schema: FakeSchema) -> None:
    sql_writer_keys.ensure_sqlalchemy_writer_key(
        FakeConn("postgresql", schema), "lionlock_signals", ["a"]
    )
    lock_at = schema.log.index(LOCK)
    assert "inspect columns lionlock_signals" in schema.log[lock_at + 1 :]
    ddl = _ddl(schema.log)
    assert any(e.startswith("sql ALTER TABLE lionlock_signals ADD COLUMN") for e in ddl)
    assert any(e.startswith("sql CREATE UNIQUE INDEX") for e in ddl)
    assert all(schema.log.index(e) > lock_at for e in ddl)


def test_postgresql_missing_index_only_locks_then_creates_it(schema: FakeSchema) -> None:
    schema.has_key_columns = True
    sql_writer_keys.ensure_sqlalchemy_writer_key(
        FakeConn("postgresql", schema), "lionlock_signals", ["a"]
    )
    lock_at = schema.log.index(LOCK)
    ddl = _ddl(schema.log)
    assert len(ddl) == 1 and ddl[0].startswith("sql CREATE UNIQUE INDEX")
    assert schema.log.index(ddl[0]) > lock_at


def test_postgresql_upgrade_finished_by_another_writer_while_waiting(schema: FakeSchema) -> None:
    def other_writer_upgrades() -> None:
        schema.has_key_columns = schema.has_key_index = True

    schema.on_lock = other_writer_upgrades
    sql_writer_keys.ensure_sqlalchemy_writer_key(
        FakeConn("postgresql", schema), "lionlock_signals", ["a"]
    )
    assert LOCK in schema.log
    assert _ddl(schema.log) == []


def test_other_dialects_take_no_lock(schema: FakeSchema) -> None:
    sql_writer_keys.ensure_sqlalchemy_writer_key(
        FakeConn("sqlite", schema), "lionlock_signals", ["a"]
    )
    assert not any("LOCK" in entry for entry in schema.log)
    assert schema.log[0] == "inspect columns lionlock_signals"
    assert len(_ddl(schema.log)) == 3  # two ADD COLUMNs and the index


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
