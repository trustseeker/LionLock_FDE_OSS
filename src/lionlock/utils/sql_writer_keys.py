"""Schema for the idempotency keys of LionLock's opt-in SQL sinks.

Every row a sink stores carries ``(writer_id, writer_seq)``. ``writer_id`` is
claimed once per writer: one above the highest id in ``lionlock_sql_writers`` and
in the sink's own table, inserted under the writers table's PRIMARY KEY, so two
writers can never share one, with or without concurrency. Reading the sink table
too means a writers table that was emptied, dropped or restored from an older
backup cannot hand out an id whose keys are already stored. ``writer_seq`` is the
writer's own counter (see ``SQLBatchWriter.enqueue``). A UNIQUE index on the pair
lets the database refuse a second copy of any event, which is what makes retrying
a COMMIT with an unknown outcome safe.

Existing tables are upgraded by adding the two nullable columns and the index.
Rows stored before the upgrade keep NULL keys, which a UNIQUE index never treats
as equal. Nothing is ever dropped, rebuilt or renamed.
"""

from __future__ import annotations

import re
import sqlite3
import time
from typing import Any, List, Sequence, Tuple

# Imports nothing from lionlock.logging: sql_telemetry imports this module.
from lionlock.utils.sql_batch_writer import is_duplicate_error, is_transient_error

WRITERS_TABLE = "lionlock_sql_writers"
WRITERS_COLUMNS: List[Tuple[str, str]] = [
    ("writer_id", "BIGINT PRIMARY KEY"),
    ("sink", "TEXT NOT NULL"),
    ("started_utc", "TEXT NOT NULL"),
]
WRITER_KEY_COLUMNS: List[Tuple[str, str]] = [("writer_id", "BIGINT"), ("writer_seq", "BIGINT")]
_KEY_NAMES = [name for name, _ in WRITER_KEY_COLUMNS]
CLAIM_ATTEMPTS = 5
# Table names are interpolated into SQL; the sinks validate them, and this re-checks.
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _checked(table: str) -> str:
    if not _IDENTIFIER.fullmatch(table):
        raise ValueError(f"Invalid SQL identifier for table: {table!r}")
    return table


def writer_key_index(table: str) -> str:
    return f"{_checked(table)}_writer_key"


def create_writer_key_index_sql(table: str) -> str:
    return f"CREATE UNIQUE INDEX {writer_key_index(table)} ON {table} ({', '.join(_KEY_NAMES)})"


def lock_table_for_key_upgrade_sql(table: str) -> str:
    """PostgreSQL: serialise writers upgrading ``table``; plain SELECTs still run."""
    return f"LOCK TABLE {_checked(table)} IN SHARE ROW EXCLUSIVE MODE"


def create_writers_table_sql() -> str:
    columns = ", ".join(f"{name} {definition}" for name, definition in WRITERS_COLUMNS)
    return f"CREATE TABLE IF NOT EXISTS {WRITERS_TABLE} ({columns})"


def next_writer_id_sql(table: str) -> str:
    """One above the highest writer id in the writers table and in ``table``.

    The writers table alone is not enough: if it is emptied, dropped or restored from
    an older backup, its MAX restarts while the sink table still holds keys under the
    old ids, and a reused id makes every new event collide with a stored row.
    """
    return (
        "SELECT COALESCE(MAX(writer_id), 0) + 1 FROM ("
        f"SELECT MAX(writer_id) AS writer_id FROM {WRITERS_TABLE} "
        f"UNION ALL SELECT MAX(writer_id) AS writer_id FROM {_checked(table)}"
        ") AS claimed"
    )


def stored_seqs_sql(table: str) -> str:
    """Named-parameter query (``:writer_id``, ``:first``, ``:last``) for stored keys."""
    return (
        f"SELECT writer_seq FROM {_checked(table)} "
        "WHERE writer_id = :writer_id AND writer_seq BETWEEN :first AND :last"
    )


def stored_seqs_params(writer_id: int | None, seqs: Sequence[int]) -> dict[str, Any]:
    return {"writer_id": writer_id, "first": min(seqs), "last": max(seqs)}


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _key_columns_to_add(table: str, existing: Sequence[str], base: Sequence[str]) -> List[str]:
    """Key column definitions ``table`` lacks; refuses a table that is not the sink's."""
    names = {name.lower() for name in existing}
    missing = [name for name in base if name.lower() not in names]
    if missing:
        raise ValueError(f"Incompatible table {table}: missing columns {', '.join(missing)}")
    present = [name for name in _KEY_NAMES if name in names]
    if present and len(present) != len(_KEY_NAMES):
        raise ValueError(f"Incompatible table {table}: partial writer key columns")
    if present:
        return []
    return [f"{name} {definition}" for name, definition in WRITER_KEY_COLUMNS]


# --- sqlite3 ------------------------------------------------------------------------------------


def sqlite_has_writer_key_index(conn: sqlite3.Connection, table: str) -> bool:
    """True when ``table`` has a unique, non-partial index on exactly the key columns."""
    indexes = conn.execute(
        'SELECT name, "unique", partial FROM pragma_index_list(?)', (table,)
    ).fetchall()
    for name, unique, partial in indexes:
        if not unique or partial:
            continue
        columns = conn.execute(
            "SELECT name FROM pragma_index_info(?) ORDER BY seqno", (name,)
        ).fetchall()
        if [str(column or "").lower() for (column,) in columns] == _KEY_NAMES:
            return True
    return False


def ensure_sqlite_writer_key(
    conn: sqlite3.Connection, table: str, base_columns: Sequence[str]
) -> None:
    """Add the key columns and UNIQUE index ``table`` lacks, inside the caller's transaction."""
    existing = [row[1] for row in conn.execute("SELECT * FROM pragma_table_info(?)", (table,))]
    for definition in _key_columns_to_add(table, existing, base_columns):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")
    ensure_sqlite_writer_key_index(conn, table)


def ensure_sqlite_writer_key_index(conn: sqlite3.Connection, table: str) -> None:
    if not sqlite_has_writer_key_index(conn, table):
        # Fails, rather than silently doing nothing, if the name is taken by another index.
        conn.execute(create_writer_key_index_sql(table))


def claim_writer_id_sqlite(conn: sqlite3.Connection, sink: str, table: str) -> int:
    """Claim the next writer id for a sink that writes to ``table``. The caller holds
    the write lock (``BEGIN IMMEDIATE``)."""
    (writer_id,) = conn.execute(next_writer_id_sql(table)).fetchone()
    conn.execute(
        f"INSERT INTO {WRITERS_TABLE} (writer_id, sink, started_utc) VALUES (?, ?, ?)",
        (writer_id, sink, _utc_now()),
    )
    return int(writer_id)


# --- SQLAlchemy ---------------------------------------------------------------------------------


def _sqlalchemy_has_writer_key_index(conn: Any, table: str) -> bool:
    from sqlalchemy import inspect

    inspector = inspect(conn)
    for index in inspector.get_indexes(table):
        where = [v for k, v in (index.get("dialect_options") or {}).items() if k.endswith("_where")]
        columns = [str(column or "").lower() for column in index.get("column_names") or []]
        if index.get("unique") and not any(where) and columns == _KEY_NAMES:
            return True
    for constraint in inspector.get_unique_constraints(table):
        columns = [str(column or "").lower() for column in constraint.get("column_names") or []]
        if columns == _KEY_NAMES:
            return True
    return False


def ensure_sqlalchemy_writer_key(conn: Any, table: str, base_columns: Sequence[str]) -> None:
    """Add the key columns and UNIQUE index ``table`` lacks, inside the caller's transaction."""
    from sqlalchemy import inspect, text

    if conn.dialect.name == "postgresql":
        # Two writers starting together on a table without key columns would both pass the
        # inspection below, and the second ADD COLUMN or CREATE INDEX would fail with "already
        # exists". The lock makes the second wait, then inspect the first one's committed result.
        conn.execute(text(lock_table_for_key_upgrade_sql(table)))
    existing = [column["name"] for column in inspect(conn).get_columns(table)]
    for definition in _key_columns_to_add(table, existing, base_columns):
        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {definition}"))
    if not _sqlalchemy_has_writer_key_index(conn, table):
        conn.execute(text(create_writer_key_index_sql(table)))


def claim_writer_id_sqlalchemy(engine: Any, sink: str, table: str) -> int:
    """Claim the next writer id for a sink that writes to ``table``, in its own
    transaction.

    In PostgreSQL the claim locks the writers table first (a mode that still lets
    other sessions read it), so writers starting together claim one after another
    instead of computing the same next id. Elsewhere two claims can still race; the
    PRIMARY KEY rejects the second insert, which then claims again.
    """
    from sqlalchemy import text

    for attempt in range(1, CLAIM_ATTEMPTS + 1):
        try:
            with engine.begin() as conn:
                if conn.dialect.name == "postgresql":
                    conn.execute(text(f"LOCK TABLE {WRITERS_TABLE} IN SHARE ROW EXCLUSIVE MODE"))
                writer_id = conn.execute(text(next_writer_id_sql(table))).scalar_one()
                conn.execute(
                    text(
                        f"INSERT INTO {WRITERS_TABLE} (writer_id, sink, started_utc) "
                        "VALUES (:writer_id, :sink, :started_utc)"
                    ),
                    {"writer_id": writer_id, "sink": sink, "started_utc": _utc_now()},
                )
            return int(writer_id)
        except Exception as exc:
            if attempt == CLAIM_ATTEMPTS or not (
                is_duplicate_error(exc) or is_transient_error(exc)
            ):
                raise
    raise AssertionError("unreachable")
