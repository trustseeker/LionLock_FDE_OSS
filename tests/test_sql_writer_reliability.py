"""Delivery guarantees shared by both opt-in SQL sinks.

``SQLTelemetryWriter`` and ``TrustOverlaySQLWriter`` delegate delivery to
``lionlock.utils.sql_batch_writer.SQLBatchWriter``. Every test below runs against
a real SQLite database for both sinks (and through SQLAlchemy when installed).
Faults are injected deterministically by wrapping ``_write_batch``, ``_commit``
or ``_stored_seqs``, and each test checks the conservation law
``enqueued == written + duplicates + failed + in_doubt + dropped + pending``.
"""

from __future__ import annotations

import importlib.util
import logging
import sqlite3
import threading
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List

import pytest

from lionlock.logging.sql_telemetry import PUBLIC_SIGNALS_COLUMNS, SQLTelemetryWriter
from lionlock.trust_overlay.sql_sink import TRUST_OVERLAY_COLUMNS, TrustOverlaySQLWriter
from lionlock.utils.sql_batch_writer import (
    MAX_RETRY_BACKOFF_S,
    QueuedEvent,
    SQLBatchWriter,
    commit_stored_nothing,
    describe_error,
    is_duplicate_error,
    is_transient_error,
)

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None
requires_sqlalchemy = pytest.mark.skipif(not HAS_SQLALCHEMY, reason="SQLAlchemy not installed")

SINK_KINDS = [
    pytest.param(("telemetry", "sqlite3"), id="telemetry-sqlite3"),
    pytest.param(("trust_overlay", "sqlite3"), id="trust_overlay-sqlite3"),
    pytest.param(("telemetry", "sqlalchemy"), id="telemetry-sqlalchemy", marks=requires_sqlalchemy),
    pytest.param(
        ("trust_overlay", "sqlalchemy"), id="trust_overlay-sqlalchemy", marks=requires_sqlalchemy
    ),
]
# family -> (table, key column, column definitions)
SCHEMAS = {
    "telemetry": ("lionlock_signals", "request_id", PUBLIC_SIGNALS_COLUMNS),
    "trust_overlay": ("trust_overlay_records", "session_id", TRUST_OVERLAY_COLUMNS),
}


@dataclass
class Sink:
    writer: SQLBatchWriter
    family: str
    backend: str
    db_path: Path
    table: str
    key_column: str

    def event(self, key: str) -> Dict[str, Any]:
        if self.family == "telemetry":
            return {
                "timestamp_utc": "2025-12-19T00:00:00Z",
                "request_id": key,
                "decision": "ALLOW",
                "severity": "green",
                "reason_code": "ok",
                "aggregate_score": 0.1,
                "signal_scores": {"repetition_loopiness": 0.1},
                "config_hash": "hash",
                "duration_ms": 1,
            }
        return {
            "timestamp": "2025-12-19T00:00:00Z",
            "session_id": key,
            "turn_index": 1,
            "model_id": "model-1",
            "prompt_type": "qa",
            "trust_score": 0.9,
            "trust_label": "TRUSTED",
        }

    def stored_keys(self) -> List[tuple]:
        """``(writer_id, writer_seq)`` of the stored rows, in insertion order."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            return conn.execute(
                f"SELECT writer_id, writer_seq FROM {self.table} ORDER BY rowid"
            ).fetchall()

    def keys(self) -> List[str]:
        """Keys of the stored rows, in insertion order."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(
                f"SELECT {self.key_column} FROM {self.table} ORDER BY rowid"
            ).fetchall()
        return [row[0] for row in rows]

    def insert_existing(self, key: str) -> None:
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute(f"INSERT INTO {self.table} ({self.key_column}) VALUES (?)", (key,))

    def transient_error(self) -> Exception:
        """What a driver raises for "database is locked" on this sink's backend."""
        locked = sqlite3.OperationalError("database is locked")
        if self.backend == "sqlalchemy":
            from sqlalchemy import exc

            return exc.OperationalError("INSERT", {}, locked)
        return locked

    def lost_connection_error(self) -> Exception:
        """A COMMIT failure whose outcome is unknown on this sink's backend."""
        if self.backend == "sqlalchemy":
            from sqlalchemy import exc

            lost = ConnectionError("server closed the connection unexpectedly")
            return exc.OperationalError("COMMIT", {}, lost, connection_invalidated=True)
        return sqlite3.OperationalError("disk I/O error")


@pytest.fixture(params=SINK_KINDS)
def make_sink(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Callable[..., Sink]]:
    family, backend = request.param
    writers: List[SQLBatchWriter] = []

    def factory(table_constraint: str = "", pre_key_rows: int = 0, **options: Any) -> Sink:
        db_path = tmp_path / "sink.db"
        table, key_column, columns = SCHEMAS[family]
        if pre_key_rows:
            # The layout before writer keys existed, holding rows written back then.
            definitions = [f"{name} {col_type}" for name, col_type in columns[:-2]]
            with closing(sqlite3.connect(db_path)) as conn, conn:
                conn.execute(f"CREATE TABLE {table} ({', '.join(definitions)})")
                conn.execute(f"CREATE INDEX {table}_lookup ON {table} ({key_column})")
                for index in range(pre_key_rows):
                    conn.execute(
                        f"INSERT INTO {table} ({key_column}) VALUES (?)", (f"old-{index}",)
                    )
        if table_constraint:
            # Pre-create the table; the writer's CREATE TABLE IF NOT EXISTS keeps it.
            definitions = [f"{name} {col_type}" for name, col_type in columns]
            definitions.append(table_constraint.format(key=key_column))
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(f"CREATE TABLE {table} ({', '.join(definitions)})")
        # By default nothing flushes until the batch fills or the test stops the writer.
        settings: Dict[str, Any] = {
            "batch_size": 1000,
            "flush_interval_ms": 60_000,
            "retry_backoff_ms": 1,
        }
        settings.update(options)
        writer: SQLBatchWriter
        if family == "telemetry":
            scheme = "sqlite" if backend == "sqlite3" else "sqlite+pysqlite"
            writer = SQLTelemetryWriter(
                f"{scheme}:///{db_path}",
                table,
                "lionlock_sessions",
                connect_timeout_s=1,
                **settings,
            )
        else:
            writer = TrustOverlaySQLWriter(
                backend=backend,
                dsn=f"sqlite:///{db_path}" if backend == "sqlalchemy" else "",
                sqlite_path=str(db_path) if backend == "sqlite3" else None,
                table=table,
                connect_timeout_s=1,
                **settings,
            )
        assert writer.available, writer.error
        writers.append(writer)
        return Sink(writer, family, backend, db_path, table, key_column)

    yield factory
    for writer in writers:
        writer.stop(timeout_s=5)


def wrap_writes(
    monkeypatch: pytest.MonkeyPatch,
    writer: SQLBatchWriter,
    before: Callable[[int, List[QueuedEvent]], None],
) -> List[float]:
    """Run ``before(call_number, items)`` ahead of every real write (it may raise
    or block). Returns the monotonic start time of each write call."""
    real_write = writer._write_batch
    starts: List[float] = []

    def write(items: List[QueuedEvent]) -> None:
        starts.append(time.monotonic())
        before(len(starts), items)
        real_write(items)

    monkeypatch.setattr(writer, "_write_batch", write)
    return starts


def wrap_commits(
    monkeypatch: pytest.MonkeyPatch,
    writer: SQLBatchWriter,
    around: Callable[[int, Callable[[], Any]], None],
) -> List[int]:
    """Run ``around(call_number, real_commit)`` in place of every COMMIT. Whatever it
    raises still goes through the writer's own commit-outcome classification."""
    real_commit_step = writer._commit
    calls: List[int] = []

    def commit_step(commit: Callable[[], Any]) -> None:
        calls.append(len(calls) + 1)
        call = len(calls)
        real_commit_step(lambda: around(call, commit))

    monkeypatch.setattr(writer, "_commit", commit_step)
    return calls


def wait_for(predicate: Callable[[], bool], timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached before timeout")
        time.sleep(0.01)


def assert_conserved(stats: Dict[str, int]) -> None:
    """Every accepted event is accounted for exactly once."""
    accounted = sum(
        stats[name]
        for name in ("written", "duplicates", "failed", "in_doubt", "dropped", "pending")
    )
    assert stats["enqueued"] == accounted, stats


def test_stop_flushes_the_last_partial_batch(make_sink: Callable[..., Sink]) -> None:
    sink = make_sink(batch_size=10)
    keys = [f"evt-{i:02d}" for i in range(25)]
    for key in keys:
        assert sink.writer.enqueue(sink.event(key))

    # 25 events with batch_size=10: at most two full batches can flush on their own;
    # the last five are only written because stop() flushes before returning.
    sink.writer.stop()

    assert sink.keys() == keys
    assert sink.writer.thread is not None and not sink.writer.thread.is_alive()
    stats = sink.writer.stats()
    assert (stats["written"], stats["dropped"], stats["failed"], stats["pending"]) == (25, 0, 0, 0)
    assert_conserved(stats)
    assert sink.writer.enqueue(sink.event("after-stop")) is False


def test_stop_is_time_bounded_when_a_write_hangs(
    make_sink: Callable[..., Sink],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="lionlock.utils.sql_batch_writer")
    sink = make_sink(batch_size=2)
    writer = sink.writer
    entered, release = threading.Event(), threading.Event()

    def hang_first_write(call: int, items: List[QueuedEvent]) -> None:
        if call == 1:
            entered.set()
            release.wait(timeout=30)  # A database call that hangs.

    wrap_writes(monkeypatch, writer, hang_first_write)
    keys = [f"evt-{i}" for i in range(5)]
    try:
        for key in keys:
            assert writer.enqueue(sink.event(key))
        assert entered.wait(timeout=10)  # The worker is stuck inside batch [evt-0, evt-1].

        started = time.monotonic()
        writer.stop(timeout_s=0.2)
        elapsed = time.monotonic() - started

        assert elapsed < 2.0  # Nominally 0.2s; the hung write cannot hold stop() hostage.
        stats = writer.stats()
        assert stats["dropped_on_stop"] == 3  # evt-2..4 could not start before the deadline.
        assert stats["pending"] == 2  # The hung batch is still in flight, not lost.
        assert_conserved(stats)
    finally:
        release.set()

    assert writer.thread is not None
    writer.thread.join(timeout=10)
    assert not writer.thread.is_alive()
    assert sink.keys() == keys[:2]
    final = writer.stats()
    assert (final["written"], final["dropped"], final["pending"]) == (2, 3, 0)
    assert_conserved(final)
    # stop() returned before this outcome existed, so it is reported once it does.
    late = [r.getMessage() for r in caplog.records if "sql_sink_late_outcome" in r.getMessage()]
    assert len(late) == 1
    assert "written=2 " in late[0] and "dropped=3 " in late[0] and late[0].endswith("pending=0")


def test_stop_deadline_ends_retries_of_a_persistent_failure(
    make_sink: Callable[..., Sink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink(batch_size=1, max_retries=1_000_000, retry_backoff_ms=100)
    writer = sink.writer

    def always_locked(call: int, items: List[QueuedEvent]) -> None:
        raise sink.transient_error()

    wrap_writes(monkeypatch, writer, always_locked)
    assert writer.enqueue(sink.event("a"))
    assert writer.enqueue(sink.event("b"))
    wait_for(lambda: writer.stats()["retries"] >= 1)

    started = time.monotonic()
    writer.stop(timeout_s=0.3)
    assert time.monotonic() - started < 2.0

    # Only the deadline ends the retries (max_retries is effectively unlimited).
    assert writer.thread is not None
    writer.thread.join(timeout=10)
    assert not writer.thread.is_alive()
    final = writer.stats()
    assert final["written"] == 0
    assert final["failed"] >= 1  # "a" was attempted; "b" was attempted or dropped.
    assert final["failed"] + final["dropped"] == 2
    assert final["pending"] == 0
    assert_conserved(final)


def test_unique_violation_skips_only_true_duplicates(make_sink: Callable[..., Sink]) -> None:
    sink = make_sink(batch_size=5, table_constraint="UNIQUE ({key})")
    sink.insert_existing("dup")
    # One row that already exists and one duplicate inside the batch itself.
    for key in ["a", "dup", "b", "a", "c"]:
        assert sink.writer.enqueue(sink.event(key))

    sink.writer.stop()

    assert sink.keys() == ["dup", "a", "b", "c"]
    stats = sink.writer.stats()
    assert (stats["written"], stats["duplicates"], stats["failed"]) == (3, 2, 0)
    assert sink.writer.last_error is None  # Duplicates are expected, not errors.
    assert_conserved(stats)


def test_other_constraint_failures_fail_only_the_offending_row(
    make_sink: Callable[..., Sink],
) -> None:
    sink = make_sink(batch_size=3, table_constraint="CHECK ({key} <> 'poison')")
    writer = sink.writer
    for key in ["a", "poison", "b"]:
        assert writer.enqueue(sink.event(key))
    wait_for(lambda: writer.stats()["pending"] == 0)

    # A CHECK failure is not a duplicate: it is counted as failed, not skipped.
    stats = writer.stats()
    assert (stats["written"], stats["duplicates"], stats["failed"]) == (2, 0, 1)
    assert "CHECK constraint failed" in (writer.last_error or "")
    assert "poison" not in (writer.last_error or "")  # Quoted text is never recorded.
    assert writer.available and writer.error is None
    assert writer.enqueue(sink.event("c"))  # The writer stays in service.

    writer.stop()

    assert sink.keys() == ["a", "b", "c"]
    final = writer.stats()
    assert (final["written"], final["failed"], final["pending"]) == (3, 1, 0)
    assert_conserved(final)


def test_transient_errors_are_retried_with_backoff(
    make_sink: Callable[..., Sink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink(batch_size=3, retry_backoff_ms=20)
    writer = sink.writer

    def locked_three_times(call: int, items: List[QueuedEvent]) -> None:
        if call <= 3:
            raise sink.transient_error()

    starts = wrap_writes(monkeypatch, writer, locked_three_times)
    for key in ["a", "b", "c"]:
        assert writer.enqueue(sink.event(key))
    wait_for(lambda: writer.stats()["written"] == 3)

    assert sink.keys() == ["a", "b", "c"]
    stats = writer.stats()
    assert (stats["retries"], stats["failed"]) == (3, 0)
    assert writer.available and writer.error is None
    # Each retry started no earlier than its scheduled backoff (20ms, 40ms, 80ms).
    gaps = [later - earlier for earlier, later in zip(starts, starts[1:])]
    assert len(gaps) == 3
    for attempt, gap in enumerate(gaps, start=1):
        assert gap >= writer.retry_delay_s(attempt)
    writer.stop()
    assert_conserved(writer.stats())


def test_exhausted_retries_count_failed_and_writer_keeps_running(
    make_sink: Callable[..., Sink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink(batch_size=2, max_retries=2)
    writer = sink.writer
    healthy = threading.Event()

    def locked_until_healthy(call: int, items: List[QueuedEvent]) -> None:
        if not healthy.is_set():
            raise sink.transient_error()

    wrap_writes(monkeypatch, writer, locked_until_healthy)
    assert writer.enqueue(sink.event("lost-1"))
    assert writer.enqueue(sink.event("lost-2"))
    wait_for(lambda: writer.stats()["failed"] == 2)

    stats = writer.stats()
    assert stats["retries"] == 2
    assert writer.available and writer.error is None  # Not disabled.
    assert "database is locked" in (writer.last_error or "")

    healthy.set()
    assert writer.enqueue(sink.event("ok-1"))
    assert writer.enqueue(sink.event("ok-2"))
    wait_for(lambda: writer.stats()["written"] == 2)
    writer.stop()

    assert sink.keys() == ["ok-1", "ok-2"]
    final = writer.stats()
    assert (final["written"], final["failed"], final["dropped"], final["pending"]) == (2, 2, 0, 0)
    assert_conserved(final)


def test_commit_with_unknown_outcome_is_confirmed_not_replayed(
    make_sink: Callable[..., Sink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink(batch_size=3)
    writer = sink.writer

    def commit_then_lose_connection(call: int, commit: Callable[[], Any]) -> None:
        commit()  # The rows are stored...
        raise sink.lost_connection_error()  # ...but the client never learns it.

    commits = wrap_commits(monkeypatch, writer, commit_then_lose_connection)
    for key in ["a", "b", "c"]:
        assert writer.enqueue(sink.event(key))
    wait_for(lambda: writer.stats()["pending"] == 0)

    # The retry looked the keys up, found all three, and inserted nothing again.
    assert sink.keys() == ["a", "b", "c"]
    assert len(commits) == 1
    stats = writer.stats()
    assert (stats["written"], stats["in_doubt"], stats["reconciled"], stats["retries"]) == (
        3,
        0,
        3,
        1,
    )
    assert (writer.last_error or "").startswith("commit outcome unknown: ")
    writer.stop()
    assert_conserved(writer.stats())


def test_commit_with_unknown_outcome_that_stored_nothing_is_inserted_once(
    make_sink: Callable[..., Sink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink(batch_size=3)
    writer = sink.writer

    def lose_connection_before_commit_once(call: int, commit: Callable[[], Any]) -> None:
        if call == 1:
            raise sink.lost_connection_error()  # Outcome unknown; in fact nothing stored.
        commit()

    commits = wrap_commits(monkeypatch, writer, lose_connection_before_commit_once)
    for key in ["a", "b", "c"]:
        assert writer.enqueue(sink.event(key))
    wait_for(lambda: writer.stats()["pending"] == 0)

    assert sink.keys() == ["a", "b", "c"]
    assert len(commits) == 2
    stats = writer.stats()
    assert (stats["written"], stats["in_doubt"], stats["reconciled"], stats["retries"]) == (
        3,
        0,
        0,
        1,
    )
    writer.stop()
    assert_conserved(writer.stats())


def test_unique_key_backstops_a_lookup_that_misses_a_late_commit(
    make_sink: Callable[..., Sink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """In PostgreSQL an unacknowledged COMMIT can still be finishing when the writer
    looks its keys up. Simulated here by hiding the stored rows from the first lookup:
    the re-insert must then hit the UNIQUE key, not store a second copy."""
    sink = make_sink(batch_size=3)
    writer = sink.writer

    def commit_then_lose_connection(call: int, commit: Callable[[], Any]) -> None:
        commit()
        if call == 1:
            raise sink.lost_connection_error()

    wrap_commits(monkeypatch, writer, commit_then_lose_connection)
    real_lookup = writer._stored_seqs
    lookups: List[int] = []

    def lookup(items: Any) -> set:
        lookups.append(len(lookups) + 1)
        return set() if len(lookups) == 1 else real_lookup(items)

    monkeypatch.setattr(writer, "_stored_seqs", lookup)
    for key in ["a", "b", "c"]:
        assert writer.enqueue(sink.event(key))
    wait_for(lambda: writer.stats()["pending"] == 0)

    assert sink.keys() == ["a", "b", "c"]  # Stored once, never twice.
    assert len(lookups) == 2
    stats = writer.stats()
    assert (stats["written"], stats["duplicates"], stats["in_doubt"], stats["reconciled"]) == (
        3,
        0,
        0,
        3,
    )
    writer.stop()
    assert_conserved(writer.stats())


def test_unresolved_unknown_outcome_is_in_doubt_and_stored_at_most_once(
    make_sink: Callable[..., Sink],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="lionlock.utils.sql_batch_writer")
    sink = make_sink(batch_size=3, max_retries=2)
    writer = sink.writer

    def commit_then_lose_connection(call: int, commit: Callable[[], Any]) -> None:
        commit()
        raise sink.lost_connection_error()

    wrap_commits(monkeypatch, writer, commit_then_lose_connection)

    def lookup_unreachable(items: Any) -> set:
        raise sink.transient_error()

    monkeypatch.setattr(writer, "_stored_seqs", lookup_unreachable)
    for key in ["a", "b", "c"]:
        assert writer.enqueue(sink.event(key))
    wait_for(lambda: writer.stats()["pending"] == 0)

    # The outcome could not be resolved before the retries ran out: in_doubt, never
    # a second insert without a lookup first.
    assert sink.keys() == ["a", "b", "c"]
    stats = writer.stats()
    assert (stats["written"], stats["in_doubt"], stats["failed"], stats["retries"]) == (0, 3, 0, 2)
    assert writer.available and writer.error is None
    writer.stop()  # Joins the worker, so its warning has been logged.
    assert any("sql_sink_commit_outcome_unknown" in r.getMessage() for r in caplog.records)
    assert_conserved(writer.stats())


def test_keys_are_deterministic_and_enforced_by_the_database(
    make_sink: Callable[..., Sink],
) -> None:
    first = make_sink(batch_size=10)
    for key in ["a", "b", "c"]:
        assert first.writer.enqueue(first.event(key))
    first.writer.stop()
    # A second writer on the same database is assigned the next id; no randomness.
    second = make_sink(batch_size=10)
    assert second.writer.enqueue(second.event("d"))
    second.writer.stop()

    assert (first.writer.writer_id, second.writer.writer_id) == (1, 2)
    assert first.stored_keys() == [(1, 1), (1, 2), (1, 3), (2, 1)]
    with closing(sqlite3.connect(first.db_path)) as conn:
        writers = conn.execute("SELECT writer_id, sink FROM lionlock_sql_writers").fetchall()
        assert writers == [(1, first.writer.sink_name), (2, second.writer.sink_name)]
        with pytest.raises(sqlite3.IntegrityError):  # The database refuses a second copy.
            conn.execute(
                f"INSERT INTO {first.table} ({first.key_column}, writer_id, writer_seq) "
                "VALUES ('replay', 1, 2)"
            )


@pytest.mark.parametrize(
    "reset",
    ["DELETE FROM lionlock_sql_writers", "DROP TABLE lionlock_sql_writers"],
    ids=["emptied", "dropped"],
)
def test_a_reset_writers_table_never_hands_out_an_id_already_stored(
    make_sink: Callable[..., Sink], reset: str
) -> None:
    """The writers table can be emptied, dropped or restored from an older backup while
    the sink table keeps its rows. A new writer must still get an id whose keys are not
    stored, or every one of its events collides with an old row and is lost."""
    first = make_sink(batch_size=10)
    for key in ["a", "b", "c"]:
        assert first.writer.enqueue(first.event(key))
    first.writer.stop()
    with closing(sqlite3.connect(first.db_path)) as conn, conn:
        conn.execute(reset)

    second = make_sink(batch_size=10)
    for key in ["d", "e", "f"]:
        assert second.writer.enqueue(second.event(key))
    second.writer.stop()

    assert second.writer.writer_id == 2
    assert first.keys() == ["a", "b", "c", "d", "e", "f"]
    assert first.stored_keys() == [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3)]
    stats = second.writer.stats()
    assert (stats["written"], stats["duplicates"], stats["failed"]) == (3, 0, 0)
    assert_conserved(stats)


def test_a_writer_key_collision_is_a_loud_failure_not_a_duplicate(
    make_sink: Callable[..., Sink], caplog: pytest.LogCaptureFixture
) -> None:
    """If another writer has stored a row under this writer's id, the UNIQUE key refuses
    this writer's event at that key. The event was not stored, so it must never be
    counted as a duplicate, which means "already stored"."""
    caplog.set_level(logging.WARNING, logger="lionlock.utils.sql_batch_writer")
    sink = make_sink(batch_size=3)
    writer = sink.writer
    # Another writer holding the same id has already stored this writer's second key.
    with closing(sqlite3.connect(sink.db_path)) as conn, conn:
        conn.execute(
            f"INSERT INTO {sink.table} ({sink.key_column}, writer_id, writer_seq) "
            "VALUES ('foreign', ?, 2)",
            (writer.writer_id,),
        )
    for key in ["a", "b", "c"]:
        assert writer.enqueue(sink.event(key))
    writer.stop()  # Joins the worker, so its log lines have been emitted.

    assert sink.keys() == ["foreign", "a", "c"]  # The other writer's row is untouched.
    stats = writer.stats()
    assert (stats["written"], stats["duplicates"], stats["failed"], stats["key_collisions"]) == (
        2,
        0,
        1,
        1,
    )
    assert (writer.last_error or "").startswith("writer key collision")
    collisions = [r for r in caplog.records if "sql_sink_writer_key_collision" in r.getMessage()]
    assert [r.levelno for r in collisions] == [logging.ERROR]
    assert_conserved(stats)


def test_a_duplicate_that_cannot_be_confirmed_is_not_counted_as_stored(
    make_sink: Callable[..., Sink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Counting an event as a duplicate claims it is already stored. When the key
    lookup that confirms it fails, the event is counted as failed instead."""
    sink = make_sink(batch_size=2, table_constraint="UNIQUE ({key})")
    sink.insert_existing("dup")
    writer = sink.writer

    def lookup_broken(items: Any) -> set:
        raise sqlite3.DatabaseError("database disk image is malformed")

    monkeypatch.setattr(writer, "_stored_seqs", lookup_broken)
    for key in ["a", "dup"]:
        assert writer.enqueue(sink.event(key))
    writer.stop()

    assert sink.keys() == ["dup", "a"]
    stats = writer.stats()
    assert (stats["written"], stats["duplicates"], stats["failed"], stats["key_collisions"]) == (
        1,
        0,
        1,
        0,
    )
    assert (writer.last_error or "").startswith("duplicate not confirmed")
    assert_conserved(stats)


def test_commit_failure_that_stored_nothing_is_retried(
    make_sink: Callable[..., Sink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink(batch_size=3)
    writer = sink.writer

    def locked_once_then_commit(call: int, commit: Callable[[], Any]) -> None:
        if call == 1:
            raise sink.transient_error()  # "database is locked" at COMMIT: nothing stored.
        commit()

    commits = wrap_commits(monkeypatch, writer, locked_once_then_commit)
    for key in ["a", "b", "c"]:
        assert writer.enqueue(sink.event(key))
    wait_for(lambda: writer.stats()["pending"] == 0)

    assert sink.keys() == ["a", "b", "c"]  # Retried once, stored once.
    assert len(commits) == 2
    stats = writer.stats()
    assert (stats["written"], stats["in_doubt"], stats["retries"]) == (3, 0, 1)
    writer.stop()
    assert_conserved(writer.stats())


def test_full_queue_evicts_oldest_and_counts_every_drop(
    make_sink: Callable[..., Sink],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="lionlock.utils.sql_batch_writer")
    sink = make_sink(batch_size=10)
    writer = sink.writer
    assert writer.max_queue_size == 100
    entered, release = threading.Event(), threading.Event()

    def hold_first_batch(call: int, items: List[QueuedEvent]) -> None:
        if call == 1:
            entered.set()
            release.wait(timeout=30)

    wrap_writes(monkeypatch, writer, hold_first_batch)
    keys = [f"evt-{i:03d}" for i in range(117)]
    try:
        for key in keys[:10]:
            assert writer.enqueue(sink.event(key))
        assert entered.wait(timeout=10)  # evt-000..009 are in flight; the queue is empty.
        for key in keys[10:]:  # 107 events into a 100-slot queue.
            assert writer.enqueue(sink.event(key))

        stats = writer.stats()
        assert stats["dropped_queue_full"] == 7
        assert stats["pending"] == 110
        assert_conserved(stats)
    finally:
        release.set()
    writer.stop(timeout_s=30)

    assert sink.keys() == keys[:10] + keys[17:]  # The 7 oldest queued events were evicted.
    # Each evicted event left a gap in the stored sequence numbers, exactly where it was.
    assert [seq for _, seq in sink.stored_keys()] == list(range(1, 11)) + list(range(18, 118))
    final = writer.stats()
    assert (final["written"], final["dropped"], final["pending"]) == (110, 7, 0)
    assert_conserved(final)
    # Reported, with logarithmic volume: warnings at the 1st, 2nd and 4th drop.
    warnings = [r for r in caplog.records if "sql_sink_queue_full" in r.getMessage()]
    assert len(warnings) == 3


def test_retry_backoff_schedule_is_deterministic_and_capped() -> None:
    writer = SQLBatchWriter(batch_size=1, flush_interval_ms=10, retry_backoff_ms=50)
    delays = [writer.retry_delay_s(attempt) for attempt in range(1, 9)]
    assert delays == pytest.approx([0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 2.0, 2.0])
    assert writer.retry_delay_s(10_000) == MAX_RETRY_BACKOFF_S


def _real_sqlite_errors(tmp_path: Path) -> Dict[str, sqlite3.Error]:
    """Trigger each error class for real, so Python 3.11+ error codes are exercised."""
    db_path = tmp_path / "classify.db"
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, "
            "score REAL CHECK (score >= 0))"
        )
        conn.execute("INSERT INTO t VALUES (1, 'taken', 1.0)")
        conn.commit()

    def error_of(sql: str, timeout: float = 5.0) -> sqlite3.Error:
        with closing(sqlite3.connect(db_path, timeout=timeout)) as conn:
            with pytest.raises(sqlite3.Error) as info:
                conn.execute(sql)
        return info.value

    errors = {
        "unique": error_of("INSERT INTO t VALUES (2, 'taken', 1.0)"),
        "primary_key": error_of("INSERT INTO t VALUES (1, 'other', 1.0)"),
        "check": error_of("INSERT INTO t VALUES (3, 'x', -1.0)"),
        "not_null": error_of("INSERT INTO t VALUES (4, NULL, 1.0)"),
        "missing_table": error_of("INSERT INTO missing VALUES (1)"),
    }
    with closing(sqlite3.connect(db_path, isolation_level=None)) as locker:
        locker.execute("BEGIN EXCLUSIVE")
        errors["busy"] = error_of("INSERT INTO t VALUES (5, 'y', 1.0)", timeout=0)
        locker.execute("ROLLBACK")
    return errors


def test_error_classification_on_real_sqlite_errors(tmp_path: Path) -> None:
    errors = _real_sqlite_errors(tmp_path)
    duplicates = {name for name, exc in errors.items() if is_duplicate_error(exc)}
    transient = {name for name, exc in errors.items() if is_transient_error(exc)}
    assert duplicates == {"unique", "primary_key"}
    assert transient == {"busy"}
    # Python 3.10 has no sqlite_errorcode; the message fallback must agree.
    assert is_transient_error(sqlite3.OperationalError("database is locked"))
    assert not is_transient_error(sqlite3.OperationalError("no such table: t"))
    assert is_duplicate_error(sqlite3.IntegrityError("UNIQUE constraint failed: t.name"))
    assert not is_duplicate_error(sqlite3.IntegrityError("CHECK constraint failed: score >= 0"))
    # Only database errors are candidates for retry or duplicate handling.
    assert not is_transient_error(ValueError("database is locked"))
    assert not is_duplicate_error(ValueError("UNIQUE constraint failed"))


class FakePgError(Exception):
    """A psycopg2-style driver error carrying its SQLSTATE in ``pgcode``."""

    def __init__(self, message: str, pgcode: str) -> None:
        super().__init__(message)
        self.pgcode = pgcode


def test_commit_outcome_is_known_only_when_nothing_was_stored(tmp_path: Path) -> None:
    errors = _real_sqlite_errors(tmp_path)
    assert commit_stored_nothing(errors["busy"])  # SQLITE_BUSY leaves the transaction open.
    assert commit_stored_nothing(errors["unique"])  # A constraint violation rolls back.
    assert commit_stored_nothing(FakePgError("could not serialize access", "40001"))
    assert commit_stored_nothing(FakePgError("deadlock detected", "40P01"))
    # Anything else may have committed before the failure surfaced.
    assert not commit_stored_nothing(sqlite3.OperationalError("disk I/O error"))
    assert not commit_stored_nothing(FakePgError("terminating connection", "57P01"))
    assert not commit_stored_nothing(ConnectionError("server closed the connection"))


def test_recorded_errors_never_carry_quoted_values() -> None:
    leaky = FakePgError(
        'invalid input syntax for type double precision: "4111 1111 1111 1111"\n'
        "LINE 1: INSERT INTO lionlock_signals VALUES ($1)",
        "22P02",
    )
    assert describe_error(leaky) == (
        "FakePgError [22P02]: invalid input syntax for type double precision: <redacted>"
    )
    assert describe_error(ValueError("could not convert string to float: 'secret'")) == (
        "ValueError: could not convert string to float: <redacted>"
    )
    assert describe_error(KeyError("secret")) == "KeyError: <redacted>"
    assert describe_error(RuntimeError()) == "RuntimeError"


@requires_sqlalchemy
def test_error_classification_through_sqlalchemy(tmp_path: Path) -> None:
    from sqlalchemy import exc

    errors = _real_sqlite_errors(tmp_path)
    assert is_duplicate_error(exc.IntegrityError("INSERT", {}, errors["unique"]))
    assert not is_duplicate_error(exc.IntegrityError("INSERT", {}, errors["check"]))
    assert is_transient_error(exc.OperationalError("INSERT", {}, errors["busy"]))
    assert not is_transient_error(exc.OperationalError("INSERT", {}, errors["missing_table"]))
    assert is_transient_error(exc.TimeoutError("QueuePool limit reached"))
    # A lost connection at COMMIT leaves the outcome unknown; a locked COMMIT stored nothing.
    lost = exc.OperationalError("COMMIT", {}, ConnectionError("gone"), connection_invalidated=True)
    assert not commit_stored_nothing(lost)
    assert commit_stored_nothing(exc.OperationalError("COMMIT", {}, errors["busy"]))
    # Recorded errors never carry SQL text or bound values.
    wrapped = exc.IntegrityError("INSERT INTO t VALUES (?)", ("secret-value",), errors["unique"])
    code = getattr(errors["unique"], "sqlite_errorname", None)  # Python 3.11+
    label = f"IntegrityError [{code}]" if code else "IntegrityError"
    assert describe_error(wrapped) == f"{label}: UNIQUE constraint failed: t.name"


def test_existing_table_is_upgraded_in_place_and_keeps_its_rows(
    make_sink: Callable[..., Sink],
) -> None:
    sink = make_sink(batch_size=10, pre_key_rows=2)
    assert sink.writer.enqueue(sink.event("new"))
    sink.writer.stop()

    assert sink.keys() == ["old-0", "old-1", "new"]
    # Rows from before the upgrade keep NULL keys; a UNIQUE index never equates NULLs.
    assert sink.stored_keys() == [(None, None), (None, None), (1, 1)]
    with closing(sqlite3.connect(sink.db_path)) as conn:
        indexes = {
            name: unique for _, name, unique, *_ in conn.execute(f"PRAGMA index_list({sink.table})")
        }
    assert indexes == {f"{sink.table}_lookup": 0, f"{sink.table}_writer_key": 1}
    # Starting again changes nothing but claiming the next writer id.
    again = make_sink(batch_size=10)
    again.writer.stop()
    assert again.writer.writer_id == 2
    assert sink.stored_keys() == [(None, None), (None, None), (1, 1)]


@pytest.mark.parametrize("family", ["telemetry", "trust_overlay"])
def test_foreign_table_is_refused_without_changes(tmp_path: Path, family: str) -> None:
    db_path = tmp_path / "foreign.db"
    table, _, _ = SCHEMAS[family]
    with closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute(f"CREATE TABLE {table} (value TEXT)")
        conn.execute(f"INSERT INTO {table} VALUES ('retain')")
    writer: SQLBatchWriter
    if family == "telemetry":
        writer = SQLTelemetryWriter(f"sqlite:///{db_path}", table, "lionlock_sessions", 10, 1000, 1)
    else:
        writer = TrustOverlaySQLWriter(
            backend="sqlite3",
            dsn="",
            sqlite_path=str(db_path),
            table=table,
            batch_size=10,
            flush_interval_ms=1000,
            connect_timeout_s=1,
        )
    writer.stop()
    assert not writer.available
    assert "incompatible" in (writer.error or "").lower()
    with closing(sqlite3.connect(db_path)) as conn:
        assert conn.execute(f"SELECT * FROM {table}").fetchall() == [("retain",)]
        names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master")}
    assert names == {table}  # Nothing created, nothing altered.
