"""Background batch writer shared by LionLock's opt-in SQL sinks.

``lionlock.logging.sql_telemetry`` and ``lionlock.trust_overlay.sql_sink`` queue
events in memory and insert them from a daemon thread. This module owns that
delivery policy so both sinks give the same guarantees:

* Every accepted event ends in exactly one terminal counter of ``stats()``:
  ``written``; ``duplicates`` (rejected by a UNIQUE or PRIMARY KEY constraint,
  i.e. already stored); ``failed`` (a write was attempted but the row could not
  be persisted); ``in_doubt`` (a COMMIT failed without a known outcome and the
  retries ran out before it could be resolved, so the row may or may not be
  stored); or ``dropped`` (never attempted: evicted from a full queue, or still
  queued when the stop deadline expired). Until then it is ``pending``.
* Every accepted event gets an idempotency key, ``(writer_id, writer_seq)``: the
  writer's id, which the database assigns when the writer starts, and the next
  number of the writer's own counter. Each sink table has a UNIQUE index on the
  key, so the database itself refuses to store an event twice. No randomness is
  involved.
* Transient errors (lock contention, lost connections) are retried with
  deterministic exponential backoff. Write errors never disable the writer.
* A COMMIT that fails without a known outcome is retried too, but first the
  writer looks up which of the batch's keys are already stored: those events are
  counted as ``written`` (and ``reconciled``), and only the others are inserted
  again.
* A non-transient batch error, such as a single UNIQUE violation, rolls the
  batch back; its rows are then inserted one by one so only the offending rows
  are skipped (duplicates) or failed.
* A UNIQUE violation is counted as a duplicate only after the writer has looked
  up the event's own key and found it not stored, so another UNIQUE constraint
  refused the row. If the key itself is stored, another writer holds this
  writer's id: the event was not stored, so it is counted as ``failed`` (and
  ``key_collisions``) and logged as an error, never as a duplicate.
* ``stop()`` flushes everything still queued, bounded by a deadline.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, NamedTuple, Sequence, Set

from lionlock.utils.sql_optional import loaded_sqlalchemy_exc

_LOGGER = logging.getLogger(__name__)

DEFAULT_MAX_RETRIES = 5
DEFAULT_RETRY_BACKOFF_MS = 50
DEFAULT_STOP_TIMEOUT_S = 2.0
MAX_RETRY_BACKOFF_S = 2.0

# SQLite result codes: https://www.sqlite.org/rescode.html
_SQLITE_BUSY = 5
_SQLITE_LOCKED = 6
_SQLITE_CONSTRAINT_PRIMARYKEY = 1555
_SQLITE_CONSTRAINT_UNIQUE = 2067
# PostgreSQL SQLSTATEs: unique_violation, and class 40 (transaction rollback).
_PG_UNIQUE_VIOLATION = "23505"
# MySQL and MariaDB ER_DUP_ENTRY. SQLSTATE 23000 is shared by every integrity violation
# (foreign key, NOT NULL, ...), so only this error number identifies a duplicate.
_MYSQL_DUP_ENTRY = 1062
_PG_TRANSACTION_ROLLBACK_CLASS = "40"

_QUOTE = re.compile(r"[\"'`]")

_OUTCOMES = ("written", "duplicates", "failed", "in_doubt")
# ``retries``, ``reconciled`` and ``key_collisions`` are diagnostics, not outcomes: a
# reconciled event is also counted as written, and a key collision as failed.
_COUNTERS = (
    "enqueued",
    *_OUTCOMES,
    "dropped_queue_full",
    "dropped_on_stop",
    "retries",
    "reconciled",
    "key_collisions",
)


class CommitOutcomeUnknown(Exception):
    """The COMMIT failed without a known outcome (for example the connection was
    lost), so the rows may already be stored. The write is retried only after the
    writer has looked up which of its keys are already stored."""


class QueuedEvent(NamedTuple):
    """An accepted event and the sequence number of its idempotency key."""

    seq: int
    event: Dict[str, Any]


@dataclass
class _Attempt:
    """What one write, including its retries, achieved."""

    # Events now known to be stored, by this write or by an earlier COMMIT.
    stored: int = 0
    # The final error, or None when every event is stored.
    error: Exception | None = None
    # The events that are not known to be stored.
    rest: List[QueuedEvent] = field(default_factory=list)
    # True when a COMMIT of ``rest`` had an unknown outcome that is still unresolved.
    in_doubt: bool = False


def _sa_exc() -> Any:
    """``sqlalchemy.exc`` when SQLAlchemy is loaded, else None. An exception SQLAlchemy raised
    implies the package is loaded, so classifying errors never has to import it."""
    return loaded_sqlalchemy_exc()


def _driver_error(exc: BaseException) -> BaseException:
    """The DB-API exception wrapped by SQLAlchemy, or ``exc`` itself."""
    orig = getattr(exc, "orig", None)
    return orig if isinstance(orig, BaseException) else exc


def _sqlstate(driver_exc: BaseException) -> str | None:
    """SQLSTATE of a PostgreSQL driver error (psycopg2 ``pgcode``, psycopg ``sqlstate``)."""
    sqlstate = getattr(driver_exc, "pgcode", None) or getattr(driver_exc, "sqlstate", None)
    return sqlstate if isinstance(sqlstate, str) and sqlstate else None


def _mysql_errno(driver_exc: BaseException) -> int | None:
    """MySQL error number of a PyMySQL or mysqlclient (MySQLdb) error.

    Both raise ``Error(errno, message)``, so the number is ``args[0]``. PostgreSQL and SQLite
    drivers put a string there, or nothing, so an integer identifies the MySQL family.
    """
    args = getattr(driver_exc, "args", None)
    if args and isinstance(args[0], int) and not isinstance(args[0], bool):
        return args[0]
    return None


def _is_sqlite_busy(exc: BaseException) -> bool:
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    code = getattr(exc, "sqlite_errorcode", None)  # Python 3.11+
    if isinstance(code, int):
        return (code & 0xFF) in (_SQLITE_BUSY, _SQLITE_LOCKED)
    message = str(exc).lower()
    return "locked" in message or "busy" in message


def _is_integrity_error(exc: BaseException) -> bool:
    sa_exc = _sa_exc()
    return isinstance(_driver_error(exc), sqlite3.IntegrityError) or (
        sa_exc is not None and isinstance(exc, sa_exc.IntegrityError)
    )


def is_transient_error(exc: BaseException) -> bool:
    """True when retrying may succeed: lock contention or a lost connection."""
    if isinstance(exc, sqlite3.Error):
        return _is_sqlite_busy(exc)
    sa_exc = _sa_exc()
    if sa_exc is None:
        return False
    if isinstance(exc, (sa_exc.TimeoutError, sa_exc.DisconnectionError)):
        return True
    if not isinstance(exc, sa_exc.DBAPIError):
        return False
    if exc.connection_invalidated:
        return True
    if isinstance(exc.orig, sqlite3.Error):
        return _is_sqlite_busy(exc.orig)
    return isinstance(exc, sa_exc.OperationalError)


def is_duplicate_error(exc: BaseException) -> bool:
    """True when ``exc`` is a UNIQUE or PRIMARY KEY violation (the row already exists)."""
    if not _is_integrity_error(exc):
        return False
    driver_exc = _driver_error(exc)
    code = getattr(driver_exc, "sqlite_errorcode", None)  # Python 3.11+
    if isinstance(code, int):
        return code in (_SQLITE_CONSTRAINT_UNIQUE, _SQLITE_CONSTRAINT_PRIMARYKEY)
    mysql_errno = _mysql_errno(driver_exc)
    if mysql_errno is not None:
        # Checked before SQLSTATE: PyMySQL also sets ``sqlstate`` (23000) on these errors.
        return mysql_errno == _MYSQL_DUP_ENTRY
    sqlstate = _sqlstate(driver_exc)
    if sqlstate is not None:
        return sqlstate == _PG_UNIQUE_VIOLATION
    return "unique" in str(driver_exc).lower()


def commit_stored_nothing(exc: BaseException) -> bool:
    """True when a COMMIT that raised ``exc`` is known to have stored nothing.

    SQLite keeps the transaction open, uncommitted, after SQLITE_BUSY or
    SQLITE_LOCKED; a constraint violation (for example a deferred one) commits
    nothing; and PostgreSQL SQLSTATE class 40 (serialization failure, deadlock)
    means the server rolled back. Any other failure, notably a lost connection,
    leaves the outcome unknown.
    """
    driver_exc = _driver_error(exc)
    if _is_sqlite_busy(driver_exc) or _is_integrity_error(exc):
        return True
    sqlstate = _sqlstate(driver_exc)
    return sqlstate is not None and sqlstate.startswith(_PG_TRANSACTION_ROLLBACK_CLASS)


def describe_error(exc: BaseException) -> str:
    """A diagnostic that carries no data values.

    It holds the driver error's type, its SQLite or SQLSTATE code when the driver
    provides one, and the first line of its message cut at the first quote.
    Drivers quote offending values (PostgreSQL: ``invalid input syntax for type
    integer: "..."``), so quoted text, SQL text and later lines are never kept.
    """
    driver_exc = _driver_error(exc)
    label = type(driver_exc).__name__
    code = getattr(driver_exc, "sqlite_errorname", None) or _sqlstate(driver_exc)
    if isinstance(code, str) and code:
        label = f"{label} [{code}]"
    lines = str(driver_exc).splitlines()
    detail = lines[0].strip() if lines else ""
    quote = _QUOTE.search(detail)
    if quote:
        detail = f"{detail[: quote.start()].rstrip()} <redacted>".lstrip()
    return f"{label}: {detail}" if detail else label


def _crossed_power_of_two(before: int, after: int) -> bool:
    """True when a counter reached 1, 2, 4, 8, ...; keeps warnings to O(log n) lines."""
    return after.bit_length() > before.bit_length()


class SQLBatchWriter:
    """Queue events in memory and insert them in batches from a daemon thread.

    Subclasses implement two methods. ``_write_batch(items)`` inserts every
    ``item.event`` with its key ``(self.writer_id, item.seq)`` in one transaction,
    commits through ``_commit()``, and raises, with nothing committed, on any
    other failure. ``_stored_seqs(items)`` returns the ``seq`` of every item whose
    key is already stored. They set ``writer_id``, claimed from the database, and
    call ``_start()`` once their tables exist, or ``_disable()`` when they cannot.
    """

    sink_name = "sql"

    def __init__(
        self,
        *,
        batch_size: int,
        flush_interval_ms: int,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff_ms: int = DEFAULT_RETRY_BACKOFF_MS,
        stop_timeout_s: float = DEFAULT_STOP_TIMEOUT_S,
    ) -> None:
        self.batch_size = max(1, batch_size)
        self.flush_interval = max(10, flush_interval_ms) / 1000.0
        self.max_queue_size = max(100, self.batch_size * 10)
        self.max_retries = max(0, max_retries)
        self.retry_backoff_s = max(0, retry_backoff_ms) / 1000.0
        self.stop_timeout_s = max(0.0, stop_timeout_s)
        self.stop_event = threading.Event()
        self.available = True
        # Fatal: the writer could not start. Write errors only set last_error.
        self.error: str | None = None
        # Most recent write error (see describe_error); the writer keeps running.
        self.last_error: str | None = None
        self.engine: Any = None
        self.thread: threading.Thread | None = None
        # Assigned by the database when the sink starts; part of every row's key.
        self.writer_id: int | None = None
        self._cond = threading.Condition()
        self._queue: deque[QueuedEvent] = deque()
        self._last_seq = 0
        self._in_flight = 0
        self._deadline: float | None = None
        # Set when stop() returned while a write was still running.
        self._stopped_early = False
        self._counts: Dict[str, int] = dict.fromkeys(_COUNTERS, 0)

    def _disable(self, error: str) -> None:
        self.available = False
        self.error = error

    def _start(self) -> None:
        if self.writer_id is None:
            raise RuntimeError("a writer must claim its writer_id before it starts")
        self.thread = threading.Thread(
            target=self._run, name=f"lionlock-{self.sink_name}-writer", daemon=True
        )
        self.thread.start()

    def _write_batch(self, items: List[QueuedEvent]) -> None:
        raise NotImplementedError

    def _stored_seqs(self, items: Sequence[QueuedEvent]) -> Set[int]:
        raise NotImplementedError

    def _commit(self, commit: Callable[[], Any]) -> None:
        """Run ``commit``. If it fails and the rows may already be stored, raise
        ``CommitOutcomeUnknown``, so the stored keys are looked up before any retry."""
        try:
            commit()
        except Exception as exc:
            if commit_stored_nothing(exc):
                raise
            raise CommitOutcomeUnknown(f"commit outcome unknown: {describe_error(exc)}") from exc

    def enqueue(self, event: Dict[str, Any]) -> bool:
        """Queue ``event``; False when the writer is stopped or unavailable.

        A full queue evicts its oldest event so the newest data is kept. Each
        eviction is counted as ``dropped_queue_full`` and reported as a warning.
        The event's key is assigned here, so an evicted event leaves a gap in the
        stored sequence numbers.
        """
        if not isinstance(event, Mapping):
            return False
        with self._cond:
            if not self.available or self.stop_event.is_set():
                return False
            evicted = len(self._queue) >= self.max_queue_size
            if evicted:
                self._queue.popleft()
                self._counts["dropped_queue_full"] += 1
            dropped = self._counts["dropped_queue_full"]
            self._last_seq += 1
            self._queue.append(QueuedEvent(self._last_seq, dict(event)))
            self._counts["enqueued"] += 1
            if len(self._queue) in (1, self.batch_size):
                self._cond.notify()
        if evicted and _crossed_power_of_two(dropped - 1, dropped):
            _LOGGER.warning(
                "sql_sink_queue_full sink=%s max_queue_size=%d dropped_total=%d",
                self.sink_name,
                self.max_queue_size,
                dropped,
            )
        return True

    def stats(self) -> Dict[str, int]:
        """Snapshot of the delivery counters.

        ``pending`` is measured (queued plus in-flight events), so the invariant
        ``enqueued == written + duplicates + failed + in_doubt + dropped + pending``
        is a real consistency check, with ``dropped = dropped_queue_full +
        dropped_on_stop``.
        """
        with self._cond:
            counts = dict(self._counts)
            counts["pending"] = len(self._queue) + self._in_flight
        counts["dropped"] = counts["dropped_queue_full"] + counts["dropped_on_stop"]
        return counts

    def retry_delay_s(self, attempt: int) -> float:
        """Delay before retry ``attempt`` (1-based): ``retry_backoff_ms`` doubled per
        retry, capped at ``MAX_RETRY_BACKOFF_S``. No jitter, so it is deterministic."""
        return min(self.retry_backoff_s * 2 ** min(attempt - 1, 30), MAX_RETRY_BACKOFF_S)

    def stop(self, timeout_s: float | None = None) -> None:
        """Stop accepting events and flush the queue within ``timeout_s`` seconds
        (default ``stop_timeout_s``).

        No batch is taken, and no retry or row-by-row attempt starts, after that
        deadline: events still queued are counted as ``dropped_on_stop`` and events
        whose write was cut short as ``failed``, never lost silently. A write that
        is already running is not interrupted: its events stay ``pending`` when
        this returns, and the counters are logged as ``sql_sink_late_outcome`` once
        it finishes.
        """
        bound = self.stop_timeout_s if timeout_s is None else max(0.0, timeout_s)
        with self._cond:
            if self.stop_event.is_set():
                return
            self.available = False
            deadline = time.monotonic() + bound
            self._deadline = deadline
            self.stop_event.set()
            self._cond.notify_all()
        thread = self.thread
        if thread is None:
            self._dispose_engine()
        elif thread is not threading.current_thread():
            thread.join(max(0.0, deadline - time.monotonic()))
        with self._cond:
            self._drop_queued()
            self._stopped_early = thread is not None and thread.is_alive()
        stats = self.stats()
        if stats["failed"] or stats["in_doubt"] or stats["dropped"] or stats["pending"]:
            self._log_summary("sql_sink_stopped_with_undelivered_events")

    def _log_summary(self, event: str) -> None:
        stats = self.stats()
        _LOGGER.warning(
            "%s sink=%s written=%d duplicates=%d failed=%d in_doubt=%d dropped=%d pending=%d",
            event,
            self.sink_name,
            stats["written"],
            stats["duplicates"],
            stats["failed"],
            stats["in_doubt"],
            stats["dropped"],
            stats["pending"],
        )

    def _past_deadline(self) -> bool:
        deadline = self._deadline
        return deadline is not None and time.monotonic() >= deadline

    def _drop_queued(self) -> None:
        # Caller holds self._cond.
        self._counts["dropped_on_stop"] += len(self._queue)
        self._queue.clear()

    def _dispose_engine(self) -> None:
        if self.engine is not None:
            try:
                self.engine.dispose()
            except Exception:
                pass

    def _run(self) -> None:
        last_flush = time.monotonic()
        while True:
            with self._cond:
                batch = self._next_batch(last_flush)
            if batch is None:
                # The worker owns the engine; release it even if stop() timed out.
                self._dispose_engine()
                return
            self._flush(batch)
            last_flush = time.monotonic()

    def _next_batch(self, last_flush: float) -> List[QueuedEvent] | None:
        """Wait (holding ``_cond``) until a batch is due; None tells the worker to exit."""
        while not self.stop_event.is_set():
            queued = len(self._queue)
            if queued >= self.batch_size:
                break
            timeout: float | None = None
            if queued:
                timeout = last_flush + self.flush_interval - time.monotonic()
                if timeout <= 0:
                    break
            self._cond.wait(timeout)
        if self.stop_event.is_set() and (not self._queue or self._past_deadline()):
            self._drop_queued()
            return None
        batch = [self._queue.popleft() for _ in range(min(self.batch_size, len(self._queue)))]
        self._in_flight = len(batch)
        return batch

    def _flush(self, batch: List[QueuedEvent]) -> None:
        """Insert ``batch``, recording each event in exactly one outcome counter."""
        outcome = dict.fromkeys(_OUTCOMES, 0)
        try:
            self._deliver(batch, outcome)
        except Exception as exc:  # Defensive: a bug here must not kill the worker.
            outcome["failed"] += len(batch) - sum(outcome.values())
            self.last_error = describe_error(exc)
        with self._cond:
            failed_before = self._counts["failed"]
            in_doubt_before = self._counts["in_doubt"]
            for name, count in outcome.items():
                self._counts[name] += count
            self._in_flight = 0
            failed_after = self._counts["failed"]
            in_doubt_after = self._counts["in_doubt"]
            finished_after_stop = self._stopped_early
        if _crossed_power_of_two(failed_before, failed_after):
            _LOGGER.warning(
                "sql_sink_write_failed sink=%s failed_total=%d last_error=%s",
                self.sink_name,
                failed_after,
                self.last_error,
            )
        if _crossed_power_of_two(in_doubt_before, in_doubt_after):
            _LOGGER.warning(
                "sql_sink_commit_outcome_unknown sink=%s in_doubt_total=%d last_error=%s",
                self.sink_name,
                in_doubt_after,
                self.last_error,
            )
        if finished_after_stop:
            # stop() already returned with this batch pending: report its outcome.
            self._log_summary("sql_sink_late_outcome")

    def _deliver(self, batch: List[QueuedEvent], outcome: Dict[str, int]) -> None:
        result = self._write_with_retry(batch)
        outcome["written"] += result.stored
        rest, error = result.rest, result.error
        if error is None:
            return
        if len(rest) == 1 or is_transient_error(error) or isinstance(error, CommitOutcomeUnknown):
            # Nothing to isolate; or retries ran out (or reached the stop deadline).
            outcome[self._outcome_of(error, result.in_doubt, rest)] += len(rest)
            return
        # The failed batch was rolled back. Insert its rows one by one so a single
        # duplicate or invalid row cannot take the rest of the batch down with it.
        # Each row's key is looked up first when an earlier COMMIT may have stored it.
        for index, item in enumerate(rest):
            if self._past_deadline():
                outcome["in_doubt" if result.in_doubt else "failed"] += len(rest) - index
                return
            row = self._write_with_retry([item], in_doubt=result.in_doubt)
            outcome["written"] += row.stored
            if row.error is not None:
                outcome[self._outcome_of(row.error, row.in_doubt, [item])] += 1

    def _outcome_of(self, error: Exception, in_doubt: bool, items: Sequence[QueuedEvent]) -> str:
        """Final classification of a write error on ``items``; true duplicates are not
        errors."""
        if isinstance(error, CommitOutcomeUnknown):
            self.last_error = str(error)
        elif in_doubt or not is_duplicate_error(error):
            self.last_error = describe_error(error)
        if in_doubt:
            return "in_doubt"
        if not is_duplicate_error(error):
            return "failed"
        return self._confirm_duplicate(error, items)

    def _confirm_duplicate(self, error: Exception, items: Sequence[QueuedEvent]) -> str:
        """``duplicates`` only when the events' own keys are not stored.

        "Duplicate" means the event is already stored, so it must be confirmed. Outside
        reconciliation this writer has never stored these events, so a UNIQUE violation
        with their keys free came from another UNIQUE constraint on the table: a true
        duplicate. If a key is already stored, another writer holds this writer's id,
        for example because the writers table was emptied while this writer ran. The
        event was refused, not stored: it is counted as ``failed`` and
        ``key_collisions`` and logged as an error. If the lookup itself fails, the
        duplicate is unconfirmed and the event is counted as ``failed``.
        """
        try:
            taken = self._stored_seqs_with_retry(items) & {item.seq for item in items}
        except Exception as exc:
            self.last_error = f"duplicate not confirmed: {describe_error(exc)}"
            return "failed"
        if not taken:
            return "duplicates"
        with self._cond:
            before = self._counts["key_collisions"]
            self._counts["key_collisions"] += len(taken)
            after = self._counts["key_collisions"]
        self.last_error = (
            f"writer key collision: writer_id {self.writer_id} is in use by another writer; "
            f"{describe_error(error)}"
        )
        if _crossed_power_of_two(before, after):
            _LOGGER.error(
                "sql_sink_writer_key_collision sink=%s writer_id=%s key_collisions_total=%d",
                self.sink_name,
                self.writer_id,
                after,
            )
        return "failed"

    def _stored_seqs_with_retry(self, items: Sequence[QueuedEvent]) -> Set[int]:
        """``_stored_seqs``, retrying transient errors with the write backoff."""
        attempt = 0
        while True:
            try:
                return self._stored_seqs(items)
            except Exception as exc:
                if not is_transient_error(exc) or attempt >= self.max_retries:
                    raise
                attempt += 1
                if not self._backoff(attempt):
                    raise
                with self._cond:
                    self._counts["retries"] += 1

    def _write_with_retry(self, items: List[QueuedEvent], in_doubt: bool = False) -> _Attempt:
        """Write ``items`` in one transaction, retrying transient errors and COMMITs
        with an unknown outcome with backoff.

        ``in_doubt`` means an earlier COMMIT of these items may have stored them.
        While it holds, every attempt starts by looking up the items' keys: the
        stored ones are counted as written (and ``reconciled``) and only the rest is
        inserted. The UNIQUE index on the key backs the lookup up: an insert that
        races a COMMIT still finishing (possible in PostgreSQL) fails instead of
        storing a second copy, and the keys are then looked up once more.
        """
        stored = 0
        attempt = 0
        check = in_doubt
        resolve_on_check = False
        conflict_rechecked = False
        while True:
            try:
                if check:
                    found = self._stored_seqs(items) & {item.seq for item in items}
                    check = False
                    if resolve_on_check:
                        # An insert conflicted after the earlier COMMIT finished, so
                        # this lookup saw its final outcome.
                        in_doubt = resolve_on_check = False
                    if found:
                        stored += len(found)
                        items = [item for item in items if item.seq not in found]
                        with self._cond:
                            self._counts["reconciled"] += len(found)
                    if not items:
                        return _Attempt(stored=stored)
                self._write_batch(items)
                return _Attempt(stored=stored + len(items))
            except CommitOutcomeUnknown as exc:
                error: Exception = exc
                in_doubt = check = True
                self.last_error = str(exc)
            except Exception as exc:
                error = exc
                if not is_transient_error(exc):
                    if in_doubt and _is_integrity_error(exc) and not conflict_rechecked:
                        conflict_rechecked = check = resolve_on_check = True
                        continue
                    return _Attempt(stored, exc, items, in_doubt)
                self.last_error = describe_error(exc)
                check = in_doubt
            if attempt >= self.max_retries:
                return _Attempt(stored, error, items, in_doubt)
            attempt += 1
            if not self._backoff(attempt):
                return _Attempt(stored, error, items, in_doubt)
            with self._cond:
                self._counts["retries"] += 1

    def _backoff(self, attempt: int) -> bool:
        """Wait before retry ``attempt``; False when it could not start before the
        stop deadline (``stop()`` wakes this wait so the deadline applies at once)."""
        resume_at = time.monotonic() + self.retry_delay_s(attempt)
        with self._cond:
            while True:
                if self._deadline is not None and resume_at >= self._deadline:
                    return False
                remaining = resume_at - time.monotonic()
                if remaining <= 0:
                    return True
                self._cond.wait(remaining)
