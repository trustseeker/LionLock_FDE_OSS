"""Local SQLite log file for LionLock telemetry.

One file (default ``logs/lionlock.db``) holds the public signal events and Trust Overlay records
written by this install. Rows are append-only and hash-chained per table, so an edit, reorder, or
deletion inside the retained window is detected by ``LogStore.verify()``. Rows removed from either
end, and a history rewritten with fresh hashes, are detected for certain only against a head
(``LogStore.head()``) recorded somewhere the log's writer cannot change; see ``verify``.

This file never leaves the machine. ``lionlock.telemetry.export`` builds uploads from it by
copying an allowlisted, re-keyed subset into a separate snapshot file.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Tuple

from lionlock.core.models import canonical_gating_decision

from .canonical import (
    GENESIS_HASH,
    canonical_json,
    chain_hash,
    finite_float,
    json_safe,
    utc_now_iso,
)

STORE_SCHEMA_VERSION = 1
STORE_APPLICATION_ID = 0x4C4C4B4C  # "LLKL"
DEFAULT_SQLITE_PATH = "logs/lionlock.db"
DEFAULT_MAX_ROWS = 100_000
PRUNE_CHECK_INTERVAL = 512
BUSY_TIMEOUT_S = 10.0
MAX_DURATION_MS = 10**12

LOG_TABLES: Tuple[str, ...] = ("events", "trust_records")

HASHED_COLUMNS: Dict[str, Tuple[str, ...]] = {
    "events": (
        "ts_utc",
        "request_id",
        "decision",
        "severity",
        "reason_code",
        "aggregate_score",
        "signal_scores_json",
        "signal_bundle_json",
        "duration_ms",
        "config_hash",
        "record_json",
    ),
    "trust_records": (
        "ts_utc",
        "session_id",
        "turn_index",
        "model_id",
        "prompt_type",
        "trust_score",
        "trust_label",
        "badge",
        "volatility",
        "record_json",
    ),
}

_SCHEMA: Tuple[str, ...] = (
    "CREATE TABLE IF NOT EXISTS log_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS events ("
    "seq INTEGER PRIMARY KEY AUTOINCREMENT, "
    "ts_utc TEXT NOT NULL, "
    "request_id TEXT, "
    "decision TEXT NOT NULL, "
    "severity TEXT, "
    "reason_code TEXT, "
    "aggregate_score REAL, "
    "signal_scores_json TEXT NOT NULL, "
    "signal_bundle_json TEXT, "
    "duration_ms INTEGER, "
    "config_hash TEXT, "
    "record_json TEXT NOT NULL, "
    "prev_hash TEXT NOT NULL, "
    "row_hash TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS trust_records ("
    "seq INTEGER PRIMARY KEY AUTOINCREMENT, "
    "ts_utc TEXT NOT NULL, "
    "session_id TEXT NOT NULL, "
    "turn_index INTEGER, "
    "model_id TEXT, "
    "prompt_type TEXT, "
    "trust_score REAL NOT NULL, "
    "trust_label TEXT NOT NULL, "
    "badge TEXT, "
    "volatility REAL, "
    "record_json TEXT NOT NULL, "
    "prev_hash TEXT NOT NULL, "
    "row_hash TEXT NOT NULL)",
)

# sqlite_master filter for objects that belong to the database's own schema. SQLite reserves the
# literal prefix "sqlite_" for its internal objects; in LIKE, "_" is a wildcard, so it is escaped.
USER_SCHEMA_OBJECTS = "name NOT LIKE 'sqlite!_%' ESCAPE '!'"

_KNOWN_TABLES = {"log_meta", "sqlite_sequence", *LOG_TABLES}
_SEVERITIES = {"green", "yellow", "orange", "red"}

_INIT_LOCK = threading.Lock()
_INITIALIZED: set[str] = set()


class StoreError(RuntimeError):
    """Raised when the configured path is not a usable LionLock log file."""


@dataclass(frozen=True)
class Identity:
    """Per-install identity used only when exporting snapshots.

    ``install_id`` is random and appears in uploads. ``export_key`` never leaves this machine:
    it keys the HMAC that replaces raw identifiers in exported rows.
    """

    install_id: str
    export_key: str = field(repr=False)


@dataclass(frozen=True)
class TableHead:
    """The end of one table's chain: rows retained, the last ``seq`` and the last ``row_hash``.

    Unpacks as ``count, last_seq, last_hash = head``. An empty table that was never written has
    head ``(0, 0, GENESIS_HASH)``. Record a head somewhere the log's writer cannot change and
    pass it back to ``LogStore.verify`` later.
    """

    count: int | None  # None only in an expected head whose count was not recorded
    last_seq: int
    last_hash: str

    def __iter__(self) -> Iterator[Any]:
        return iter((self.count, self.last_seq, self.last_hash))

    def as_dict(self) -> Dict[str, Any]:
        return {"count": self.count, "last_seq": self.last_seq, "last_hash": self.last_hash}


@dataclass(frozen=True)
class ChainStatus:
    table: str
    ok: bool
    rows_checked: int
    first_bad_seq: int | None = None
    reason: str | None = None
    head: TableHead | None = None
    # Rows 1..pruned_through were removed by the store's own pruning (0: nothing pruned).
    pruned_through: int = 0


def _text(value: Any, max_len: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:max_len] if text else None


def _non_negative_int(value: Any, upper: int = MAX_DURATION_MS) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, float):
        if not value.is_integer():
            return None
        value = int(value)
    if not isinstance(value, int) or value < 0 or value > upper:
        return None
    return value


def _numeric_map(value: Any) -> Dict[str, float]:
    if not isinstance(value, Mapping):
        return {}
    cleaned: Dict[str, float] = {}
    for key, item in value.items():
        number = finite_float(item)
        if number is not None:
            cleaned[str(key)] = number
    return cleaned


def _decision(value: Any) -> str:
    text = str(value or "").strip()
    if text.upper() == "ERROR":
        return "ERROR"
    return canonical_gating_decision(text or None)


def _event_values(record: Mapping[str, Any]) -> Dict[str, Any]:
    severity = str(record.get("severity") or "").strip().lower()
    bundle = record.get("signal_bundle")
    return {
        "ts_utc": _text(record.get("timestamp_utc"), 64) or utc_now_iso(),
        "request_id": _text(record.get("request_id"), 256),
        "decision": _decision(record.get("decision")),
        "severity": severity if severity in _SEVERITIES else None,
        "reason_code": _text(record.get("reason_code"), 64),
        "aggregate_score": finite_float(record.get("aggregate_score")),
        "signal_scores_json": canonical_json(_numeric_map(record.get("signal_scores"))),
        "signal_bundle_json": (
            canonical_json(json_safe(bundle)) if isinstance(bundle, Mapping) else None
        ),
        "duration_ms": _non_negative_int(record.get("duration_ms")),
        "config_hash": _text(record.get("config_hash"), 128),
        "record_json": canonical_json(json_safe(dict(record))),
    }


def _trust_values(record: Mapping[str, Any]) -> Dict[str, Any]:
    trust_score = finite_float(record.get("trust_score"))
    trust_label = _text(record.get("trust_label"), 32)
    session_id = _text(record.get("session_id"), 256)
    if trust_score is None or trust_label is None or session_id is None:
        raise ValueError("trust record requires session_id, trust_score, and trust_label")
    return {
        "ts_utc": _text(record.get("timestamp"), 64) or utc_now_iso(),
        "session_id": session_id,
        "turn_index": _non_negative_int(record.get("turn_index")),
        "model_id": _text(record.get("model_id"), 256),
        "prompt_type": _text(record.get("prompt_type"), 32),
        "trust_score": trust_score,
        "trust_label": trust_label,
        "badge": _text(record.get("badge"), 32),
        "volatility": finite_float(record.get("volatility")),
        "record_json": canonical_json(json_safe(dict(record))),
    }


def _get_meta(conn: sqlite3.Connection, keys: Tuple[str, ...]) -> Dict[str, str]:
    if not keys:
        return {}
    placeholders = ",".join("?" for _ in keys)
    rows = conn.execute(
        f"SELECT key, value FROM log_meta WHERE key IN ({placeholders})", keys
    ).fetchall()
    return {str(key): str(value) for key, value in rows}


def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT OR REPLACE INTO log_meta (key, value) VALUES (?, ?)", (key, value))


def _check_table(table: str) -> None:
    if table not in LOG_TABLES:
        raise ValueError(f"Unknown log table: {table!r}")


def _ensure_identity(conn: sqlite3.Connection) -> Identity:
    conn.execute(
        "INSERT OR IGNORE INTO log_meta (key, value) VALUES ('install_id', ?)",
        (uuid.uuid4().hex,),
    )
    conn.execute(
        "INSERT OR IGNORE INTO log_meta (key, value) VALUES ('export_key', ?)",
        (secrets.token_hex(32),),
    )
    meta = _get_meta(conn, ("install_id", "export_key"))
    return Identity(install_id=meta["install_id"], export_key=meta["export_key"])


def _sequence_counter(conn: sqlite3.Connection, table: str) -> int:
    """The highest seq SQLite ever handed out for ``table`` (0 if none). Deleting rows does not
    lower it, so it still shows rows removed from the end."""
    try:
        row = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = ?", (table,)).fetchone()
    except sqlite3.OperationalError:  # no AUTOINCREMENT table has ever been written
        return 0
    if row is None or row[0] is None:
        return 0
    value = _parse_row_number(row[0])
    if value is None:
        raise _MalformedMetadata(f"sqlite_sequence for {table} is not a row number: {row[0]!r}")
    return value


class _MalformedMetadata(Exception):
    """Integrity metadata the store cannot parse; verify() reports it as a failed check."""


def _parse_row_number(value: Any) -> int | None:
    """A non-negative row number from SQLite or the meta table, or None if it is not one.

    ``str.isdigit`` alone accepts characters such as '²' that ``int`` rejects, so parse strictly.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    # SQLite row numbers fit in 64 bits (at most 19 digits). Longer strings are not row numbers,
    # and int() refuses very long ones (Python's integer string limit) with ValueError.
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 19:
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _anchor(conn: sqlite3.Connection, table: str) -> Tuple[str | None, str | None]:
    meta = _get_meta(conn, (f"anchor:{table}", f"anchor_seq:{table}"))
    return meta.get(f"anchor:{table}"), meta.get(f"anchor_seq:{table}")


def _table_head(conn: sqlite3.Connection, table: str) -> TableHead:
    _check_table(table)
    count = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    row = conn.execute(f"SELECT seq, row_hash FROM {table} ORDER BY seq DESC LIMIT 1").fetchone()
    if row is not None:
        return TableHead(count, int(row[0]), str(row[1]))
    anchor_hash, anchor_seq = _anchor(conn, table)
    parsed = _parse_row_number(anchor_seq) if anchor_seq is not None else None
    if anchor_hash is not None and parsed is not None:
        return TableHead(0, parsed, anchor_hash)
    return TableHead(0, 0, GENESIS_HASH)


def as_table_head(value: Any) -> TableHead:
    """A ``TableHead`` from a tuple ``(count, last_seq, last_hash)`` or a mapping with those keys.

    ``count`` may be ``None`` (unknown). Raises ``ValueError`` for anything malformed.
    """
    if isinstance(value, TableHead):
        value = tuple(value)
    elif isinstance(value, Mapping):
        value = (value.get("count"), value.get("last_seq"), value.get("last_hash"))
    if not isinstance(value, (tuple, list)) or len(value) != 3:
        raise ValueError("a head is (count, last_seq, last_hash)")
    count, last_seq, last_hash = value
    if count is not None and (isinstance(count, bool) or not isinstance(count, int) or count < 0):
        raise ValueError("head count must be a non-negative integer or null")
    if isinstance(last_seq, bool) or not isinstance(last_seq, int) or last_seq < 0:
        raise ValueError("head last_seq must be a non-negative integer")
    if (
        not isinstance(last_hash, str)
        or len(last_hash) != 64
        or any(char not in "0123456789abcdef" for char in last_hash)
    ):
        raise ValueError("head last_hash must be 64 lowercase hex characters")
    if count is not None and count > last_seq:
        raise ValueError("head count cannot exceed last_seq")
    return TableHead(count, last_seq, last_hash)


def _read_rows(
    conn: sqlite3.Connection, table: str, after_seq: int, limit: int
) -> List[Dict[str, Any]]:
    _check_table(table)
    cursor = conn.execute(
        f"SELECT * FROM {table} WHERE seq > ? ORDER BY seq LIMIT ?", (int(after_seq), int(limit))
    )
    names = [description[0] for description in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


class LogSession:
    """Log operations performed while holding the log's write lock."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def identity(self) -> Identity:
        return _ensure_identity(self._conn)

    def meta(self, *keys: str) -> Dict[str, str]:
        return _get_meta(self._conn, tuple(keys))

    def set_meta(self, updates: Mapping[str, str]) -> None:
        for key, value in updates.items():
            _set_meta(self._conn, key, value)

    def rows(self, table: str, *, after_seq: int, limit: int) -> List[Dict[str, Any]]:
        return _read_rows(self._conn, table, after_seq, limit)


class LogStore:
    """Append-only, hash-chained SQLite log. Safe across threads and processes."""

    def __init__(
        self, path: str | Path = DEFAULT_SQLITE_PATH, *, max_rows: int = DEFAULT_MAX_ROWS
    ) -> None:
        self.path = Path(path).expanduser()
        # Checked before int() truncates: 0 means "keep every row", so letting -1 or -0.5 become 0
        # would silently turn pruning off.
        if float(max_rows) < 0:
            raise ValueError("max_rows must be 0 (keep every row) or a positive row count")
        self.max_rows = int(max_rows)

    def append_event(self, record: Mapping[str, Any]) -> int:
        """Append one sanitized public event (see ``event_log.sanitize_public_event``)."""
        return self._append("events", _event_values(record))

    def append_trust_record(self, record: Mapping[str, Any]) -> int:
        """Append one validated Trust Overlay record."""
        return self._append("trust_records", _trust_values(record))

    def read_rows(
        self, table: str, *, after_seq: int = 0, limit: int = 1000
    ) -> List[Dict[str, Any]]:
        with self._read() as conn:
            return _read_rows(conn, table, after_seq, limit)

    def counts(self) -> Dict[str, int]:
        with self._read() as conn:
            return {
                table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in LOG_TABLES
            }

    def head(self, table: str) -> TableHead:
        """``(count, last_seq, last_hash)`` of one table, read in one transaction."""
        with self._read() as conn:
            return _table_head(conn, table)

    def heads(self) -> Dict[str, TableHead]:
        """``head()`` of every table, read in one transaction."""
        with self._read() as conn:
            return {table: _table_head(conn, table) for table in LOG_TABLES}

    def verify(self, expected_head: Mapping[str, Any] | None = None) -> Dict[str, ChainStatus]:
        """Re-hash every retained row and check the chain's structure.

        Each table must run without gaps from its prune anchor (or seq 1) to a last row equal to
        SQLite's sequence counter; every row must link to the one before it and match its hash.
        ``pruned_through`` reports rows the store's own pruning removed.

        These checks catch deletions made with plain SQL, but someone who can write the file can
        also rewrite the anchor, the counter and every hash. Only a head recorded somewhere the
        writer cannot change detects that: pass ``expected_head={table: head}`` (a ``TableHead``,
        a ``(count, last_seq, last_hash)`` tuple, or a mapping with those keys). Its row must still
        be in the chain with the same hash, or be the prune anchor itself; a head that pruning has
        since removed can no longer be confirmed and fails.
        """
        expected: Dict[str, TableHead] = {}
        for table, value in (expected_head or {}).items():
            _check_table(table)
            expected[table] = as_table_head(value)
        with self._read() as conn:
            return {
                table: self._verify_table(conn, table, expected.get(table)) for table in LOG_TABLES
            }

    def identity(self) -> Identity:
        """Return this install's export identity, creating it on first use."""
        with self._write() as conn:
            return _ensure_identity(conn)

    @contextmanager
    def exclusive(self) -> Iterator[LogSession]:
        """Hold the log's write lock for a multi-step operation such as sealing an export."""
        with self._write() as conn:
            yield LogSession(conn)

    def reset_identity(self) -> Identity:
        """Rotate the export identity so future uploads cannot be linked to past ones.

        Rows already exported are not exported again, and exported sequence numbers restart
        at 1 for the new identity.
        """
        with self._write() as conn:
            watermarks = _get_meta(conn, tuple(f"export:last_seq:{t}" for t in LOG_TABLES))
            _set_meta(conn, "install_id", uuid.uuid4().hex)
            _set_meta(conn, "export_key", secrets.token_hex(32))
            _set_meta(conn, "export:segment_index", "0")
            _set_meta(conn, "export:last_digest", "")
            for table in LOG_TABLES:
                offset = watermarks.get(f"export:last_seq:{table}", "0")
                _set_meta(conn, f"export:seq_offset:{table}", offset)
            meta = _get_meta(conn, ("install_id", "export_key"))
        return Identity(install_id=meta["install_id"], export_key=meta["export_key"])

    def get_meta(self, *keys: str) -> Dict[str, str]:
        with self._read() as conn:
            return _get_meta(conn, tuple(keys))

    def set_meta(self, updates: Mapping[str, str]) -> None:
        with self._write() as conn:
            for key, value in updates.items():
                _set_meta(conn, key, value)

    def _append(self, table: str, values: Dict[str, Any]) -> int:
        columns = HASHED_COLUMNS[table]
        with self._write() as conn:
            prev_hash = self._head_hash(conn, table)
            row_hash = chain_hash(prev_hash, {column: values[column] for column in columns})
            names = (*columns, "prev_hash", "row_hash")
            placeholders = ",".join("?" for _ in names)
            cursor = conn.execute(
                f"INSERT INTO {table} ({','.join(names)}) VALUES ({placeholders})",
                [*(values[column] for column in columns), prev_hash, row_hash],
            )
            seq = int(cursor.lastrowid or 0)
            if self.max_rows and seq % PRUNE_CHECK_INTERVAL == 0:
                self._prune(conn, table)
        return seq

    def _head_hash(self, conn: sqlite3.Connection, table: str) -> str:
        row = conn.execute(f"SELECT row_hash FROM {table} ORDER BY seq DESC LIMIT 1").fetchone()
        if row is not None:
            return str(row[0])
        return _get_meta(conn, (f"anchor:{table}",)).get(f"anchor:{table}", GENESIS_HASH)

    def _prune(self, conn: sqlite3.Connection, table: str) -> int:
        row = conn.execute(
            f"SELECT seq, row_hash FROM {table} ORDER BY seq DESC LIMIT 1 OFFSET ?",
            (self.max_rows,),
        ).fetchone()
        if row is None:
            return 0
        cutoff_seq, cutoff_hash = int(row[0]), str(row[1])
        deleted = conn.execute(f"DELETE FROM {table} WHERE seq <= ?", (cutoff_seq,)).rowcount
        # The oldest retained row links to the last deleted one; keep that link verifiable.
        _set_meta(conn, f"anchor:{table}", cutoff_hash)
        _set_meta(conn, f"anchor_seq:{table}", str(cutoff_seq))
        return int(deleted)

    def _verify_table(
        self, conn: sqlite3.Connection, table: str, expected: TableHead | None = None
    ) -> ChainStatus:
        columns = HASHED_COLUMNS[table]
        head = _table_head(conn, table)
        anchor_hash, anchor_seq_text = _anchor(conn, table)
        anchor_seq = 0
        checked = 0

        def fail(seq: int | None, reason: str) -> ChainStatus:
            return ChainStatus(table, False, checked, seq, reason, head, anchor_seq)

        # Only _prune writes the anchor, and it always writes both keys together.
        if (anchor_hash is None) != (anchor_seq_text is None):
            return fail(None, "prune anchor is incomplete (anchor hash and anchor_seq disagree)")
        if anchor_seq_text is not None:
            parsed_anchor = _parse_row_number(anchor_seq_text)
            if parsed_anchor is None or parsed_anchor < 1:
                return fail(None, "prune anchor_seq is not a positive row number")
            anchor_seq = parsed_anchor
        expected_prev = anchor_hash if anchor_hash is not None else GENESIS_HASH
        expected_seq = anchor_seq + 1
        hash_at_expected_head: str | None = None
        cursor = conn.execute(
            f"SELECT seq, {','.join(columns)}, prev_hash, row_hash FROM {table} ORDER BY seq"
        )
        for row in cursor:
            seq = int(row[0])
            if seq != expected_seq:
                if checked:
                    return fail(seq, f"rows {expected_seq}..{seq - 1} are missing")
                if anchor_hash is None:
                    return fail(
                        seq,
                        f"rows {expected_seq}..{seq - 1} are missing before the first row "
                        "and no prune anchor accounts for them",
                    )
                return fail(
                    seq,
                    f"the first row is seq {seq} but the prune anchor ends at seq {anchor_seq}",
                )
            payload = dict(zip(columns, row[1 : 1 + len(columns)]))
            prev_hash, row_hash = row[-2], row[-1]
            if prev_hash != expected_prev:
                return fail(seq, "prev_hash does not link")
            try:
                recomputed = chain_hash(str(prev_hash), payload)
            except (TypeError, ValueError):
                return fail(seq, "row holds non-canonical values")
            if recomputed != row_hash:
                return fail(seq, "row_hash does not match row")
            if expected is not None and seq == expected.last_seq:
                hash_at_expected_head = str(row_hash)
            expected_prev = row_hash
            expected_seq += 1
            checked += 1

        last_seq = expected_seq - 1
        if anchor_hash is not None and not checked:
            return fail(None, f"no rows remain after the prune anchor (seq {anchor_seq})")
        try:
            counter = _sequence_counter(conn, table)
        except _MalformedMetadata as exc:
            return fail(None, str(exc))
        if counter > last_seq:
            return fail(
                last_seq + 1,
                f"rows {last_seq + 1}..{counter} were deleted from the end "
                f"(the table's sequence counter is at {counter})",
            )
        if counter < last_seq:
            return fail(None, f"the table's sequence counter ({counter}) is behind seq {last_seq}")
        if expected is not None:
            reason = self._check_expected_head(
                expected, last_seq, anchor_hash, anchor_seq, hash_at_expected_head
            )
            if reason is not None:
                return fail(expected.last_seq or None, reason)
        return ChainStatus(table, True, checked, head=head, pruned_through=anchor_seq)

    @staticmethod
    def _check_expected_head(
        expected: TableHead,
        last_seq: int,
        anchor_hash: str | None,
        anchor_seq: int,
        hash_at_expected_head: str | None,
    ) -> str | None:
        """Why the verified chain does not continue the recorded head, or None if it does."""
        if expected.last_seq == 0:
            return None  # recorded while the table was empty; every chain continues from there
        if expected.count is not None and anchor_seq < expected.last_seq - expected.count:
            return (
                f"the recorded head had pruned through seq {expected.last_seq - expected.count}, "
                f"but rows from seq {anchor_seq + 1} are present again: history was rewritten"
            )
        if expected.last_seq > last_seq:
            return (
                f"the recorded head is seq {expected.last_seq} but the last row is seq "
                f"{last_seq}: rows were removed from the end (truncated)"
            )
        if expected.last_seq == anchor_seq:
            if anchor_hash != expected.last_hash:
                return "the prune anchor does not match the recorded head: history was rewritten"
            return None
        if expected.last_seq < anchor_seq:
            return (
                f"the recorded head (seq {expected.last_seq}) has since been pruned (rows up to "
                f"seq {anchor_seq} are gone), so it can no longer be confirmed; record heads "
                "more often than every logging.sqlite_max_rows rows"
            )
        if hash_at_expected_head != expected.last_hash:
            return (
                f"row {expected.last_seq} does not match the recorded head: history was rewritten"
            )
        return None

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self._ensure_initialized()
        conn = sqlite3.connect(str(self.path), timeout=BUSY_TIMEOUT_S, isolation_level=None)
        try:
            conn.execute("PRAGMA secure_delete=ON")
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        # BEGIN IMMEDIATE takes the write lock up front, so reading the chain head and
        # appending the next row are atomic across threads and processes.
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                # Whatever file is at the path now must still be this log, checked under the
                # lock and before the mode or any row changes.
                self._check_identity(conn)
                self._ensure_private(always=False)
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        with self._connect() as conn:
            conn.execute("BEGIN")
            try:
                self._check_identity(conn)
                yield conn
            finally:
                conn.execute("ROLLBACK")

    def _ensure_initialized(self) -> None:
        # The cache only skips creating the schema again. It is not evidence of what the file
        # at this path is now: _write and _read check that on every open.
        key = str(self.path.resolve())
        if key in _INITIALIZED and self.path.exists():
            return
        with _INIT_LOCK:
            if key in _INITIALIZED and self.path.exists():
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.path), timeout=BUSY_TIMEOUT_S, isolation_level=None)
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._check_compatible(conn)
                for ddl in _SCHEMA:
                    conn.execute(ddl)
                conn.execute(f"PRAGMA application_id={STORE_APPLICATION_ID}")
                conn.execute(f"PRAGMA user_version={STORE_SCHEMA_VERSION}")
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()
            # Only after _check_compatible accepted the file, so a foreign file is never touched.
            self._ensure_private(always=True)
            _INITIALIZED.add(key)

    def _ensure_private(self, *, always: bool) -> None:
        """Make the log owner-only (POSIX). ``always`` is set on the first open in a process;
        later writes re-check the mode so a file loosened since then is tightened again."""
        if os.name != "posix":
            return
        try:
            if always or self.path.stat().st_mode & 0o077:
                os.chmod(self.path, 0o600)
        except OSError as exc:
            raise StoreError(f"could not make {self.path} private to its owner: {exc}") from exc

    def _check_identity(self, conn: sqlite3.Connection) -> None:
        """Refuse a file at this path that is not (or is no longer) an initialized LionLock log."""
        app_id = int(conn.execute("PRAGMA application_id").fetchone()[0])
        if app_id != STORE_APPLICATION_ID:
            raise StoreError(f"{self.path} is not a LionLock log file; refusing to use it.")
        self._check_compatible(conn)

    def _check_compatible(self, conn: sqlite3.Connection) -> None:
        app_id = int(conn.execute("PRAGMA application_id").fetchone()[0])
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        entries = conn.execute(
            f"SELECT type, name FROM sqlite_master WHERE {USER_SCHEMA_OBJECTS}"
        ).fetchall()
        tables = {str(name) for kind, name in entries if kind == "table"}
        # A database without LionLock's application id is claimed only if it is empty: no
        # schema of its own and no version stamp. Same-named tables are not enough.
        empty = not entries and version == 0
        if app_id == 0 and not empty:
            raise StoreError(f"{self.path} is not a LionLock log file; refusing to write to it.")
        if app_id not in (0, STORE_APPLICATION_ID) or not tables <= _KNOWN_TABLES:
            raise StoreError(f"{self.path} is not a LionLock log file; refusing to write to it.")
        if version > STORE_SCHEMA_VERSION:
            raise StoreError(
                f"{self.path} uses log schema v{version}; this LionLock supports "
                f"v{STORE_SCHEMA_VERSION}. Upgrade LionLock to write to it."
            )


def _logging_cfg(config: Mapping[str, Any] | None) -> Mapping[str, Any]:
    logging_cfg = config.get("logging", {}) if isinstance(config, Mapping) else {}
    return logging_cfg if isinstance(logging_cfg, Mapping) else {}


def sqlite_logging_enabled(config: Mapping[str, Any] | None) -> bool:
    logging_cfg = _logging_cfg(config)
    backend = str(logging_cfg.get("backend") or "").strip().lower()
    return bool(logging_cfg.get("enabled", True)) and backend == "sqlite"


def resolve_sqlite_path(config: Mapping[str, Any] | None) -> Path:
    raw = str(_logging_cfg(config).get("sqlite_path") or "").strip()
    return Path(raw or DEFAULT_SQLITE_PATH).expanduser()


def open_store(config: Mapping[str, Any] | None) -> LogStore:
    max_rows = _logging_cfg(config).get("sqlite_max_rows", DEFAULT_MAX_ROWS)
    try:
        number = float(max_rows)
        # Negative before truncation, so -0.5 falls back too instead of becoming 0 (keep every row).
        max_rows_int = DEFAULT_MAX_ROWS if number < 0 else int(number)
    except (TypeError, ValueError, OverflowError):
        max_rows_int = DEFAULT_MAX_ROWS
    return LogStore(resolve_sqlite_path(config), max_rows=max_rows_int)
