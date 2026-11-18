"""Reference ingest server for LionLock telemetry snapshots (standard library only).

Run it on infrastructure you control, behind a TLS-terminating reverse proxy::

    lionlock-telemetry serve --data-dir /var/lib/lionlock-telemetry --port 8787

Every upload is treated as hostile input. The body is size-capped before and after gzip
decompression, and the SHA-256 of the decompressed bytes (``received_sha256``) must equal the
declared ``X-LionLock-File-SHA256``. Its raw bytes then exist only in an
owner-only file under ``quarantine/`` while they are validated: opened read-only with SQLite's
hardening options, the file must match the snapshot schema exactly, pass ``PRAGMA quick_check``,
reproduce its content digest, and come through a re-run of the export policy unchanged. The
validated rows are then rebuilt into a fresh file, and only that rebuild is stored, durably and
before the upload is recorded, as ``accepted/<stored_sha256>.db``. Uploaded bytes are deleted
whether the upload is accepted or rejected; a rejection keeps only its reason. Uploads are
idempotent per (install, segment) by ``content_digest``, a duplicate is confirmed only while its
accepted file is intact, and client IP addresses are never logged or stored.

With tokens, each install is bound to the token that first uploaded a segment for it, and other
tokens are refused for that install. Every request must arrive in full within a total deadline,
and the server handles a bounded number of connections at once. New files and directories are
created owner-only.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import socket
import sqlite3
import sys
import threading
import time
import uuid
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Mapping, Tuple

from lionlock.logging.token_auth import hash_token

from .snapshot import (
    COLUMNS,
    DATA_TABLES,
    DEFAULT_MAX_SNAPSHOT_BYTES,
    SnapshotError,
    SnapshotInfo,
    rebuild_clean,
    validate_snapshot_bytes,
)
from .store import USER_SCHEMA_OBJECTS
from .upload import CONTENT_TYPE, UPLOAD_PATH

_LOGGER = logging.getLogger(__name__)

DEFAULT_MAX_BODY_BYTES = 16 * 1024 * 1024
DEFAULT_UPLOADS_PER_HOUR = 120
_RATE_KEYS_MAX = 100_000
DEFAULT_MAX_CONCURRENT_UPLOADS = 4
# A request (request line, headers and body) must arrive in full within this many seconds. A
# full 20,000-row snapshot is a few hundred KB of gzip, so this leaves ample room for slow links.
DEFAULT_REQUEST_DEADLINE_S = 60.0
# Connections handled at once; more are answered 503 straight away, without starting a thread.
DEFAULT_MAX_CONNECTIONS = 32
# Idle limit for any single read or write on a connection.
_SOCKET_TIMEOUT_S = 30.0

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

_PRIVATE_DIR_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600

# v2: uploads are keyed by (install_id, segment_index) and record the SHA-256 of the received
# file and of the rebuilt file kept in accepted/ separately. Older warehouses are refused.
# install_owners, which binds each install to the token that first uploaded for it, was added to
# v2 later: a v2 warehouse that predates it is upgraded in place by adding that one table, and
# no existing row, table or index changes.
WAREHOUSE_SCHEMA_VERSION = 2

_WAREHOUSE_V2_BASE_DDL: Tuple[str, ...] = (
    "CREATE TABLE IF NOT EXISTS uploads ("
    "install_id TEXT NOT NULL, "
    "segment_index INTEGER NOT NULL, "
    "content_digest TEXT NOT NULL, "
    "prev_segment_digest TEXT NOT NULL, "
    "chain_status TEXT NOT NULL, "
    "received_sha256 TEXT NOT NULL, "
    "stored_sha256 TEXT NOT NULL, "
    "received_hour TEXT NOT NULL, "
    "lionlock_version TEXT NOT NULL, "
    "python TEXT NOT NULL, "
    "platform TEXT NOT NULL, "
    "events_rows INTEGER NOT NULL, "
    "events_pruned_before_export INTEGER NOT NULL, "
    "trust_records_rows INTEGER NOT NULL, "
    "trust_records_pruned_before_export INTEGER NOT NULL, "
    "PRIMARY KEY (install_id, segment_index))",
    "CREATE INDEX IF NOT EXISTS uploads_by_received_sha256 ON uploads (received_sha256)",
    "CREATE TABLE IF NOT EXISTS events ("
    "install_id TEXT NOT NULL, "
    "seq INTEGER NOT NULL, "
    "ts_hour TEXT, "
    "decision TEXT NOT NULL, "
    "severity TEXT, "
    "reason_code TEXT, "
    "aggregate_score REAL, "
    "signal_scores_json TEXT NOT NULL, "
    "signal_bundle_json TEXT, "
    "duration_ms INTEGER, "
    "config_hash TEXT, "
    "PRIMARY KEY (install_id, seq))",
    "CREATE TABLE IF NOT EXISTS trust_records ("
    "install_id TEXT NOT NULL, "
    "seq INTEGER NOT NULL, "
    "ts_hour TEXT, "
    "session_key TEXT NOT NULL, "
    "turn_index INTEGER, "
    "model_family TEXT NOT NULL, "
    "prompt_type TEXT, "
    "trust_score REAL NOT NULL, "
    "trust_label TEXT NOT NULL, "
    "badge TEXT, "
    "volatility REAL, "
    "drift_detected INTEGER, "
    "trigger_flags_json TEXT NOT NULL, "
    "detail_json TEXT NOT NULL, "
    "PRIMARY KEY (install_id, seq))",
)

# token_sha256 is the allowlist entry (SHA-256 of the bearer token), never the token itself.
_INSTALL_OWNERS_DDL = (
    "CREATE TABLE IF NOT EXISTS install_owners ("
    "install_id TEXT PRIMARY KEY NOT NULL, "
    "token_sha256 TEXT NOT NULL, "
    "bound_hour TEXT NOT NULL)"
)

WAREHOUSE_DDL: Tuple[str, ...] = (*_WAREHOUSE_V2_BASE_DDL, _INSTALL_OWNERS_DDL)

_UPGRADABLE = "upgradable"


@dataclass(frozen=True)
class ReceiverConfig:
    data_dir: Path
    # SHA-256 hashes of accepted bearer tokens; empty means anonymous uploads are accepted.
    token_hashes: frozenset[str] = frozenset()
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_snapshot_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES
    uploads_per_hour: int = DEFAULT_UPLOADS_PER_HOUR
    max_concurrent_uploads: int = DEFAULT_MAX_CONCURRENT_UPLOADS
    request_deadline_s: float = DEFAULT_REQUEST_DEADLINE_S
    max_connections: int = DEFAULT_MAX_CONNECTIONS


@dataclass(frozen=True)
class IngestResult:
    status: int
    body: Dict[str, Any]
    headers: Dict[str, str] = field(default_factory=dict)


def load_token_hashes(path: str | Path) -> frozenset[str]:
    """Read one SHA-256 token hash per line (``#`` comments allowed); raw tokens are refused.

    A file that lists no hashes is refused too: an empty allowlist must not silently turn into
    anonymous mode. Anonymous mode means passing no token file at all.
    """
    hashes = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip().lower()
        if not stripped or stripped.startswith("#"):
            continue
        if not _HEX64.fullmatch(stripped):
            raise ValueError("token hash file must contain only 64-hex SHA-256 hashes")
        hashes.add(stripped)
    if not hashes:
        raise ValueError(
            "token hash file lists no token hashes; add at least one, or omit the file to accept "
            "anonymous uploads"
        )
    return frozenset(hashes)


def gunzip_capped(data: bytes, limit: int) -> bytes:
    """Decompress a single gzip member, refusing output larger than ``limit`` bytes."""
    decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
    output = bytearray()
    pending = data
    try:
        while pending and not decompressor.eof:
            output += decompressor.decompress(pending, 1 << 16)
            if len(output) > limit:
                raise ValueError("decompressed body exceeds the size limit")
            pending = decompressor.unconsumed_tail
    except zlib.error as exc:
        raise ValueError("body is not valid gzip") from exc
    if not decompressor.eof:
        raise ValueError("gzip body is truncated")
    if decompressor.unused_data:
        raise ValueError("gzip body has trailing data")
    return bytes(output)


class WarehouseVersionError(RuntimeError):
    """Raised when ``warehouse.db`` was created with a different layout than this receiver's."""


def _schema_signature(conn: sqlite3.Connection) -> Tuple[Any, ...]:
    """Schema objects with their SQL, plus each table's columns and each index's key columns."""
    entries = sorted(
        conn.execute(
            f"SELECT type, name, tbl_name, sql FROM sqlite_master WHERE {USER_SCHEMA_OBJECTS}"
        ).fetchall()
    )
    tables = [name for kind, name, *_ in entries if kind == "table"]
    columns = {table: conn.execute(f'PRAGMA table_xinfo("{table}")').fetchall() for table in tables}
    indexes = {
        table: sorted(
            (tuple(index[1:]), tuple(conn.execute(f'PRAGMA index_xinfo("{index[1]}")').fetchall()))
            for index in conn.execute(f'PRAGMA index_list("{table}")').fetchall()
        )
        for table in tables
    }
    return tuple(entries), columns, indexes


_SIGNATURES: Dict[Tuple[str, ...], Tuple[Any, ...]] = {}


def _reference_signature(ddl: Tuple[str, ...]) -> Tuple[Any, ...]:
    if ddl not in _SIGNATURES:
        reference = sqlite3.connect(":memory:")
        try:
            for statement in ddl:
                reference.execute(statement)
            _SIGNATURES[ddl] = _schema_signature(reference)
        finally:
            reference.close()
    return _SIGNATURES[ddl]


def _warehouse_layout(conn: sqlite3.Connection) -> str:
    """``empty``, ``current``, ``upgradable`` or a short reason the warehouse cannot be used.

    Empty means no schema objects of its own, ``user_version`` 0 and ``application_id`` 0;
    tables with zero rows are not empty. Current means ``user_version`` 2 and a schema that
    matches ``WAREHOUSE_DDL`` exactly, including columns, keys and indexes. Upgradable means
    ``user_version`` 2 and an exact match for the v2 layout from before ``install_owners``.
    """
    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    app_id = int(conn.execute("PRAGMA application_id").fetchone()[0])
    objects = conn.execute(
        f"SELECT COUNT(*) FROM sqlite_master WHERE {USER_SCHEMA_OBJECTS}"
    ).fetchone()[0]
    if version == 0 and app_id == 0 and objects == 0:
        return "empty"
    if app_id != 0:
        return f"it has application_id {app_id}"
    if version != WAREHOUSE_SCHEMA_VERSION:
        return f"it uses warehouse layout v{version or 1}"
    signature = _schema_signature(conn)
    if signature == _reference_signature(WAREHOUSE_DDL):
        return "current"
    if signature == _reference_signature(_WAREHOUSE_V2_BASE_DDL):
        return _UPGRADABLE
    return f"its v{version} schema does not match this receiver's"


def _warehouse_state(conn: sqlite3.Connection) -> str:
    """``empty``, ``current`` or a short reason the warehouse cannot be read.

    For readers of ``uploads``, ``events`` and ``trust_records`` (bigquery-sync): those tables
    are identical with and without ``install_owners``, so a warehouse the receiver has not
    upgraded yet still counts as current here. ``install_owners`` is never read by them.
    """
    layout = _warehouse_layout(conn)
    return "current" if layout == _UPGRADABLE else layout


def _refuse(path: Path, reason: str) -> WarehouseVersionError:
    return WarehouseVersionError(
        f"{path.name} cannot be used: {reason}. It was left unchanged; this receiver writes "
        f"warehouse layout v{WAREHOUSE_SCHEMA_VERSION} only, so start it with a new data "
        "directory"
    )


def _create_private_file(path: Path) -> None:
    """Create ``path`` empty and owner-only, unless it exists (its mode is then left alone)."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, _PRIVATE_FILE_MODE)
    except FileExistsError:
        return
    os.close(fd)


def init_warehouse(path: Path) -> None:
    """Create the warehouse, upgrade one from before ``install_owners``, or confirm it.

    An existing file is inspected read-only before anything is created or written. A v2
    warehouse that predates ``install_owners`` is upgraded in place by adding that empty table,
    in one transaction; no existing row, table, index or version field is touched. Anything
    other than an empty database, that layout or the current layout is refused unchanged: no
    reset or overwrite. A new warehouse and data directory are created owner-only.
    """
    if path.exists() and path.stat().st_size > 0:
        try:
            conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
            try:
                state = _warehouse_layout(conn)
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise _refuse(path, "it is not a readable SQLite database") from exc
        if state == "current":
            return
        if state not in ("empty", _UPGRADABLE):
            raise _refuse(path, state)

    path.parent.mkdir(mode=_PRIVATE_DIR_MODE, parents=True, exist_ok=True)
    # SQLite would create the file world-readable; create it owner-only first. Its journal
    # files take the database file's mode.
    _create_private_file(path)
    conn = sqlite3.connect(str(path), isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        state = _warehouse_layout(conn)  # re-checked under the write lock
        if state == "empty":
            for ddl in WAREHOUSE_DDL:
                conn.execute(ddl)
            conn.execute(f"PRAGMA user_version={WAREHOUSE_SCHEMA_VERSION}")
        elif state == _UPGRADABLE:
            conn.execute(_INSTALL_OWNERS_DDL)
        else:
            conn.execute("ROLLBACK")
            if state == "current":
                return
            raise _refuse(path, state)
        conn.execute("COMMIT")
        if state == _UPGRADABLE:
            _LOGGER.warning("%s upgraded in place: added the install_owners table", path.name)
    finally:
        conn.close()


_CONFLICTS = {
    "conflict": "segment was already received with different content",
    "sequence_conflict": "segment rows reuse sequence numbers already stored for this install",
}
_O_BINARY = getattr(os, "O_BINARY", 0)


def _fsync_directory(directory: Path) -> None:
    """Persist a rename inside ``directory`` (POSIX; elsewhere the rename itself suffices)."""
    if os.name != "posix":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _error(status: int, message: str, headers: Dict[str, str] | None = None) -> IngestResult:
    return IngestResult(status, {"status": "error", "error": message}, dict(headers or {}))


def _current_hour() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:00:00Z")


def _rate_key(token_sha: str | None, install_id: str) -> str:
    """Who an upload is counted against.

    With tokens, the SHA-256 of the token that was authorized for this request: a client cannot
    change it without a new token, so rotating install ids does not reset its budget, and only
    allowlisted tokens ever become keys. Anonymous uploads can only be counted per install id,
    which the client chooses, so that limit slows a misbehaving client but cannot stop a
    deliberate one; docs/TELEMETRY.md says to require tokens on any public endpoint.
    """
    return "token:" + token_sha if token_sha is not None else "install:" + install_id


class Receiver:
    """Validation and storage for uploaded snapshots, independent of the HTTP layer."""

    def __init__(self, config: ReceiverConfig) -> None:
        self.config = config
        self.quarantine_dir = config.data_dir / "quarantine"
        self.accepted_dir = config.data_dir / "accepted"
        self.rejected_dir = config.data_dir / "rejected"
        self.warehouse_path = config.data_dir / "warehouse.db"
        init_warehouse(self.warehouse_path)
        for directory in (self.quarantine_dir, self.accepted_dir, self.rejected_dir):
            directory.mkdir(mode=_PRIVATE_DIR_MODE, parents=True, exist_ok=True)
        self._report_shared_modes()
        self._ingest_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._rate: Dict[str, Tuple[int, int]] = {}
        self._rate_pruned_hour = -1
        self._slots = threading.BoundedSemaphore(max(1, config.max_concurrent_uploads))
        # Measures each request's deadline; replaceable so tests need not sleep.
        self.clock: Callable[[], float] = time.monotonic

    def _report_shared_modes(self) -> None:
        """Warn about existing receiver paths that group or others can access.

        New paths are created owner-only, but existing modes are an operator's choice and are
        never changed here; this only reports them.
        """
        if os.name != "posix":
            return
        for path, label in (
            (self.config.data_dir, "data directory"),
            (self.warehouse_path, "warehouse.db"),
            (self.quarantine_dir, "quarantine/"),
            (self.accepted_dir, "accepted/"),
            (self.rejected_dir, "rejected/"),
        ):
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                _LOGGER.warning(
                    "%s is accessible to group or others (mode %04o); new receiver files are "
                    "created owner-only, but existing modes are left unchanged",
                    label,
                    mode,
                )

    def _token_sha256(self, header: str | None) -> str | None:
        """The allowlisted SHA-256 of the bearer token in ``header``, or None."""
        if not header or not header.startswith("Bearer "):
            return None
        token = header[len("Bearer ") :].strip()
        if not token:
            return None
        digest = hash_token(token)
        return digest if digest in self.config.token_hashes else None

    def authorize(self, header: str | None) -> bool:
        if not self.config.token_hashes:
            return True
        return self._token_sha256(header) is not None

    @contextmanager
    def upload_slot(self) -> Iterator[bool]:
        """Reserve one of ``max_concurrent_uploads`` slots before reading a request body."""
        acquired = self._slots.acquire(blocking=False)
        try:
            yield acquired
        finally:
            if acquired:
                self._slots.release()

    def handle_upload(self, headers: Mapping[str, str], body: bytes) -> IngestResult:
        # The single Authorization value is both what is authorized and what the upload is
        # counted and bound against. More than one is refused: with two, one could be checked
        # and the other counted.
        authorization = [value for key, value in headers.items() if key.lower() == "authorization"]
        if len(authorization) > 1:
            return _error(400, "more than one Authorization header")
        token_sha: str | None = None
        if self.config.token_hashes:
            token_sha = self._token_sha256(authorization[0] if authorization else None)
            if token_sha is None:
                return _error(401, "unauthorized", {"WWW-Authenticate": "Bearer"})
        lowered = {key.lower(): value for key, value in headers.items()}
        if lowered.get("content-type", "").split(";")[0].strip() != CONTENT_TYPE:
            return _error(415, "unsupported content type")
        encoding = lowered.get("content-encoding", "identity").strip().lower()
        limit = self.config.max_snapshot_bytes
        if encoding == "gzip":
            try:
                data = gunzip_capped(body, limit)
            except ValueError as exc:
                return _error(413 if "limit" in str(exc) else 400, str(exc))
        elif encoding in ("", "identity"):
            data = body
            if len(data) > limit:
                return _error(413, "snapshot exceeds the size limit")
        else:
            return _error(415, "unsupported content encoding")

        received_sha = hashlib.sha256(data).hexdigest()
        if lowered.get("x-lionlock-file-sha256", "").strip().lower() != received_sha:
            return _error(400, "X-LionLock-File-SHA256 does not match the body")
        install_id = lowered.get("x-lionlock-install-id", "").strip().lower()
        if not _HEX32.fullmatch(install_id):
            return _error(400, "missing or malformed X-LionLock-Install-Id")
        # Counted before the duplicate shortcut: resending identical bytes still costs a gunzip,
        # a hash and a re-read of the stored file, so it must not be free.
        if not self._within_rate(_rate_key(token_sha, install_id)):
            return _error(429, "upload rate limit exceeded", {"Retry-After": "3600"})
        if token_sha is not None and self._bound_elsewhere(install_id, token_sha):
            return self._foreign_install()
        recorded = self._recorded_upload_for(received_sha)
        if recorded is not None:
            stored, recorded_install = recorded
            if token_sha is not None and self._bound_elsewhere(recorded_install, token_sha):
                return self._foreign_install()
            if not self._evidence_intact(stored):
                return self._evidence_failure()
            return IngestResult(200, {"status": "duplicate", "file_sha256": received_sha})

        try:
            info = validate_snapshot_bytes(data, max_bytes=limit, work_dir=self.quarantine_dir)
            self._check_headers(lowered, info)
            clean = rebuild_clean(info, work_dir=self.quarantine_dir)
        except SnapshotError as exc:
            self._reject(received_sha, str(exc))
            return _error(422, str(exc))

        stored_sha = hashlib.sha256(clean).hexdigest()
        outcome, recorded_sha = self._ingest(received_sha, stored_sha, clean, info, token_sha)
        if outcome == "foreign_install":
            return self._foreign_install()
        if outcome in _CONFLICTS:
            message = _CONFLICTS[outcome]
            self._reject(received_sha, message)
            return _error(409, message)
        if outcome == "duplicate" and not self._evidence_intact(recorded_sha):
            return self._evidence_failure()
        body_out: Dict[str, Any] = {
            "status": outcome,
            "file_sha256": received_sha,
            "install_id": info.install_id,
            "segment_index": info.segment_index,
        }
        if outcome == "created":
            body_out["stored_sha256"] = stored_sha
        return IngestResult(201 if outcome == "created" else 200, body_out)

    def _check_headers(self, headers: Mapping[str, str], info: SnapshotInfo) -> None:
        declared = (
            headers.get("x-lionlock-install-id", "").strip().lower(),
            headers.get("x-lionlock-segment", "").strip(),
            headers.get("x-lionlock-content-digest", "").strip().lower(),
        )
        if declared != (info.install_id, str(info.segment_index), info.content_digest):
            raise SnapshotError("upload headers do not match the snapshot metadata")

    def _bound_elsewhere(self, install_id: str, token_sha: str) -> bool:
        """Whether ``install_id`` is bound to a token other than ``token_sha``."""
        conn = sqlite3.connect(str(self.warehouse_path), timeout=30)
        try:
            row = conn.execute(
                "SELECT token_sha256 FROM install_owners WHERE install_id = ?", (install_id,)
            ).fetchone()
        finally:
            conn.close()
        return row is not None and row[0] != token_sha

    @staticmethod
    def _foreign_install() -> IngestResult:
        # No rejected/ note: the snapshot was not judged, and its owner may still send it.
        _LOGGER.warning("refused an upload for an install bound to a different token")
        return _error(403, "install is bound to a different upload token")

    def _within_rate(self, key: str) -> bool:
        if self.config.uploads_per_hour <= 0:
            return True
        with self._rate_lock:
            # Read the clock under the lock: a stale hour could overwrite a live bucket with an
            # expired one and use up the once-per-hour prune.
            hour = int(time.time() // 3600)
            if len(self._rate) >= _RATE_KEYS_MAX and key not in self._rate:
                # Drop only buckets from earlier hours, at most once per hour so a full table is
                # not rescanned on every refused key. Clearing everything would hand every client
                # a fresh budget to anyone who cycles through enough install ids.
                if self._rate_pruned_hour != hour:
                    self._rate = {k: v for k, v in self._rate.items() if v[0] == hour}
                    self._rate_pruned_hour = hour
                if len(self._rate) >= _RATE_KEYS_MAX:
                    return False
            bucket_hour, count = self._rate.get(key, (hour, 0))
            if bucket_hour != hour:
                count = 0
            if count >= self.config.uploads_per_hour:
                return False
            self._rate[key] = (hour, count + 1)
        return True

    def _recorded_upload_for(self, received_sha: str) -> Tuple[str, str] | None:
        """(stored_sha256, install_id) of a committed upload that arrived as exactly these bytes."""
        conn = sqlite3.connect(str(self.warehouse_path), timeout=30)
        try:
            row = conn.execute(
                "SELECT stored_sha256, install_id FROM uploads WHERE received_sha256 = ? LIMIT 1",
                (received_sha,),
            ).fetchone()
        finally:
            conn.close()
        return None if row is None else (str(row[0]), str(row[1]))

    def _evidence_intact(self, stored_sha: str | None) -> bool:
        """Whether the accepted file a committed upload points to exists with its recorded hash."""
        if not stored_sha:
            return False
        path = self.accepted_dir / f"{stored_sha}.db"
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest() == stored_sha
        except OSError:
            return False

    @staticmethod
    def _evidence_failure() -> IngestResult:
        # The warehouse record is left as it is: it is the evidence that something went wrong.
        _LOGGER.error("a recorded upload's accepted file is missing or corrupt")
        return _error(500, "stored evidence missing or corrupt")

    def _store(self, stored_sha: str, clean: bytes) -> None:
        """Write accepted/<stored_sha>.db durably. Called before the upload is committed, so a
        recorded upload always has its file. Accepted files are never deleted here: a failure
        later in the same request can leave an unreferenced (orphan) clean file behind."""
        target = self.accepted_dir / f"{stored_sha}.db"
        if self._evidence_intact(stored_sha):
            return
        partial = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        try:
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(clean)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(partial, target)
        finally:
            partial.unlink(missing_ok=True)
        _fsync_directory(self.accepted_dir)

    def _reject(self, received_sha: str, reason: str) -> None:
        """Record why an upload was refused. The uploaded bytes themselves are not kept.

        A new note is created owner-only; an existing one is overwritten with its mode unchanged.
        """
        note = self.rejected_dir / f"{received_sha}.reason.txt"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_BINARY
        fd = os.open(note, flags, _PRIVATE_FILE_MODE)
        with os.fdopen(fd, "wb") as handle:
            handle.write((reason + "\n").encode("utf-8"))

    def _ingest(
        self,
        received_sha: str,
        stored_sha: str,
        clean: bytes,
        info: SnapshotInfo,
        token_sha: str | None = None,
    ) -> Tuple[str, str | None]:
        """Merge a validated segment once; returns (outcome, recorded stored_sha256).

        Its logical content decides duplicate vs conflict, so the same segment in a
        bytewise-different file is a duplicate, not a conflict. Rows that reuse sequence numbers
        already stored for the install are a conflict too. The accepted file is written durably
        before the upload is committed.

        With a token, an install bound to another token is refused (``foreign_install``) before
        anything else is decided, and an unbound install is bound to this token in the same
        transaction that records its first new segment. Anonymous uploads neither bind nor check.
        """
        meta = info.meta
        with self._ingest_lock:
            conn = sqlite3.connect(str(self.warehouse_path), timeout=30, isolation_level=None)
            try:
                conn.execute("BEGIN IMMEDIATE")
                owner = None
                if token_sha is not None:
                    owner = conn.execute(
                        "SELECT token_sha256 FROM install_owners WHERE install_id = ?",
                        (info.install_id,),
                    ).fetchone()
                    if owner is not None and owner[0] != token_sha:
                        conn.execute("ROLLBACK")
                        return "foreign_install", None
                existing = conn.execute(
                    "SELECT content_digest, stored_sha256 FROM uploads "
                    "WHERE install_id = ? AND segment_index = ?",
                    (info.install_id, info.segment_index),
                ).fetchone()
                if existing is not None:
                    conn.execute("ROLLBACK")
                    same = existing[0] == info.content_digest
                    return ("duplicate" if same else "conflict"), str(existing[1])
                if self._reuses_sequence_numbers(conn, info):
                    conn.execute("ROLLBACK")
                    return "sequence_conflict", None
                self._store(stored_sha, clean)
                upload: Dict[str, Any] = {
                    "install_id": info.install_id,
                    "segment_index": info.segment_index,
                    "content_digest": info.content_digest,
                    "prev_segment_digest": meta["prev_segment_digest"],
                    "chain_status": self._chain_status(conn, info),
                    "received_sha256": received_sha,
                    "stored_sha256": stored_sha,
                    "received_hour": _current_hour(),
                    "lionlock_version": meta["lionlock_version"],
                    "python": meta["python"],
                    "platform": meta["platform"],
                    "events_rows": int(meta["events_rows"]),
                    "events_pruned_before_export": int(meta["events_pruned_before_export"]),
                    "trust_records_rows": int(meta["trust_records_rows"]),
                    "trust_records_pruned_before_export": int(
                        meta["trust_records_pruned_before_export"]
                    ),
                }
                conn.execute(
                    f"INSERT INTO uploads ({','.join(upload)}) "
                    f"VALUES ({','.join('?' for _ in upload)})",
                    tuple(upload.values()),
                )
                for table in DATA_TABLES:
                    columns = ("install_id", *COLUMNS[table])
                    placeholders = ",".join("?" for _ in columns)
                    conn.executemany(
                        f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})",
                        [(info.install_id, *row) for row in info.rows[table]],
                    )
                self._relink_successor(conn, info)
                if token_sha is not None and owner is None:
                    conn.execute(
                        "INSERT INTO install_owners (install_id, token_sha256, bound_hour) "
                        "VALUES (?, ?, ?)",
                        (info.install_id, token_sha, _current_hour()),
                    )
                conn.execute("COMMIT")
                return "created", stored_sha
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    @staticmethod
    def _reuses_sequence_numbers(conn: sqlite3.Connection, info: SnapshotInfo) -> bool:
        for table in DATA_TABLES:
            seqs = [row[0] for row in info.rows[table]]
            for start in range(0, len(seqs), 500):
                chunk = seqs[start : start + 500]
                hit = conn.execute(
                    f"SELECT 1 FROM {table} WHERE install_id = ? "
                    f"AND seq IN ({','.join('?' for _ in chunk)}) LIMIT 1",
                    (info.install_id, *chunk),
                ).fetchone()
                if hit is not None:
                    return True
        return False

    @staticmethod
    def _relink_successor(conn: sqlite3.Connection, info: SnapshotInfo) -> None:
        """A successor that arrived first was recorded as a gap; judge it now."""
        row = conn.execute(
            "SELECT prev_segment_digest FROM uploads WHERE install_id = ? AND segment_index = ?",
            (info.install_id, info.segment_index + 1),
        ).fetchone()
        if row is not None:
            conn.execute(
                "UPDATE uploads SET chain_status = ? WHERE install_id = ? AND segment_index = ?",
                (
                    "ok" if row[0] == info.content_digest else "broken",
                    info.install_id,
                    info.segment_index + 1,
                ),
            )

    @staticmethod
    def _chain_status(conn: sqlite3.Connection, info: SnapshotInfo) -> str:
        prev_digest = info.meta["prev_segment_digest"]
        if info.segment_index == 1:
            return "ok" if prev_digest == "" else "broken"
        row = conn.execute(
            "SELECT content_digest FROM uploads WHERE install_id = ? AND segment_index = ?",
            (info.install_id, info.segment_index - 1),
        ).fetchone()
        if row is None:
            return "gap"
        return "ok" if row[0] == prev_digest else "broken"


class _DeadlineReader(io.RawIOBase):
    """Reads a request socket, giving up once the request's total deadline has passed.

    A per-read timeout alone lets a client that sends one byte at a time hold a connection, and
    an upload slot, indefinitely. Every read here waits at most the idle timeout and never past
    the deadline, which is fixed when the connection is accepted.
    """

    def __init__(
        self, sock: socket.socket, deadline: float, idle_s: float, clock: Callable[[], float]
    ) -> None:
        super().__init__()
        self._sock = sock
        self._deadline = deadline
        self._idle_s = idle_s
        self._clock = clock

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        remaining = self._deadline - self._clock()
        if remaining <= 0:
            raise TimeoutError("request deadline exceeded")
        self._sock.settimeout(min(self._idle_s, remaining))
        return self._sock.recv_into(buffer)


# The standard library's log_message escapes these; an override must do the same, or a request
# line could write terminal escape sequences or forged lines into the log.
_LOG_ESCAPES = str.maketrans({c: f"\\x{c:02x}" for c in (*range(0x20), *range(0x7F, 0xA0))})
_LOG_ESCAPES[ord("\\")] = "\\\\"


class _Handler(BaseHTTPRequestHandler):
    server_version = "lionlock-receiver"
    sys_version = ""
    timeout = _SOCKET_TIMEOUT_S

    def setup(self) -> None:
        super().setup()
        receiver: Receiver = self.server.receiver  # type: ignore[attr-defined]
        deadline = receiver.clock() + receiver.config.request_deadline_s
        self.rfile.close()  # releases only the stdlib's reader; the socket stays open
        self.rfile = io.BufferedReader(
            _DeadlineReader(self.connection, deadline, _SOCKET_TIMEOUT_S, receiver.clock)
        )

    def log_message(self, format: str, *args: Any) -> None:
        # Deliberately omits the client address: the receiver never records IP addresses.
        _LOGGER.info("%s", (format % args).translate(_LOG_ESCAPES))

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._reply(200, {"status": "ok"})
        else:
            self._reply(404, {"status": "error", "error": "not found"})

    def do_POST(self) -> None:
        receiver: Receiver = self.server.receiver  # type: ignore[attr-defined]
        if self.path != UPLOAD_PATH:
            self._reply(404, {"status": "error", "error": "not found"})
            return
        authorization = self.headers.get_all("Authorization") or []
        if len(authorization) > 1:
            self._reply(400, {"status": "error", "error": "more than one Authorization header"})
            return
        if not receiver.authorize(authorization[0] if authorization else None):
            self._reply(
                401, {"status": "error", "error": "unauthorized"}, {"WWW-Authenticate": "Bearer"}
            )
            return
        try:
            length = int(self.headers.get("Content-Length") or "")
        except ValueError:
            self._reply(411, {"status": "error", "error": "Content-Length is required"})
            return
        if length <= 0 or length > receiver.config.max_body_bytes:
            self._reply(413, {"status": "error", "error": "body size is out of range"})
            return
        with receiver.upload_slot() as acquired:
            if not acquired:
                result = _error(503, "receiver is busy; retry later", {"Retry-After": "30"})
                self._reply(result.status, result.body, result.headers)
                return
            try:
                body = self.rfile.read(length)
            except TimeoutError:
                self.close_connection = True
                self._reply(408, {"status": "error", "error": "request did not arrive in time"})
                return
            if len(body) != length:
                self._reply(400, {"status": "error", "error": "incomplete body"})
                return
            try:
                # Exactly one Authorization header reaches this point, the one just authorized.
                result = receiver.handle_upload(dict(self.headers.items()), body)
            except Exception:  # noqa: BLE001 - never leak internals to the client
                _LOGGER.exception("snapshot ingest failed")
                result = _error(500, "internal error")
        self._reply(result.status, result.body, result.headers)

    def _reply(
        self, status: int, payload: Dict[str, Any], headers: Dict[str, str] | None = None
    ) -> None:
        # A read may have shortened the socket timeout to the deadline's remainder; writing the
        # reply gets the ordinary idle timeout.
        self.connection.settimeout(_SOCKET_TIMEOUT_S)
        data = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)


_BUSY_BODY = (
    json.dumps({"error": "receiver is busy; retry later", "status": "error"}, sort_keys=True) + "\n"
).encode("utf-8")
_BUSY_RESPONSE = (
    "HTTP/1.0 503 Service Unavailable\r\n"
    "Server: lionlock-receiver\r\n"
    "Content-Type: application/json\r\n"
    f"Content-Length: {len(_BUSY_BODY)}\r\n"
    "Cache-Control: no-store\r\n"
    "Retry-After: 30\r\n"
    "Connection: close\r\n"
    "\r\n"
).encode("ascii") + _BUSY_BODY


def _answer_busy(sock: socket.socket) -> None:
    """Best-effort 503 from the accepting thread: it never waits on the client."""
    try:
        sock.setblocking(False)
        sock.send(_BUSY_RESPONSE)
        sock.recv(65536)  # take what already arrived, so closing is less likely to reset
    except OSError:
        pass


class ReceiverServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: Tuple[str, int], receiver: Receiver) -> None:
        super().__init__(address, _Handler)
        self.receiver = receiver
        self._connections = threading.BoundedSemaphore(max(1, receiver.config.max_connections))

    def process_request(self, request: Any, client_address: Any) -> None:
        """Start a handler thread, unless ``max_connections`` are already being handled."""
        if not self._connections.acquire(blocking=False):
            _LOGGER.warning("connection limit reached; answered 503")
            _answer_busy(request)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connections.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connections.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        # The stdlib default prints client_address to stderr; the receiver never records it.
        _LOGGER.error("request handler failed: %s", type(sys.exc_info()[1]).__name__)


def make_server(
    config: ReceiverConfig, host: str = "127.0.0.1", port: int = 8787
) -> ReceiverServer:
    return ReceiverServer((host, port), Receiver(config))
