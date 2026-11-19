"""Receiver hardening: one Authorization value, install binding, request deadlines, connection
caps, deeply nested JSON, log escaping and owner-only files. All data here is synthetic."""

import hashlib
import http.client
import json
import logging
import os
import socket
import sqlite3
import threading
import time
import types
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Sequence, Tuple

import pytest

from lionlock.logging.token_auth import hash_token
from lionlock.telemetry import receiver as receiver_module
from lionlock.telemetry import snapshot as snapshot_module
from lionlock.telemetry.bigquery_sync import _warehouse_state
from lionlock.telemetry.cli import main as cli_main
from lionlock.telemetry.export import export_snapshot, pending_snapshots
from lionlock.telemetry.receiver import (
    WAREHOUSE_DDL,
    Receiver,
    ReceiverConfig,
    ReceiverServer,
    make_server,
)
from lionlock.telemetry.snapshot import (
    SnapshotError,
    file_sha256,
    validate_snapshot,
    write_snapshot,
)
from lionlock.telemetry.store import LogStore
from lionlock.telemetry.upload import (
    CONTENT_TYPE,
    UPLOAD_PATH,
    export_and_upload,
    resolve_upload_settings,
    upload_pending,
)

TOKEN_A = "llk_synthetic_partner_a_0123456789"
TOKEN_B = "llk_synthetic_partner_b_0123456789"
POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="checks POSIX permission bits")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (
        "DO_NOT_TRACK",
        "LIONLOCK_TELEMETRY_UPLOAD",
        "LIONLOCK_TELEMETRY_ENDPOINT",
        "LIONLOCK_UPLOAD_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def serve(tmp_path) -> Iterator[Callable[..., Tuple[ReceiverServer, int]]]:
    servers: List[ReceiverServer] = []

    def _start(**overrides: Any) -> Tuple[ReceiverServer, int]:
        config = ReceiverConfig(data_dir=tmp_path / "server", **overrides)
        server = make_server(config, host="localhost", port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server, int(server.server_address[1])

    yield _start
    for server in servers:
        server.shutdown()
        server.server_close()


def _log(directory: Path, count: int = 3, start: int = 0) -> Path:
    db = directory / "log.db"
    store = LogStore(db)
    for i in range(start, start + count):
        store.append_event(
            {
                "timestamp_utc": f"2026-09-27T10:{i % 60:02d}:00Z",
                "request_id": f"req-{i}",
                "decision": "REFRESH",
                "severity": "yellow",
                "reason_code": "low_coherence",
                "aggregate_score": 0.5,
                "signal_scores": {"coherence_structure": 0.5},
                "duration_ms": 100 + i,
            }
        )
    return db


def _export(directory: Path, count: int = 3, start: int = 0) -> Path:
    db = _log(directory, count, start)
    result = export_snapshot(LogStore(db), directory / "outbox")
    assert result is not None
    return result.path


def _forge(genuine: Path, target: Path) -> Path:
    """Different content for the same install and segment, with a correct digest."""
    info = validate_snapshot(genuine)
    first = list(info.rows["events"][0])
    first[8] = 999  # duration_ms
    meta = {key: value for key, value in info.meta.items() if key != "content_digest"}
    write_snapshot(target, meta, {**info.rows, "events": [tuple(first), *info.rows["events"][1:]]})
    return target


def _headers(path: Path, token: str | None = None) -> Dict[str, str]:
    info = validate_snapshot(path)
    headers = {
        "Content-Type": CONTENT_TYPE,
        "X-LionLock-File-SHA256": file_sha256(path),
        "X-LionLock-Install-Id": info.install_id,
        "X-LionLock-Segment": str(info.segment_index),
        "X-LionLock-Content-Digest": info.content_digest,
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _post(port: int, body: bytes, headers: Sequence[Tuple[str, str]]) -> int:
    """POST with headers sent exactly as listed, repeated names included."""
    conn = http.client.HTTPConnection("localhost", port, timeout=10)
    try:
        conn.putrequest("POST", UPLOAD_PATH, skip_accept_encoding=True)
        for name, value in headers:
            conn.putheader(name, value)
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        response = conn.getresponse()
        response.read()
        return int(response.status)
    finally:
        conn.close()


# A body that passes every check up to the rate limit and is then rejected as not a snapshot.
_NOT_A_SNAPSHOT = b"synthetic bytes that are not a snapshot"
_NOT_A_SNAPSHOT_HEADERS = [
    ("Content-Type", CONTENT_TYPE),
    ("X-LionLock-File-SHA256", hashlib.sha256(_NOT_A_SNAPSHOT).hexdigest()),
    ("X-LionLock-Install-Id", "0" * 32),
]


def _rows(db: Path, query: str, params: Tuple[Any, ...] = ()) -> list:
    conn = sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True)
    try:
        return conn.execute(query, params).fetchall()
    finally:
        conn.close()


def _wait_for(predicate: Callable[[], bool], timeout_s: float = 5.0) -> bool:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


# ---------------------------------------------------------------------------------------------
# 1. Exactly one Authorization value is authorized, counted and bound
# ---------------------------------------------------------------------------------------------


def test_a_second_authorization_header_cannot_dodge_the_per_token_limit(serve) -> None:
    _, port = serve(token_hashes=frozenset({hash_token(TOKEN_A)}), uploads_per_hour=3)
    valid = ("Authorization", f"Bearer {TOKEN_A}")

    doubled = [
        _post(port, _NOT_A_SNAPSHOT, [*_NOT_A_SNAPSHOT_HEADERS, valid, ("Authorization", junk)])
        for junk in (f"Bearer junk-{i}" for i in range(5))
    ]
    # Control: one header is counted against the token.
    single = [_post(port, _NOT_A_SNAPSHOT, [*_NOT_A_SNAPSHOT_HEADERS, valid]) for _ in range(5)]
    assert (doubled, single) == ([400] * 5, [422, 422, 422, 429, 429])


def test_junk_authorization_values_cannot_fill_the_rate_table(serve, tmp_path, monkeypatch):
    monkeypatch.setattr(receiver_module, "_RATE_KEYS_MAX", 2)
    tokens = frozenset({hash_token(TOKEN_A), hash_token(TOKEN_B)})
    _, port = serve(token_hashes=tokens, uploads_per_hour=50)
    valid_a = ("Authorization", f"Bearer {TOKEN_A}")
    attacker = [
        _post(port, _NOT_A_SNAPSHOT, [*_NOT_A_SNAPSHOT_HEADERS, valid_a, ("Authorization", junk)])
        for junk in (f"Bearer junk-{i}" for i in range(3))
    ]
    # Another partner's first upload is still counted and accepted, not locked out.
    genuine = _export(tmp_path / "b")
    partner = _post(port, genuine.read_bytes(), list(_headers(genuine, TOKEN_B).items()))
    assert (partner, attacker) == (201, [400] * 3)


def test_handle_upload_authorizes_and_counts_the_same_single_value(tmp_path) -> None:
    receiver = Receiver(
        ReceiverConfig(
            data_dir=tmp_path / "server",
            token_hashes=frozenset({hash_token(TOKEN_A)}),
            uploads_per_hour=1,
        )
    )
    path = _export(tmp_path / "a")
    body, headers = path.read_bytes(), _headers(path)

    both = {**headers, "Authorization": f"Bearer {TOKEN_A}", "authorization": "Bearer junk"}
    assert receiver.handle_upload(both, body).status == 400
    assert receiver.handle_upload(headers, body).status == 401
    assert receiver.handle_upload({**headers, "Authorization": "Bearer junk"}, body).status == 401
    # None of the refusals used the token's one upload for this hour.
    assert receiver.handle_upload(_headers(path, TOKEN_A), body).status == 201


# ---------------------------------------------------------------------------------------------
# 2. An install is bound to the token that first uploaded for it
# ---------------------------------------------------------------------------------------------


def test_an_install_stays_bound_to_the_token_that_first_uploaded_for_it(tmp_path) -> None:
    receiver = Receiver(
        ReceiverConfig(
            data_dir=tmp_path / "server",
            token_hashes=frozenset({hash_token(TOKEN_A), hash_token(TOKEN_B)}),
        )
    )

    def send(path: Path, token: str) -> int:
        return receiver.handle_upload(_headers(path, token), path.read_bytes()).status

    b_dir = tmp_path / "b"
    b_seg1 = _export(b_dir)
    assert send(b_seg1, TOKEN_B) == 201
    b_seg2 = _export(b_dir, count=2, start=3)
    fake_seg2 = _forge(b_seg2, tmp_path / "fake.db")

    assert send(fake_seg2, TOKEN_A) == 403  # a new segment for B's install
    assert send(b_seg1, TOKEN_A) == 403  # B's own bytes, resent
    assert send(b_seg2, TOKEN_B) == 201  # B is unaffected
    assert send(_export(tmp_path / "a"), TOKEN_A) == 201  # and so is A's own install

    warehouse = tmp_path / "server" / "warehouse.db"
    owners = _rows(warehouse, "SELECT install_id, token_sha256 FROM install_owners ORDER BY 2")
    install_b = validate_snapshot(b_seg1).install_id
    assert (install_b, hash_token(TOKEN_B)) in owners and len(owners) == 2
    segments = "SELECT segment_index FROM uploads WHERE install_id = ? ORDER BY 1"
    assert _rows(warehouse, segments, (install_b,)) == [(1,), (2,)]
    assert TOKEN_B.encode() not in warehouse.read_bytes()
    # A binding refusal judges nothing, so it leaves no rejected/ note.
    assert list((tmp_path / "server" / "rejected").iterdir()) == []


def test_a_squatted_install_never_makes_its_owner_set_a_snapshot_aside(
    tmp_path, serve, monkeypatch
) -> None:
    """The reviewed attack: A uploads a fake segment for B's install before B does. B's genuine
    snapshot must stay in B's outbox for the operator to resolve, not be marked rejected."""
    tokens = frozenset({hash_token(TOKEN_A), hash_token(TOKEN_B)})
    _, port = serve(token_hashes=tokens)
    b_dir = tmp_path / "b"
    genuine = _export(b_dir)
    fake = _forge(genuine, tmp_path / "fake.db")
    assert _post(port, fake.read_bytes(), list(_headers(fake, TOKEN_A).items())) == 201

    monkeypatch.setenv("LIONLOCK_UPLOAD_TOKEN", TOKEN_B)
    settings = resolve_upload_settings(
        {
            "logging": {"enabled": True, "backend": "sqlite", "sqlite_path": str(b_dir / "log.db")},
            "logging_sql": {"enabled": False},
            "telemetry_upload": {
                "enabled": True,
                "endpoint": f"http://localhost:{port}",
                "outbox_dir": str(b_dir / "outbox"),
            },
        }
    )
    outcomes = upload_pending(settings, sleep=lambda _s: None)
    assert [(o.status, o.http_status) for o in outcomes] == [("auth_failed", 403)]
    assert pending_snapshots(settings.outbox_dir) == [genuine]
    assert not (settings.outbox_dir / "rejected").exists()


def test_a_warehouse_from_before_install_binding_is_upgraded_in_place(tmp_path) -> None:
    data_dir = tmp_path / "server"
    data_dir.mkdir()
    warehouse = data_dir / "warehouse.db"
    conn = sqlite3.connect(warehouse)
    try:
        for ddl in WAREHOUSE_DDL:
            if "install_owners" not in ddl:
                conn.execute(ddl)
        conn.execute("PRAGMA user_version=2")
        conn.execute(
            "INSERT INTO uploads VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("a" * 32, 1, "b" * 64, "", "ok", "c" * 64, "d" * 64, "2026-01-01T00:00:00Z")
            + ("1.0.0b1", "3.12", "linux", 1, 0, 1, 0),
        )
        conn.execute(
            "INSERT INTO events (install_id, seq, decision, signal_scores_json) "
            "VALUES ('" + "a" * 32 + "', 1, 'ALLOW', '{}')"
        )
        conn.execute(
            "INSERT INTO trust_records (install_id, seq, session_key, model_family, trust_score, "
            "trust_label, trigger_flags_json, detail_json) "
            "VALUES ('" + "a" * 32 + "', 1, '', 'other', 0.5, 'MONITOR', '[]', '{}')"
        )
        conn.commit()
    finally:
        conn.close()
    note = data_dir / "rejected" / f"{'e' * 64}.reason.txt"
    note.parent.mkdir()
    note.write_text("synthetic reason\n", encoding="utf-8")
    if os.name == "posix":
        os.chmod(data_dir, 0o750)
        os.chmod(warehouse, 0o640)
        os.chmod(note, 0o644)

    def state() -> Dict[str, Any]:
        tables = ("uploads", "events", "trust_records")
        ro = sqlite3.connect(f"{warehouse.resolve().as_uri()}?mode=ro", uri=True)
        try:
            return {
                "rows": {t: ro.execute(f"SELECT * FROM {t}").fetchall() for t in tables},
                "sql": ro.execute(
                    "SELECT type, name, sql FROM sqlite_master WHERE tbl_name IN "
                    "('uploads', 'events', 'trust_records') ORDER BY name"
                ).fetchall(),
                "user_version": ro.execute("PRAGMA user_version").fetchone()[0],
                "sync": _warehouse_state(ro),
                "modes": [p.stat().st_mode & 0o777 for p in (data_dir, warehouse, note)],
                "note": note.read_bytes(),
            }
        finally:
            ro.close()

    before = state()
    assert before["sync"] == "current"  # bigquery-sync can read it before the upgrade too
    Receiver(ReceiverConfig(data_dir=data_dir, token_hashes=frozenset({hash_token(TOKEN_A)})))
    assert state() == before
    assert _rows(warehouse, "SELECT * FROM install_owners") == []
    columns = [row[1] for row in _rows(warehouse, "PRAGMA table_info(install_owners)")]
    assert columns == ["install_id", "token_sha256", "bound_hour"]
    Receiver(ReceiverConfig(data_dir=data_dir))  # an upgraded warehouse opens as current
    assert state() == before


# ---------------------------------------------------------------------------------------------
# 3. Slow clients: a total request deadline and a connection cap
# ---------------------------------------------------------------------------------------------


class _Clock:
    """A clock the test moves by hand; ``read`` is set once the server has consulted it."""

    def __init__(self) -> None:
        self.now = 1_000_000.0
        self.read = threading.Event()

    def __call__(self) -> float:
        self.read.set()
        return self.now


def _slot_watch(receiver: Receiver, monkeypatch) -> threading.Event:
    taken = threading.Event()
    original = receiver.upload_slot

    @contextmanager
    def watched() -> Iterator[bool]:
        with original() as acquired:
            if acquired:
                taken.set()
            yield acquired

    monkeypatch.setattr(receiver, "upload_slot", watched)
    return taken


def _upload_config(tmp_path: Path, port: int) -> dict:
    return {
        "logging": {"enabled": True, "backend": "sqlite", "sqlite_path": str(tmp_path / "log.db")},
        "logging_sql": {"enabled": False},
        "telemetry_upload": {"enabled": True, "endpoint": f"http://localhost:{port}"},
    }


def test_a_trickling_body_loses_its_upload_slot_at_the_deadline(
    serve, tmp_path, monkeypatch
) -> None:
    server, port = serve(max_concurrent_uploads=1)
    clock = _Clock()
    server.receiver.clock = clock
    taken = _slot_watch(server.receiver, monkeypatch)

    slow = socket.create_connection(("localhost", port), timeout=5)
    try:
        slow.sendall(
            f"POST {UPLOAD_PATH} HTTP/1.0\r\nContent-Type: {CONTENT_TYPE}\r\n"
            "Content-Length: 1000\r\n\r\n".encode("ascii")
        )
        assert taken.wait(5), "the slow request never reached its upload slot"
        _log(tmp_path)
        config = _upload_config(tmp_path, port)
        busy = export_and_upload(config, max_attempts=1)
        assert [(u["status"], u["http_status"]) for u in busy["uploads"]] == [("retry", 503)]

        clock.now += 3600  # long past any deadline; no real waiting
        slow.sendall(b"x")  # one more byte, as a trickling client would send
        assert slow.recv(4096).startswith(b"HTTP/1.0 408")
    finally:
        slow.close()
    after = export_and_upload(config, max_attempts=1)
    assert [u["status"] for u in after["uploads"]] == ["uploaded"]


def test_slow_request_headers_are_cut_off_at_the_deadline(serve) -> None:
    server, port = serve()
    clock = _Clock()
    server.receiver.clock = clock
    slow = socket.create_connection(("localhost", port), timeout=5)
    try:
        slow.sendall(f"POST {UPLOAD_PATH} HTTP/1.0\r\nContent-Type: ".encode("ascii"))
        assert clock.read.wait(5), "the request deadline was never measured"
        clock.now += 3600
        slow.sendall(b"a")
        try:
            assert slow.recv(4096) == b""  # dropped without a response, as the stdlib does
        except ConnectionResetError:
            pass
    finally:
        slow.close()


def _read_all(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _health(port: int) -> int | None:
    conn = http.client.HTTPConnection("localhost", port, timeout=5)
    try:
        conn.request("GET", "/healthz")
        return int(conn.getresponse().status)
    except (OSError, http.client.HTTPException):
        return None
    finally:
        conn.close()


def test_connections_beyond_the_cap_are_answered_503_at_once(serve) -> None:
    _, port = serve(max_connections=2)
    idle = [socket.create_connection(("localhost", port), timeout=5) for _ in range(2)]
    try:
        extra = socket.create_connection(("localhost", port), timeout=5)
        try:
            reply = _read_all(extra)
        finally:
            extra.close()
        assert reply.startswith(b"HTTP/1.0 503")
        assert b"Retry-After: 30" in reply and b"receiver is busy" in reply
    finally:
        for sock in idle:
            sock.close()
    # Capacity comes back as soon as the idle connections go away.
    assert _wait_for(lambda: _health(port) == 200)


# ---------------------------------------------------------------------------------------------
# 4. Deeply nested or oversized JSON is an ordinary rejection
# ---------------------------------------------------------------------------------------------


def _deeply_nested(tmp_path: Path) -> Path:
    info = validate_snapshot(_export(tmp_path / "log"))
    first = list(info.rows["events"][0])
    first[6] = "[" * 100_000 + "]" * 100_000  # signal_scores_json
    meta = {key: value for key, value in info.meta.items() if key != "content_digest"}
    deep = tmp_path / "deep.db"
    write_snapshot(deep, meta, {"events": [tuple(first)], "trust_records": []})
    return deep


def test_deeply_nested_json_is_rejected_not_crashed_on(tmp_path, serve, capsys) -> None:
    deep = _deeply_nested(tmp_path)
    with pytest.raises(SnapshotError, match="nested too deeply"):
        validate_snapshot(deep)

    _, port = serve()
    assert _post(port, deep.read_bytes(), list(_headers_unchecked(deep).items())) == 422
    note = tmp_path / "server" / "rejected" / f"{file_sha256(deep)}.reason.txt"
    assert "nested too deeply" in note.read_text(encoding="utf-8")

    code = cli_main(["--config", str(tmp_path / "absent.toml"), "inspect", str(deep)])
    assert code == 1
    assert json.loads(capsys.readouterr().out)["valid"] is False


def test_running_out_of_memory_while_decoding_is_a_snapshot_error(tmp_path, monkeypatch):
    path = _export(tmp_path)

    def exhausted(_value: str) -> Any:
        raise MemoryError

    monkeypatch.setattr(snapshot_module, "json", types.SimpleNamespace(loads=exhausted))
    with pytest.raises(SnapshotError):
        validate_snapshot(path)


def _headers_unchecked(path: Path) -> Dict[str, str]:
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        meta = dict(conn.execute("SELECT key, value FROM snapshot_meta"))
    finally:
        conn.close()
    return {
        "Content-Type": CONTENT_TYPE,
        "X-LionLock-File-SHA256": file_sha256(path),
        "X-LionLock-Install-Id": meta["install_id"],
        "X-LionLock-Segment": meta["segment_index"],
        "X-LionLock-Content-Digest": meta["content_digest"],
    }


# ---------------------------------------------------------------------------------------------
# 5. Control characters in requests are escaped in the log
# ---------------------------------------------------------------------------------------------


def test_request_lines_cannot_write_control_characters_to_the_log(serve, caplog) -> None:
    caplog.set_level(logging.INFO, logger="lionlock.telemetry.receiver")
    _, port = serve()
    sock = socket.create_connection(("localhost", port), timeout=5)
    try:
        sock.sendall(b"GET /\x1b[2J\x07probe\\ HTTP/1.0\r\n\r\n")
        assert _read_all(sock).startswith(b"HTTP/1.0 404")
    finally:
        sock.close()
    assert "\x1b" not in caplog.text and "\x07" not in caplog.text
    assert "/\\x1b[2J\\x07probe\\\\" in caplog.text


# ---------------------------------------------------------------------------------------------
# 6. New receiver files are owner-only; existing modes are kept and reported
# ---------------------------------------------------------------------------------------------


class _ModeSpy:
    """Stands in for the receiver module's ``sqlite3`` and records the warehouse file's mode
    right after every read-write connect, so a briefly world-readable file would be seen."""

    def __init__(self) -> None:
        self.modes: List[int] = []

    def connect(self, database: Any, *args: Any, **kwargs: Any) -> Any:
        conn = sqlite3.connect(database, *args, **kwargs)
        if str(database).endswith("warehouse.db"):
            self.modes.append(os.stat(database).st_mode & 0o777)
        return conn

    def __getattr__(self, name: str) -> Any:
        return getattr(sqlite3, name)


@POSIX_ONLY
def test_new_receiver_paths_are_created_owner_only(tmp_path, monkeypatch) -> None:
    previous = os.umask(0o022)
    try:
        spy = _ModeSpy()
        monkeypatch.setattr(receiver_module, "sqlite3", spy)
        data_dir = tmp_path / "server"
        receiver = Receiver(ReceiverConfig(data_dir=data_dir))
        bad = receiver.handle_upload(dict(_NOT_A_SNAPSHOT_HEADERS), _NOT_A_SNAPSHOT)
        good = _export(tmp_path / "log")
        assert bad.status == 422
        assert receiver.handle_upload(_headers(good), good.read_bytes()).status == 201
    finally:
        os.umask(previous)

    def mode(path: Path) -> int:
        return path.stat().st_mode & 0o777

    assert spy.modes and set(spy.modes) == {0o600}
    assert mode(data_dir / "warehouse.db") == 0o600
    for name in ("", "quarantine", "accepted", "rejected"):
        assert mode(data_dir / name) == 0o700, name
    for path in (*(data_dir / "rejected").iterdir(), *(data_dir / "accepted").iterdir()):
        assert mode(path) == 0o600, path.name


@POSIX_ONLY
def test_existing_receiver_modes_are_kept_and_reported(tmp_path, caplog) -> None:
    data_dir = tmp_path / "server"
    Receiver(ReceiverConfig(data_dir=data_dir))
    note = data_dir / "rejected" / f"{'f' * 64}.reason.txt"
    note.write_text("synthetic earlier reason\n", encoding="utf-8")
    shared = {
        data_dir: 0o755,
        data_dir / "warehouse.db": 0o644,
        data_dir / "rejected": 0o755,
        note: 0o644,
    }
    for path, wanted in shared.items():
        os.chmod(path, wanted)

    caplog.set_level(logging.WARNING, logger="lionlock.telemetry.receiver")
    receiver = Receiver(ReceiverConfig(data_dir=data_dir))
    assert receiver.handle_upload(dict(_NOT_A_SNAPSHOT_HEADERS), _NOT_A_SNAPSHOT).status == 422

    for path, wanted in shared.items():
        assert path.stat().st_mode & 0o777 == wanted, path.name
    assert note.read_text(encoding="utf-8") == "synthetic earlier reason\n"
    new_note = data_dir / "rejected" / f"{hashlib.sha256(_NOT_A_SNAPSHOT).hexdigest()}.reason.txt"
    assert new_note.stat().st_mode & 0o777 == 0o600
    reported = caplog.text
    for label, mode in (
        ("data directory", "0755"),
        ("warehouse.db", "0644"),
        ("rejected/", "0755"),
    ):
        assert f"{label} is accessible to group or others (mode {mode})" in reported
    assert "accepted/" not in reported and "quarantine/" not in reported
