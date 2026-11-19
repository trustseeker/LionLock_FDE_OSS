"""Local SQLite log: heads, deletions from either end, prune anchors and recorded checkpoints."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from lionlock.telemetry import store as store_module
from lionlock.telemetry.canonical import chain_hash
from lionlock.telemetry.cli import main
from lionlock.telemetry.store import GENESIS_HASH, HASHED_COLUMNS, LogStore, TableHead


def _event(i: int) -> dict:
    return {
        "timestamp_utc": f"2026-09-27T10:{i % 60:02d}:00Z",
        "request_id": f"req-{i}",
        "decision": "ALLOW",
        "severity": "green",
        "aggregate_score": 0.1,
        "signal_scores": {"repetition_loopiness": 0.1},
    }


def _store_with(path: Path, rows: int, **kwargs) -> LogStore:
    store = LogStore(path, **kwargs)
    for i in range(rows):
        store.append_event(_event(i))
    return store


def _sql(path: Path, *statements: tuple) -> None:
    with sqlite3.connect(path) as conn:
        for statement in statements:
            conn.execute(*statement)


def _row_hash(path: Path, seq: int) -> str:
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT row_hash FROM events WHERE seq = ?", (seq,)).fetchone()[0]


def test_head_reports_count_last_seq_and_last_hash(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    store = _store_with(path, 3)
    assert store.head("events") == TableHead(3, 3, _row_hash(path, 3))
    assert store.head("trust_records") == TableHead(0, 0, GENESIS_HASH)
    assert store.heads()["events"] == store.head("events")
    status = store.verify()["events"]
    assert status.ok and status.head == store.head("events") and status.pruned_through == 0


def test_the_reviewers_attack_no_longer_verifies(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    store = _store_with(path, 10)

    _sql(path, ("DELETE FROM events WHERE seq > 7",))
    status = store.verify()["events"]
    assert not status.ok
    assert status.reason == (
        "rows 8..10 were deleted from the end (the table's sequence counter is at 10)"
    )

    anchor = _row_hash(path, 3)
    _sql(
        path,
        ("DELETE FROM events WHERE seq <= 3",),
        ("INSERT OR REPLACE INTO log_meta (key, value) VALUES ('anchor:events', ?)", (anchor,)),
    )
    status = store.verify()["events"]  # was (ok=True, rows_checked=4)
    assert (status.ok, status.rows_checked) == (False, 0)
    assert "prune anchor is incomplete" in str(status.reason)


def test_deleting_from_the_start_with_a_rewritten_anchor_hash_is_caught(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    store = _store_with(path, 10)
    anchor = _row_hash(path, 3)
    _sql(
        path,
        ("DELETE FROM events WHERE seq <= 3",),
        ("INSERT OR REPLACE INTO log_meta (key, value) VALUES ('anchor:events', ?)", (anchor,)),
    )
    status = store.verify()["events"]
    assert not status.ok and "prune anchor is incomplete" in str(status.reason)

    # An anchor_seq that does not meet the first row is caught too. One that does, with the
    # counter rewritten as well, needs a recorded head (see the forgery test below).
    _sql(path, ("INSERT INTO log_meta (key, value) VALUES ('anchor_seq:events', '2')",))
    status = store.verify()["events"]
    assert not status.ok
    assert status.reason == "the first row is seq 4 but the prune anchor ends at seq 2"


def test_deleting_from_the_start_without_an_anchor_is_named_as_such(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    store = _store_with(path, 5)
    _sql(path, ("DELETE FROM events WHERE seq <= 2",))
    status = store.verify()["events"]
    assert not status.ok and status.first_bad_seq == 3
    assert "no prune anchor accounts for them" in str(status.reason)


def test_a_gap_in_the_middle_is_reported_where_it_is(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    store = _store_with(path, 5)
    _sql(path, ("DELETE FROM events WHERE seq = 3",))
    status = store.verify()["events"]
    assert (status.ok, status.first_bad_seq, status.reason) == (False, 4, "rows 3..3 are missing")


def test_a_legitimate_prune_verifies_and_is_reported(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(store_module, "PRUNE_CHECK_INTERVAL", 4)
    path = tmp_path / "lionlock.db"
    store = _store_with(path, 23, max_rows=5)
    status = store.verify()["events"]
    assert status.ok, status.reason
    head = store.head("events")
    assert status.pruned_through == head.last_seq - head.count > 0


def _forge_everything(path: Path, delete_after: int, delete_through: int) -> None:
    """What someone who understands the format can do: delete rows at both ends and rewrite
    the anchor, anchor_seq and sequence counter so every local check agrees."""
    anchor = _row_hash(path, delete_through)
    _sql(
        path,
        ("DELETE FROM events WHERE seq > ?", (delete_after,)),
        ("DELETE FROM events WHERE seq <= ?", (delete_through,)),
        ("INSERT OR REPLACE INTO log_meta (key, value) VALUES ('anchor:events', ?)", (anchor,)),
        (
            "INSERT OR REPLACE INTO log_meta (key, value) VALUES ('anchor_seq:events', ?)",
            (str(delete_through),),
        ),
        ("UPDATE sqlite_sequence SET seq = ? WHERE name = 'events'", (delete_after,)),
    )


def test_a_full_forgery_is_caught_only_by_a_recorded_head(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    store = _store_with(path, 10)
    recorded = store.head("events")
    _forge_everything(path, delete_after=7, delete_through=3)

    assert store.verify()["events"].ok  # no self-contained check can see this
    status = store.verify(expected_head={"events": recorded})["events"]
    assert not status.ok
    assert "rows were removed from the end (truncated)" in str(status.reason)


def test_a_rewritten_history_is_caught_by_a_recorded_head(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    store = _store_with(path, 5)
    recorded = store.head("events")
    columns = HASHED_COLUMNS["events"]
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE events SET decision = 'BLOCK' WHERE seq = 2")
        previous = GENESIS_HASH
        rows = conn.execute(f"SELECT seq, {','.join(columns)} FROM events ORDER BY seq")
        for row in rows.fetchall():
            new_hash = chain_hash(previous, dict(zip(columns, row[1:])))
            conn.execute(
                "UPDATE events SET prev_hash = ?, row_hash = ? WHERE seq = ?",
                (previous, new_hash, row[0]),
            )
            previous = new_hash

    assert store.verify()["events"].ok
    status = store.verify(expected_head={"events": recorded})["events"]
    assert not status.ok and "history was rewritten" in str(status.reason)


def test_a_grown_log_still_matches_its_recorded_head(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(store_module, "PRUNE_CHECK_INTERVAL", 4)
    path = tmp_path / "lionlock.db"
    store = _store_with(path, 6, max_rows=5)
    recorded = store.head("events")
    for i in range(6, 8):
        store.append_event(_event(i))
    assert store.verify(expected_head={"events": recorded})["events"].ok
    assert store.verify(expected_head={"events": tuple(recorded)})["events"].ok

    # Pruned past the recorded head: it cannot be confirmed any more, and the result says so.
    for i in range(8, 30):
        store.append_event(_event(i))
    status = store.verify(expected_head={"events": recorded})["events"]
    assert not status.ok and "can no longer be confirmed" in str(status.reason)


def test_the_head_at_the_prune_anchor_is_confirmed_by_the_anchor(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(store_module, "PRUNE_CHECK_INTERVAL", 4)
    path = tmp_path / "lionlock.db"
    store = _store_with(path, 3, max_rows=5)
    recorded = store.head("events")  # seq 3
    for i in range(3, 8):
        store.append_event(_event(i))  # the prune at seq 8 keeps 4..8: anchor at seq 3
    assert store.verify()["events"].pruned_through == 3
    assert store.verify(expected_head={"events": recorded})["events"].ok
    forged = TableHead(recorded.count, recorded.last_seq, "f" * 64)
    assert not store.verify(expected_head={"events": forged})["events"].ok


@pytest.mark.parametrize(
    "head",
    [(1, 2, "x"), (-1, 2, "a" * 64), (3, 2, "a" * 64), {"last_seq": 2}, "events:2"],
)
def test_malformed_expected_heads_are_refused(tmp_path: Path, head) -> None:
    store = _store_with(tmp_path / "lionlock.db", 2)
    with pytest.raises(ValueError):
        store.verify(expected_head={"events": head})
    with pytest.raises(ValueError):
        store.verify(expected_head={"other": (1, 1, "a" * 64)})


def _cli(capsys, tmp_path: Path, *argv: str) -> tuple[int, dict]:
    code = main(["--config", str(tmp_path / "absent.toml"), *argv])
    return code, json.loads(capsys.readouterr().out)


def test_cli_head_and_verify_expected_head(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "logs" / "lionlock.db"
    _store_with(path, 10)

    code, heads = _cli(capsys, tmp_path, "head")
    assert code == 0
    assert heads["events"] == {"count": 10, "last_seq": 10, "last_hash": _row_hash(path, 10)}
    saved = tmp_path / "heads.json"
    saved.write_text(json.dumps(heads), encoding="utf-8")

    code, verified = _cli(capsys, tmp_path, "verify", "--expected-head", str(saved))
    assert code == 0 and verified["ok"] is True
    assert verified["expected_head_checked"] == ["events", "trust_records"]
    assert verified["tables"]["events"]["head"] == heads["events"]

    _forge_everything(path, delete_after=7, delete_through=3)
    code, verified = _cli(capsys, tmp_path, "verify")
    assert code == 0  # without a recorded head the forgery is invisible
    code, verified = _cli(capsys, tmp_path, "verify", "--expected-head", str(saved))
    assert code == 1 and verified["ok"] is False
    assert "truncated" in verified["tables"]["events"]["reason"]

    saved.write_text('{"events": {"last_seq": "ten"}}', encoding="utf-8")
    code, verified = _cli(capsys, tmp_path, "verify", "--expected-head", str(saved))
    assert code == 2 and "expected head" in verified["error"]
