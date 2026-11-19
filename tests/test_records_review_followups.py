"""Review follow-ups for the records-integrity PR: each case failed before its fix."""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
from pathlib import Path

import pytest

from lionlock.telemetry.store import LogStore

from lionlock.trust_overlay.logger import (
    _RESPONSE_HASH_CONTEXT,
    build_trust_record,
    keyed_response_hash,
    pseudonymous_user_key,
)
from lionlock.trust_overlay.schemas import validate_trust_record

_EVENT = {
    "timestamp_utc": "2026-09-27T10:00:00Z",
    "request_id": "req-1",
    "decision": "ALLOW",
    "severity": "green",
    "aggregate_score": 0.1,
    "signal_scores": {"repetition_loopiness": 0.1},
}


def test_no_user_id_can_reproduce_the_response_hash_key() -> None:
    salt = "synthetic-test-salt"
    key = hmac.new(salt.encode("utf-8"), _RESPONSE_HASH_CONTEXT, hashlib.sha256).hexdigest()
    # The old context as a user_id used to yield exactly the response-hash key.
    assert pseudonymous_user_key("lionlock/trust_overlay/response_hash/v1", salt) != key
    # No user_id can: its UTF-8 encoding never contains the 0xFF byte the context starts with.
    with pytest.raises(UnicodeDecodeError):
        _RESPONSE_HASH_CONTEXT.decode("utf-8")
    assert keyed_response_hash("reply", salt) == keyed_response_hash("reply", salt)


def test_an_explicit_null_hash_scheme_is_rejected(monkeypatch) -> None:
    monkeypatch.delenv("TRUST_OVERLAY_SALT", raising=False)
    record = build_trust_record(  # type: ignore[arg-type]
        session_id="session-1",
        turn_index=1,
        model_id="model-1",
        prompt_type="qa",
        derived_signals={"overall_risk": 0.2},
        aggregate_score=0.2,
        response_text="Yes.",
        response_hash=None,
        score_history=[],
        timestamps=[],
        config={},
    )
    validate_trust_record(record)
    record["hash_scheme"] = None
    with pytest.raises(ValueError, match="hash_scheme"):
        validate_trust_record(record)


@pytest.mark.parametrize("bad", ["invalid", "\u00b2"])
def test_a_malformed_sequence_counter_fails_verification(tmp_path: Path, bad: str) -> None:
    path = tmp_path / "lionlock.db"
    store = LogStore(path)
    store.append_event(_EVENT)
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = 'events'", (bad,))
    status = LogStore(path).verify()["events"]
    assert status.ok is False
    assert "sqlite_sequence" in status.reason


def test_a_superscript_prune_anchor_fails_verification(tmp_path: Path) -> None:
    path = tmp_path / "lionlock.db"
    store = LogStore(path)
    store.append_event(_EVENT)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO log_meta(key, value) VALUES ('anchor:events', ?)", ("0" * 64,)
        )
        conn.execute(
            "INSERT OR REPLACE INTO log_meta(key, value) VALUES ('anchor_seq:events', ?)",
            ("\u00b2",),
        )
    reopened = LogStore(path)
    status = reopened.verify()["events"]
    assert status.ok is False
    assert "anchor_seq" in status.reason
    reopened.head("events")  # no crash
