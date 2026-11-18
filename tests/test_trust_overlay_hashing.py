"""Trust Overlay records: no guessable digests, a hashing-scheme marker, no free-text notes."""

from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path

import pytest

from lionlock.trust_overlay.logger import (
    append_trust_record,
    build_deployment_context_snapshot,
    build_trust_record,
    keyed_response_hash,
)
from lionlock.trust_overlay.schemas import sanitize_record, validate_trust_record

REPLY = "Yes."


def _record(config: dict | None = None, **overrides) -> dict:
    arguments = dict(
        session_id="session-1",
        turn_index=1,
        model_id="model-1",
        prompt_type="qa",
        derived_signals={"overall_risk": 0.2, "notes": "free text the caller typed"},
        aggregate_score=0.2,
        response_text=REPLY,
        response_hash=None,
        score_history=[],
        timestamps=[],
        config=config or {},
    )
    arguments.update(overrides)
    return build_trust_record(**arguments)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _no_salt_from_environment(monkeypatch) -> None:
    monkeypatch.delenv("TRUST_OVERLAY_SALT", raising=False)


def test_no_unkeyed_digest_of_the_reply_without_a_salt() -> None:
    record = _record()
    assert record["response_hash"] is None
    assert record["hash_scheme"] == "none"
    assert hashlib.sha256(REPLY.encode()).hexdigest() not in json.dumps(record)


def test_the_reply_is_hashed_under_a_key_when_a_salt_is_configured() -> None:
    config = {"trust_overlay": {"salt": "synthetic-test-salt"}}
    record = _record(config)
    assert record["hash_scheme"] == "keyed-v1"
    assert record["response_hash"] == keyed_response_hash(REPLY, "synthetic-test-salt")
    assert record["response_hash"] != hashlib.sha256(REPLY.encode()).hexdigest()
    assert record["response_hash"] != keyed_response_hash(REPLY, "another-salt")
    validate_trust_record(record)


def test_a_caller_supplied_hash_is_kept_and_marked() -> None:
    record = _record(response_hash="caller-correlation-id")
    assert record["response_hash"] == "caller-correlation-id"
    assert record["hash_scheme"] == "caller"


def test_no_hostname_or_container_digests() -> None:
    snapshot = build_deployment_context_snapshot(
        trust_logic_version="TO-0.1.0", fingerprint="f" * 64, runtime_mode="oss", config={}
    )
    assert "host_id_hash" not in snapshot and "container_id_hash" not in snapshot
    host_digest = hashlib.sha256(socket.gethostname().encode()).hexdigest()
    assert host_digest not in json.dumps(_record())

    supplied = dict(snapshot, host_id_hash="a" * 64, container_id_hash="b" * 64)
    record = _record(deployment_context_snapshot=supplied)
    assert set(record["deployment_context_snapshot"]) == set(snapshot)


def test_free_text_notes_are_stripped(tmp_path: Path) -> None:
    record = _record()
    assert "notes" not in record["signal_summary"]

    handmade = dict(record, signal_summary={"overall_risk": 0.2, "notes": "typed by a caller"})
    path = append_trust_record(handmade, base_dir=tmp_path)
    assert "typed by a caller" not in path.read_text(encoding="utf-8")
    assert handmade["signal_summary"]["notes"] == "typed by a caller"  # input left unchanged


def test_records_without_the_marker_still_validate() -> None:
    legacy = sanitize_record(_record())
    legacy.pop("hash_scheme")
    legacy["response_hash"] = hashlib.sha256(REPLY.encode()).hexdigest()
    validate_trust_record(legacy)


@pytest.mark.parametrize(
    "scheme, response_hash", [("sha256", "x"), ("none", "abc"), ("keyed-v1", None)]
)
def test_an_inconsistent_marker_is_refused(scheme: str, response_hash) -> None:
    record = dict(_record(), hash_scheme=scheme, response_hash=response_hash)
    with pytest.raises(ValueError):
        validate_trust_record(record)
