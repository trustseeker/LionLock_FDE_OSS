"""TrustVaultLogger format 2: strict canonical entries, refused payloads, legacy logs unchanged."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

import pytest

from lionlock import TrustVaultLogger
from lionlock.utils.chain_verifier import (
    GENESIS_HASH,
    TamperDetectedError,
    verify_chain,
    verify_chain_file,
)
from lionlock.utils.jcs import canonical_text

# --- the legacy rule, frozen here as it was before format 2 -----------------------------------


def _legacy_hash(entry: dict[str, Any]) -> str:
    body = {key: value for key, value in entry.items() if key != "sha256"}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_legacy_log(path: Path, payloads: list[Any]) -> None:
    """Exactly what TrustVaultLogger.record wrote before format 2: the hash over the in-memory
    entry, the line from json.dumps(entry)."""
    previous = GENESIS_HASH
    lines = []
    for index, payload in enumerate(payloads):
        entry = {
            "ts": f"2026-01-01T00:00:{index:02d}Z",
            "event": "detect",
            "payload": payload,
            "prev_hash": previous,
        }
        entry["sha256"] = _legacy_hash(entry)
        previous = entry["sha256"]
        lines.append(json.dumps(entry))
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def _old_verify_chain(entries: list[Any]) -> None:
    """``verify_chain`` as it was before format 2 (no recorded head)."""
    previous_hash = GENESIS_HASH
    for count, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise TamperDetectedError(f"Entry #{count} is not an object")
        if entry.get("prev_hash") != previous_hash:
            raise TamperDetectedError(f"Entry #{count} prev_hash mismatch")
        current_hash = str(entry.get("sha256") or "")
        if current_hash != _legacy_hash(entry):
            raise TamperDetectedError(f"Entry #{count} hash mismatch")
        previous_hash = current_hash


def _outcome(check, entries: list[Any]) -> str:
    try:
        check(entries)
    except TamperDetectedError as exc:
        return str(exc)
    return "ok"


def _entries(path: Path) -> list[Any]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# --- new entries ------------------------------------------------------------------------------


def test_new_entries_are_marked_format_2_and_written_in_canonical_form(tmp_path: Path) -> None:
    path = tmp_path / "trustvault.log"
    logger = TrustVaultLogger(path)
    payload = {"turn_scores": {"10": 0.7, "9": 0.4}, "score": 1.0, "tiny": 1e-7, "name": "café"}
    logger.record(event="detect", payload=payload)
    logger.record(event="detect", payload={"n": 2})

    raw_lines = path.read_text(encoding="utf-8").splitlines()
    for raw in raw_lines:
        entry = json.loads(raw)
        assert entry["format"] == 2
        assert set(entry) == {"ts", "event", "format", "payload", "prev_hash", "sha256"}
        assert raw == canonical_text(entry)  # the line is exactly the canonical encoding
        body = {key: value for key, value in entry.items() if key != "sha256"}
        assert entry["sha256"] == hashlib.sha256(canonical_text(body).encode()).hexdigest()
    assert '"payload":{"name":"café","score":1,"tiny":1e-7,' in raw_lines[0]
    assert json.loads(raw_lines[0])["payload"] == payload  # same values, read back
    logger.verify_chain()


def test_the_reviewers_integer_key_payload_is_refused_and_the_file_is_unchanged(
    tmp_path: Path,
) -> None:
    path = tmp_path / "trustvault.log"
    logger = TrustVaultLogger(path)
    logger.record(event="detect", payload={"n": 1})
    before = path.read_bytes()

    with pytest.raises(ValueError, match=r"payload\.turn_scores: key 9 \(int\) is not text"):
        logger.record(event="detect", payload={"turn_scores": {9: 0.4, 10: 0.7}})
    assert path.read_bytes() == before
    logger.verify_chain()


@pytest.mark.parametrize(
    "payload, where",
    [
        ({"x": math.nan}, "payload.x"),
        ({"x": [1.0, math.inf]}, r"payload.x\[1\]"),
        ({"x": -math.inf}, "payload.x"),
        ({"x": 2**53}, "payload.x"),
        ({"x": {None: 1}}, "payload.x"),
        ({"x": {(1, 2): 1}}, "payload.x"),
        ({"x": {True: 1}}, "payload.x"),
        ({"x": {1.5: 1}}, "payload.x"),
        ({"x": {"ok": {"a b": object()}}}, r'payload.x.ok\["a b"\]'),
        ({"x": {1, 2}}, "payload.x"),
        ({"x": b"bytes"}, "payload.x"),
        ({"x": "\ud800"}, "payload.x"),
        ({"\udc00": 1}, "payload"),
    ],
)
def test_values_without_a_canonical_form_are_refused_before_anything_is_written(
    tmp_path: Path, payload: Any, where: str
) -> None:
    existing = tmp_path / "existing.log"
    logger = TrustVaultLogger(existing)
    logger.record(event="detect", payload={"n": 1})
    before = existing.read_bytes()
    with pytest.raises(ValueError, match=f"^{where}: "):
        logger.record(event="detect", payload=payload)
    assert existing.read_bytes() == before

    fresh = tmp_path / "new-dir" / "fresh.log"
    with pytest.raises(ValueError):
        TrustVaultLogger(fresh).record(event="detect", payload=payload)
    assert not fresh.parent.exists()


def test_unserializable_payloads_still_raise_type_error_for_old_callers(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        TrustVaultLogger(tmp_path / "t.log").record(event="detect", payload={"x": object()})


def test_editing_a_format_2_entry_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "trustvault.log"
    logger = TrustVaultLogger(path)
    for index in range(3):
        logger.record(event="detect", payload={"n": index})
    entries = _entries(path)
    entries[1]["payload"] = {"n": "forged"}
    with pytest.raises(TamperDetectedError, match="Entry #2 hash mismatch"):
        verify_chain(entries)


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda e: e.update(extra=1), "exactly the format 2 fields"),
        (lambda e: e.update(format=3), "unsupported format 3"),
        (lambda e: e.update(format=True), "unsupported format True"),
        (lambda e: e.pop("ts"), "exactly the format 2 fields"),
        (lambda e: e["payload"].update(x=math.nan), r"not in canonical form \(payload.x"),
    ],
)
def test_format_2_entries_are_checked_strictly(tmp_path: Path, change, message: str) -> None:
    path = tmp_path / "trustvault.log"
    TrustVaultLogger(path).record(event="detect", payload={"n": 1})
    entries = _entries(path)
    change(entries[0])
    with pytest.raises(TamperDetectedError, match=message):
        verify_chain(entries)


def test_values_are_hashed_not_bytes_so_any_json_parser_agrees(tmp_path: Path) -> None:
    path = tmp_path / "trustvault.log"
    TrustVaultLogger(path).record(event="detect", payload={"x": 1e20, "y": 3.0})
    (entry,) = _entries(path)
    assert entry["payload"]["x"] == 10**20 and isinstance(entry["payload"]["x"], int)
    # Re-encoded by another serializer, the same values still verify.
    path.write_text(json.dumps(entry, indent=1).replace("\n", "") + "\n", encoding="utf-8")
    verify_chain_file(path)
    entry["format"] = 2.0  # a JSON number equal to 2, as another language would read it
    verify_chain([entry])


# --- legacy logs ------------------------------------------------------------------------------

LEGACY_CASES: dict[str, list[Any]] = {
    "honest": [{"signal": "noop"}, {"score": 1.0}, {"tiny": 1e-7}, {"name": "café"}],
    "integer keys (false mismatch)": [
        {"n": 0},
        {"turn_scores": {9: 0.4, 10: 0.7}},
        {"n": 2},
        {"n": 3},
    ],
    "NaN and Infinity": [{"x": math.nan}, {"y": math.inf}, {"z": -math.inf}],
    "single integer key": [{"by_turn": {3: 0.1}}, {"n": 1}],
}


def _variants(entries: list[Any]) -> dict[str, list[Any]]:
    edited = json.loads(json.dumps(entries))
    edited[-1]["payload"] = {"forged": True}
    later_edit = json.loads(json.dumps(entries))
    later_edit[-1]["event"] = "forged"
    return {
        "as written": entries,
        "last entry edited": edited,
        "event edited": later_edit,
        "first removed": entries[1:],
        "middle removed": entries[:1] + entries[2:],
        "reordered": [entries[1], entries[0], *entries[2:]],
        "not an object": [*entries[:-1], ["not", "an", "object"]],
    }


@pytest.mark.parametrize("case", sorted(LEGACY_CASES))
def test_legacy_logs_verify_exactly_as_before(tmp_path: Path, case: str) -> None:
    path = tmp_path / "legacy.log"
    _write_legacy_log(path, LEGACY_CASES[case])
    for name, entries in _variants(_entries(path)).items():
        assert _outcome(verify_chain, entries) == _outcome(_old_verify_chain, entries), name


def test_legacy_results_are_the_known_ones(tmp_path: Path) -> None:
    path = tmp_path / "legacy.log"
    _write_legacy_log(path, LEGACY_CASES["honest"])
    verify_chain_file(path)
    _write_legacy_log(path, LEGACY_CASES["NaN and Infinity"])
    verify_chain_file(path)
    # The integer-key problem of the legacy rule stays exactly as it was: never rewritten.
    _write_legacy_log(path, LEGACY_CASES["integer keys (false mismatch)"])
    before = path.read_bytes()
    with pytest.raises(TamperDetectedError, match="^Entry #2 hash mismatch$"):
        verify_chain_file(path)
    assert path.read_bytes() == before


def test_a_legacy_log_switches_to_format_2_by_appending(tmp_path: Path) -> None:
    path = tmp_path / "trustvault.log"
    _write_legacy_log(path, LEGACY_CASES["honest"])
    legacy_bytes = path.read_bytes()
    logger = TrustVaultLogger(path)
    logger.record(event="detect", payload={"after": "upgrade"})
    logger.record(event="detect", payload={"after": "upgrade", "n": 2})

    assert path.read_bytes().startswith(legacy_bytes)  # old lines are never rewritten
    entries = _entries(path)
    assert ["format" in entry for entry in entries] == [False] * 4 + [True] * 2
    assert entries[4]["prev_hash"] == entries[3]["sha256"]
    count, head = logger.head()
    logger.verify_chain(expected_head=head, expected_count=count)

    tampered_old = json.loads(json.dumps(entries))
    tampered_old[1]["payload"] = {"score": 2.0}
    with pytest.raises(TamperDetectedError, match="Entry #2 hash mismatch"):
        verify_chain(tampered_old)
    tampered_new = json.loads(json.dumps(entries))
    tampered_new[5]["payload"]["n"] = 3
    with pytest.raises(TamperDetectedError, match="Entry #6 hash mismatch"):
        verify_chain(tampered_new)
