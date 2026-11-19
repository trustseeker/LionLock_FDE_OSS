"""Review follow-ups for the runtime-hardening PR: each case failed before its fix."""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction

import pytest

from lionlock.core.scoring import score_payload
from lionlock.replay import policy_registry
from lionlock.signal_schemas import SignalMetadata, SignalPayload, ValidationError


def test_an_invalid_metadata_instance_is_rejected_not_crashed_on() -> None:
    payload = {"prompt": "p", "response": "r", "metadata": SignalMetadata(latency_window_stats=1)}  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        SignalPayload.model_validate(payload)
    assert score_payload(payload) is None


def test_an_invalid_payload_instance_is_rejected() -> None:
    with pytest.raises(ValidationError):
        SignalPayload.model_validate(SignalPayload(prompt="", response="r"))


def test_valid_instances_are_still_accepted() -> None:
    meta = SignalMetadata(turn_index=3, latency_window_stats=[1, 2.5])
    result = SignalPayload.model_validate(SignalPayload(prompt="p", response="r", metadata=meta))
    assert result.metadata == meta


def test_buffers_are_not_numbers_but_decimal_and_fraction_are() -> None:
    with pytest.raises(ValidationError):
        SignalPayload.model_validate(
            {"prompt": "p", "response": "r", "metadata": {"drift_slope": memoryview(b"1")}}
        )
    for value in (Decimal("0.5"), Fraction(1, 2)):
        ok = SignalPayload.model_validate(
            {"prompt": "p", "response": "r", "metadata": {"drift_slope": value}}
        )
        assert ok.metadata is not None and ok.metadata.drift_slope == 0.5


def test_a_malformed_policy_entry_is_an_error_not_an_absent_entry(tmp_path) -> None:
    registry = tmp_path / "policies.toml"
    registry.write_text('[policies]\ndev-local = "invalid"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="dev-local"):
        policy_registry.load_policy_registry(registry)


def test_a_bad_local_value_the_entry_replaces_does_not_block_replay(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "lionlock.toml").write_text("[gating.thresholds]\nred = nan\n", encoding="utf-8")
    registry = tmp_path / "policies.toml"
    registry.write_text(
        '[policies."GC-1"]\n'
        "gating.thresholds.yellow = 0.45\n"
        "gating.thresholds.orange = 0.65\n"
        "gating.thresholds.red = 0.8\n",
        encoding="utf-8",
    )
    bundle = policy_registry.resolve_policy("GC-1", registry_path=registry)
    assert bundle.config["gating"]["thresholds"]["red"] == 0.8
    # Left to the local file, the same bad value still fails.
    registry.write_text('[policies."GC-2"]\ngating.enabled = true\n', encoding="utf-8")
    with pytest.raises(ValueError):
        policy_registry.resolve_policy("GC-2", registry_path=registry)
