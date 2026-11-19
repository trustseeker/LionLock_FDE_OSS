"""Replay uses the policy it was given, never the shell it runs in.

``LIONLOCK_GATING_ENABLED`` is a live-deployment switch. Replay used to apply it on top of the
recorded policy, so one ``policy_version`` and ``config_hash`` replayed as BLOCK or as ALLOW
depending on the environment. Each test runs with the variable set both ways.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lionlock.config import load_config
from lionlock.logging.event_log import config_hash_from
from lionlock.replay import policy_registry, replay_engine
from lionlock.replay.sql_reader import TelemetryEvent

RED_BUNDLE = {
    "signal_schema_version": "SE-0.4.0",
    "signal_scores": {
        "repetition_loopiness": 0.9,
        "novelty_entropy_proxy": 0.9,
        "coherence_structure": 0.9,
        "context_adherence": 0.9,
        "hallucination_risk": 0.0,
    },
    "derived_signals": {
        "fatigue_risk_index": 0.0,
        "fatigue_risk_25t": 0.0,
        "fatigue_risk_50t": 0.0,
        "low_conf_halluc": 0.0,
        "congestion_signature": 0.0,
    },
    "missing_inputs": [],
}

POLICY_TABLES = (
    'gating.hallucination_mode = "warn_only"\n'
    "gating.thresholds.yellow = 0.45\n"
    "gating.thresholds.orange = 0.65\n"
    "gating.thresholds.red = 0.80\n"
)


@pytest.fixture(autouse=True)
def _no_local_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LIONLOCK_GATING_ENABLED", raising=False)
    monkeypatch.chdir(tmp_path)


def _registry(tmp_path: Path, enabled_line: str) -> str:
    path = tmp_path / "policies.toml"
    path.write_text(f'[policies."GC-R"]\n{enabled_line}{POLICY_TABLES}', encoding="utf-8")
    return str(path)


def _event(policy: policy_registry.PolicyBundle, stored_decision: str) -> TelemetryEvent:
    return TelemetryEvent(
        event_pk=1,
        session_id="session-env",
        turn_index=1,
        timestamp="2025-01-01T00:00:00Z",
        signal_bundle=RED_BUNDLE,
        gating_decision=stored_decision,
        decision_risk_score=0.9,
        trigger_signal="context_adherence",
        trust_logic_version="TO-0.1.0",
        policy_version=policy.policy_version,
        config_hash=policy.config_hash,
        code_fingerprint="fp",
        prompt_type="qa",
        response_hash="hash-env-1",
        replay_id="replay-env",
        event_type="gating_decision",
        event_severity="red",
    )


def _replayed_decision(policy: policy_registry.PolicyBundle, stored_decision: str) -> str:
    result = replay_engine.replay([_event(policy, stored_decision)], policy)
    recomputed = result.diff_artifact["events"][0]["recomputed"]
    assert recomputed["policy_version"] == policy.policy_version
    assert recomputed["config_hash"] == policy.config_hash
    return str(recomputed["gating_decision"])


@pytest.mark.parametrize("env_value", [None, "false", "0", "off", "true", "1", "on"])
def test_policy_with_gating_enabled_replays_block_in_every_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env_value: str | None
) -> None:
    policy = policy_registry.resolve_policy(
        "GC-R", registry_path=_registry(tmp_path, "gating.enabled = true\n")
    )
    if env_value is not None:
        monkeypatch.setenv("LIONLOCK_GATING_ENABLED", env_value)
    assert _replayed_decision(policy, "BLOCK") == "BLOCK"


@pytest.mark.parametrize("env_value", [None, "false", "true", "1", "on"])
def test_policy_with_gating_disabled_replays_allow_in_every_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env_value: str | None
) -> None:
    policy = policy_registry.resolve_policy(
        "GC-R", registry_path=_registry(tmp_path, "gating.enabled = false\n")
    )
    if env_value is not None:
        monkeypatch.setenv("LIONLOCK_GATING_ENABLED", env_value)
    assert _replayed_decision(policy, "ALLOW") == "ALLOW"


def test_policy_without_explicit_enabled_resolves_identically_in_every_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A registry entry that leaves gating.enabled to the base config.

    The base config used to be loaded with the environment override applied, so the resolved
    policy, and its config_hash, changed with the shell before replay even started.
    """
    registry = _registry(tmp_path, "")
    resolved = {}
    for env_value in (None, "false", "true"):
        if env_value is None:
            monkeypatch.delenv("LIONLOCK_GATING_ENABLED", raising=False)
        else:
            monkeypatch.setenv("LIONLOCK_GATING_ENABLED", env_value)
        policy = policy_registry.resolve_policy("GC-R", registry_path=registry)
        resolved[env_value] = (policy.config["gating"]["enabled"], policy.config_hash)
        assert _replayed_decision(policy, "BLOCK") == "BLOCK"
    assert set(resolved.values()) == {(True, resolved[None][1])}
    assert resolved[None][1] == config_hash_from(
        policy_registry.resolve_policy("GC-R", registry_path=registry).config
    )


def test_live_config_loading_still_honours_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LIONLOCK_GATING_ENABLED", "false")
    assert load_config("missing.toml")["gating"]["enabled"] is False
    assert load_config("missing.toml", env_gating_override=False)["gating"]["enabled"] is True
    monkeypatch.setenv("LIONLOCK_GATING_ENABLED", "true")
    (Path.cwd() / "off.toml").write_text("[gating]\nenabled = false\n", encoding="utf-8")
    assert load_config("off.toml")["gating"]["enabled"] is True
    assert load_config("off.toml", env_gating_override=False)["gating"]["enabled"] is False


def test_replay_rejects_a_policy_that_is_not_explicit_about_enabled(tmp_path: Path) -> None:
    config = {"gating": {"enabled": "false"}, "signals": {}}
    policy = policy_registry.PolicyBundle("GC-S", config, config_hash_from(config))
    with pytest.raises(ValueError, match="gating.enabled = 'false': must be a boolean"):
        replay_engine.replay([], policy)
