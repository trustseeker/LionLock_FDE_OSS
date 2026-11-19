"""Replay and the simulator hand the gate the policy's own weights, and never soften its refusals.

* Since LL-0002 (D1) the raw-channel trigger is the enabled signal with the largest *weighted*
  contribution. Replay and the simulator computed the aggregate with the policy's weights but
  called the gate without them, so attribution used the default weights.
* The gate raises ValueError for an invalid policy or non-finite evidence. Neither caller may turn
  that into a decision; replay also refuses to pre-coerce a non-finite stored score to 0.0, which
  would have hidden it from the gate.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from lionlock.core import gating
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores
from lionlock.logging.event_log import config_hash_from
from lionlock.replay import policy_registry, replay_engine
from lionlock.replay.sql_reader import TelemetryEvent
from lionlock.sim import cli as sim_cli
from lionlock.sim import runner

# Default weights put repetition first (0.30 * 0.9 > 0.20 * 0.9); this policy puts context first.
SCORES = {
    "repetition_loopiness": 0.9,
    "novelty_entropy_proxy": 0.1,
    "coherence_structure": 0.1,
    "context_adherence": 0.9,
    "hallucination_risk": 0.0,
}
DERIVED = {
    "fatigue_risk_index": 0.0,
    "fatigue_risk_25t": 0.0,
    "fatigue_risk_50t": 0.0,
    "low_conf_halluc": 0.0,
    "congestion_signature": 0.0,
}
CONTEXT_FIRST = {
    "gating": {
        "enabled": True,
        "hallucination_mode": "warn_only",
        "thresholds": {"yellow": 0.45, "orange": 0.65, "red": 0.80},
    },
    "signals": {
        "enabled": list(SCORES),
        "weights": {
            "repetition_loopiness": 0.05,
            "novelty_entropy_proxy": 0.05,
            "coherence_structure": 0.05,
            "context_adherence": 0.85,
            "hallucination_risk": 0.0,
        },
    },
}


def _policy(config: dict[str, Any]) -> policy_registry.PolicyBundle:
    return policy_registry.PolicyBundle("GC-W", config, config_hash_from(config))


def _event(bundle: Any, policy: policy_registry.PolicyBundle) -> TelemetryEvent:
    return TelemetryEvent(
        event_pk=1,
        session_id="session-w",
        turn_index=1,
        timestamp="2025-01-01T00:00:00Z",
        signal_bundle=bundle,
        gating_decision="BLOCK",
        decision_risk_score=0.82,
        trigger_signal="context_adherence",
        trust_logic_version="TO-0.1.0",
        policy_version=policy.policy_version,
        config_hash=policy.config_hash,
        code_fingerprint="fp",
        prompt_type="qa",
        response_hash="hash-w-1",
        replay_id="replay-w",
        event_type="gating_decision",
        event_severity="red",
    )


def _bundle_dict() -> dict[str, Any]:
    return {
        "signal_schema_version": "SE-0.4.0",
        "signal_scores": dict(SCORES),
        "derived_signals": dict(DERIVED),
        "missing_inputs": [],
    }


def test_replay_names_the_trigger_by_the_policys_weights() -> None:
    policy = _policy(CONTEXT_FIRST)
    result = replay_engine.replay([_event(_bundle_dict(), policy)], policy)
    recomputed = result.diff_artifact["events"][0]["recomputed"]
    assert recomputed["gating_decision"] == "BLOCK"
    assert recomputed["trigger_signal"] == "context_adherence"
    assert result.report["summary"]["trigger_mismatch"] == 0
    # The same bundle under default weights is attributed to repetition, so the weights mattered.
    default = gating.evaluate_policy(replay_engine._parse_signal_bundle(_bundle_dict()))
    assert default.trigger_signal == "repetition_loopiness"


def test_simulator_names_the_trigger_by_the_policys_weights() -> None:
    bundle = SignalBundle(
        "SE-0.4.0", SignalScores(**SCORES), DerivedSignals(**DERIVED), missing_inputs=()
    )
    decision = runner._evaluate_policy(bundle, CONTEXT_FIRST)
    assert decision.gating_decision == "BLOCK"
    assert decision.trigger_signal == "context_adherence"


@pytest.mark.parametrize(
    "bad_score",
    [float("nan"), float("inf"), "nan", "not a number", 10**400],
    ids=["nan", "inf", "nan-string", "text", "int-beyond-float-range"],
)
def test_replay_reports_a_non_finite_stored_score_instead_of_reading_it_as_zero(
    bad_score: object,
) -> None:
    policy = _policy(CONTEXT_FIRST)
    bundle = _bundle_dict()
    bundle["signal_scores"]["context_adherence"] = bad_score
    stored = json.dumps(bundle) if bad_score != 10**400 else bundle
    result = replay_engine.replay([_event(stored, policy)], policy)
    summary = result.report["summary"]
    assert summary["bundle_errors"] == 1
    assert summary["replayed_count"] == 0
    entry = result.diff_artifact["events"][0]
    assert entry["error"] == "invalid_signal_bundle"
    assert entry["recomputed"] is None


def test_an_absent_or_null_stored_score_still_reads_as_zero() -> None:
    policy = _policy(CONTEXT_FIRST)
    bundle = _bundle_dict()
    del bundle["derived_signals"]["fatigue_risk_25t"]
    bundle["derived_signals"]["congestion_signature"] = None
    result = replay_engine.replay([_event(bundle, policy)], policy)
    assert result.report["summary"]["bundle_errors"] == 0
    assert result.report["summary"]["replayed_count"] == 1


def _refuse(**_: Any) -> Any:
    raise ValueError("gate refused: synthetic invalid input")


def test_replay_propagates_the_gates_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _policy(CONTEXT_FIRST)
    monkeypatch.setattr(replay_engine.gating_module, "_evaluate_policy_with_scores", _refuse)
    with pytest.raises(ValueError, match="gate refused"):
        replay_engine.replay([_event(_bundle_dict(), policy)], policy)


def test_simulator_propagates_the_gates_value_error(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runner.gating_module, "_evaluate_policy_with_scores", _refuse)
    with pytest.raises(ValueError, match="gate refused"):
        runner.run_simulation(turns=3, output_dir=str(tmp_path / "out"), db_url="sqlite:///s.db")
    code = sim_cli.run(["run", "--turns", "3", "--out-dir", "cli-out", "--db", "sqlite:///c.db"])
    assert code == 1
    assert "sim error: gate refused" in capsys.readouterr().err
    assert not (tmp_path / "cli-out" / "report.json").exists()
