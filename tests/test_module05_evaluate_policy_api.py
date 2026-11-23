import math

import pytest

from lionlock.core import evaluate_policy
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores


def _bundle(
    *,
    repetition: float = 0.2,
    novelty: float = 0.3,
    coherence: float = 0.4,
    context: float = 0.2,
    hallucination: float = 0.1,
    fatigue: float = 0.2,
    congestion: float = 0.1,
) -> SignalBundle:
    scores = SignalScores(
        repetition_loopiness=repetition,
        novelty_entropy_proxy=novelty,
        coherence_structure=coherence,
        context_adherence=context,
        hallucination_risk=hallucination,
    )
    derived = DerivedSignals(
        fatigue_risk_index=fatigue,
        fatigue_risk_25t=fatigue,
        fatigue_risk_50t=fatigue,
        low_conf_halluc=0.2,
        congestion_signature=congestion,
    )
    return SignalBundle(
        signal_schema_version="SE-0.2.0",
        signal_scores=scores,
        derived_signals=derived,
        missing_inputs=(),
    )


def test_evaluate_policy_populates_required_fields() -> None:
    decision = evaluate_policy(_bundle())
    assert decision.gating_decision in {"ALLOW", "REFRESH", "BLOCK"}
    assert decision.decision in {"ALLOW", "REFRESH", "BLOCK"}
    assert isinstance(decision.signal_bundle, dict)
    assert "signal_scores" in decision.signal_bundle
    assert "derived_signals" in decision.signal_bundle
    assert decision.trigger_signal


def test_evaluate_policy_risk_score_finite_and_out_of_range_refused() -> None:
    # The largest valid derived value still blocks; a value outside [0, 1] is refused rather
    # than clamped (LL-0002 R7, after the full pre-release review).
    decision = evaluate_policy(_bundle(fatigue=1.0))
    assert math.isfinite(decision.decision_risk_score)
    assert 0.0 <= decision.decision_risk_score <= 1.0
    assert decision.gating_decision == "BLOCK"
    with pytest.raises(ValueError, match="fatigue_risk_index"):
        evaluate_policy(_bundle(fatigue=2.5))


def test_evaluate_policy_trigger_signal_deterministic() -> None:
    bundle = _bundle()
    first = evaluate_policy(bundle).trigger_signal
    second = evaluate_policy(bundle).trigger_signal
    assert first == second
    assert first
