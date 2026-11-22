import math

import pytest

from lionlock.core import evaluate_policy
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores


def _bundle(
    *,
    repetition: float = 0.1,
    novelty: float = 0.1,
    coherence: float = 0.1,
    context: float = 0.1,
    hallucination: float = 0.1,
    fatigue: float = 0.1,
    low_conf_halluc: float = 0.1,
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
        low_conf_halluc=low_conf_halluc,
        congestion_signature=congestion,
    )
    return SignalBundle(
        signal_schema_version="SE-0.2.0",
        signal_scores=scores,
        derived_signals=derived,
        missing_inputs=(),
    )


def test_derived_channel_escalates_decision() -> None:
    bundle = _bundle(
        repetition=0.05,
        novelty=0.05,
        coherence=0.05,
        context=0.05,
        hallucination=0.05,
        fatigue=0.9,
        low_conf_halluc=0.1,
        congestion=0.1,
    )
    decision = evaluate_policy(bundle)
    assert decision.decision_risk_score == 0.9
    assert decision.gating_decision == "BLOCK"
    assert decision.trigger_signal == "fatigue_risk_index"


def test_tie_break_deterministic_for_derived_signals() -> None:
    bundle = _bundle(
        fatigue=0.6,
        low_conf_halluc=0.6,
        congestion=0.6,
        repetition=0.1,
        novelty=0.1,
        coherence=0.1,
        context=0.1,
        hallucination=0.1,
    )
    decision = evaluate_policy(bundle)
    assert decision.trigger_signal == "fatigue_risk_index"


def test_tie_break_deterministic_for_raw_signals() -> None:
    bundle = _bundle(
        repetition=0.4,
        novelty=0.4,
        coherence=0.4,
        context=0.4,
        hallucination=0.4,
        fatigue=0.1,
        low_conf_halluc=0.1,
        congestion=0.1,
    )
    # LL-0002 (D1): the raw-channel trigger is the signal with the largest weighted contribution,
    # so equal scores go to the heaviest default weight (repetition, 0.30). hallucination_risk has
    # weight 0 by default and can no longer be named for a decision it did not drive.
    decision = evaluate_policy(bundle)
    assert decision.trigger_signal == "repetition_loopiness"


def test_tie_break_on_equal_contributions_follows_trigger_order() -> None:
    bundle = _bundle(
        repetition=0.4,
        novelty=0.4,
        coherence=0.4,
        context=0.4,
        hallucination=0.4,
        fatigue=0.1,
        low_conf_halluc=0.1,
        congestion=0.1,
    )
    equal = dict.fromkeys(
        (
            "repetition_loopiness",
            "novelty_entropy_proxy",
            "coherence_structure",
            "context_adherence",
            "hallucination_risk",
        ),
        0.2,
    )
    # Every contribution is 0.08; the tie goes to the first raw signal in TRIGGER_SIGNAL_ORDER.
    # hallucination_risk is enabled with a positive weight here, so it is eligible and wins.
    decision = evaluate_policy(bundle, weights=equal)
    assert decision.trigger_signal == "hallucination_risk"
    # With its weight at 0 it is not eligible, and the tie goes to the next signal in the order.
    decision = evaluate_policy(bundle, weights={**equal, "hallucination_risk": 0.0})
    assert decision.trigger_signal == "context_adherence"


def test_non_finite_evidence_is_refused_naming_the_field() -> None:
    # Review A1: a nan or infinite score used to be read as 0.0, which could lower the risk and
    # turn broken evidence into ALLOW. It is now refused, and the error names the field.
    cases = {
        "repetition_loopiness": _bundle(repetition=math.nan),
        "novelty_entropy_proxy": _bundle(novelty=math.inf),
        "fatigue_risk_index": _bundle(fatigue=-math.inf),
        "low_conf_halluc": _bundle(low_conf_halluc=math.nan),
    }
    for field, bundle in cases.items():
        with pytest.raises(ValueError, match=field):
            evaluate_policy(bundle)


def test_finite_out_of_range_inputs_are_refused() -> None:
    # Scores and derived values must lie in [0, 1] (LL-0002 R7); finite values outside it used to
    # be clamped, and the full pre-release review found ways that let extreme values weaken a
    # decision.
    bundle = _bundle(repetition=1.7, novelty=0.1, coherence=0.1, context=0.2, hallucination=0.1)
    with pytest.raises(ValueError, match="repetition_loopiness"):
        evaluate_policy(bundle)
    with pytest.raises(ValueError, match="fatigue_risk_index"):
        evaluate_policy(_bundle(fatigue=2.0))
