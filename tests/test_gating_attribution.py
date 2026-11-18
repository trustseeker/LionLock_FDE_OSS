"""Unit tests for the LL-0002 decision rule (D1): severity, attribution and policy adjustments.

The harness acceptance tests in harness/specs/LL-0002 check the rule against a golden product. These
tests pin the same behaviour on small hand-built bundles, so a regression names itself without the
harness, including in the sdist's test suite.
"""

from __future__ import annotations

import math

import pytest

from lionlock.core import evaluate_policy
from lionlock.core.gating import decide_gate
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores

SIGNALS = tuple(SignalScores.__dataclass_fields__)
DEFAULT_ACTION = {"red": "BLOCK", "orange": "REFRESH", "yellow": "REFRESH", "green": "ALLOW"}


def _bundle(
    *,
    repetition: float = 0.1,
    novelty: float = 0.1,
    coherence: float = 0.1,
    context: float = 0.1,
    hallucination: float = 0.1,
    low_conf_halluc: float = 0.0,
) -> SignalBundle:
    return SignalBundle(
        signal_schema_version="SE-0.4.0",
        signal_scores=SignalScores(
            repetition_loopiness=repetition,
            novelty_entropy_proxy=novelty,
            coherence_structure=coherence,
            context_adherence=context,
            hallucination_risk=hallucination,
        ),
        derived_signals=DerivedSignals(
            fatigue_risk_index=0.0,
            fatigue_risk_25t=0.0,
            fatigue_risk_50t=0.0,
            low_conf_halluc=low_conf_halluc,
            congestion_signature=0.0,
        ),
        missing_inputs=(),
    )


def _loop() -> SignalBundle:
    """Every raw signal at its maximum: red on non-hallucination evidence alone."""
    return _bundle(repetition=1.0, novelty=1.0, coherence=1.0, context=1.0, hallucination=1.0)


def _hallucination_only() -> SignalBundle:
    """Red only because of hallucination evidence: low_conf_halluc 1.0, everything else low."""
    return _bundle(hallucination=1.0, low_conf_halluc=1.0)


def test_red_on_other_evidence_is_blocked_and_names_its_driver() -> None:
    decision = evaluate_policy(_loop())
    assert (decision.severity, decision.gating_decision) == ("red", "BLOCK")
    assert decision.trigger_signal == "repetition_loopiness"
    assert decision.reason_code == "repetition_loop"
    assert decision.policy_adjustment is None


def test_warn_only_softens_a_hallucination_only_red_without_rewriting_severity() -> None:
    decision = evaluate_policy(_hallucination_only())
    assert decision.severity == "red"
    assert decision.gating_decision == "REFRESH"
    assert decision.policy_adjustment == "warn_only_hallucination"
    assert decision.trigger_signal == "low_conf_halluc"
    assert decision.reason_code == "hallucination_risk"


def test_block_mode_does_not_soften() -> None:
    decision = evaluate_policy(_hallucination_only(), hallucination_mode="block")
    assert (decision.severity, decision.gating_decision) == ("red", "BLOCK")
    assert decision.policy_adjustment is None


def test_hard_gate_list_softens_an_unlisted_reason_and_says_so() -> None:
    decision = evaluate_policy(_loop(), hard_gate_reasons_enabled=["hallucination_risk"])
    assert decision.severity == "red"
    assert decision.gating_decision == "REFRESH"
    assert decision.policy_adjustment == "hard_gate_reason_disabled"
    listed = evaluate_policy(_loop(), hard_gate_reasons_enabled=["repetition_loop"])
    assert (listed.gating_decision, listed.policy_adjustment) == ("BLOCK", None)


def test_disabled_gating_allows_but_records_what_it_overrode() -> None:
    decision = evaluate_policy(_loop(), gating_enabled=False)
    assert (decision.severity, decision.gating_decision) == ("red", "ALLOW")
    assert decision.policy_adjustment == "gating_disabled"
    green = evaluate_policy(_bundle(), gating_enabled=False)
    assert (green.severity, green.gating_decision, green.policy_adjustment) == (
        "green",
        "ALLOW",
        None,
    )


def test_zero_weight_signal_is_never_the_raw_trigger() -> None:
    # hallucination_risk is the largest raw score but has weight 0 by default.
    decision = evaluate_policy(_bundle(hallucination=0.9, context=0.6, repetition=0.6))
    assert decision.trigger_signal != "hallucination_risk"
    assert decision.trigger_signal == "repetition_loopiness"


def test_disabled_signal_is_never_the_raw_trigger() -> None:
    decision = evaluate_policy(
        _bundle(repetition=1.0, context=0.5), enabled_signals=["context_adherence"]
    )
    assert decision.trigger_signal == "context_adherence"


@pytest.mark.parametrize(
    "bundle",
    [_loop(), _hallucination_only(), _bundle(), _bundle(context=0.7, coherence=0.7)],
)
@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"hallucination_mode": "block"},
        {"gating_enabled": False},
        {"hard_gate_reasons_enabled": ["context_drift"]},
    ],
)
def test_adjustment_is_none_exactly_when_the_action_is_the_default(
    bundle: SignalBundle, kwargs: dict
) -> None:
    decision = evaluate_policy(bundle, **kwargs)
    is_default = decision.gating_decision == DEFAULT_ACTION[decision.severity]
    assert (decision.policy_adjustment is None) == is_default


@pytest.mark.parametrize(
    ("kwargs", "named"),
    [
        ({"hallucination_mode": "warn-only"}, "hallucination_mode"),
        ({"thresholds": {"yellow": 0.45, "orange": 0.65}}, "red"),
        ({"thresholds": {"yellow": 0.45, "orange": 0.65, "red": math.nan}}, "red"),
        ({"thresholds": {"yellow": 0.7, "orange": 0.65, "red": 0.8}}, "yellow < orange"),
        ({"weights": {"repetition_loopiness": math.nan}}, "repetition_loopiness"),
        ({"weights": {"context_adherence": -0.1}}, "context_adherence"),
        ({"weights": dict.fromkeys(SIGNALS, 0.0)}, "positive weight"),
        ({"enabled_signals": ["no_such_signal"]}, "no_such_signal"),
    ],
)
def test_invalid_policy_is_refused_naming_the_setting(kwargs: dict, named: str) -> None:
    with pytest.raises(ValueError, match=named):
        evaluate_policy(_loop(), **kwargs)


@pytest.mark.parametrize("aggregate", [math.nan, math.inf, -math.inf])
def test_decide_gate_refuses_a_non_finite_aggregate(aggregate: float) -> None:
    with pytest.raises(ValueError, match="aggregate_score"):
        decide_gate(aggregate, SignalScores(**dict.fromkeys(SIGNALS, 0.0)))
