"""Unit tests for the LL-0002 decision rule (D1): severity, attribution and policy adjustments.

The harness acceptance tests in harness/specs/LL-0002 check the rule against a golden product. These
tests pin the same behaviour on small hand-built bundles, so a regression names itself without the
harness, including in the sdist's test suite.
"""

from __future__ import annotations

import math
from pathlib import Path

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


def test_weights_whose_sum_overflows_are_refused_not_turned_into_allow() -> None:
    # External review: each weight is finite, their sum is inf, and finite / inf = 0.0 gave ALLOW.
    bundle = _bundle(repetition=0.85, context=0.85, novelty=0.0, coherence=0.0, hallucination=0.0)
    same_ratio = {"repetition_loopiness": 1.0, "context_adherence": 1.0}
    assert evaluate_policy(bundle, weights=same_ratio).gating_decision == "BLOCK"
    huge = {"repetition_loopiness": 1e308, "context_adherence": 1e308}
    with pytest.raises(ValueError, match="between"):
        evaluate_policy(bundle, weights=huge)
    # Only ratios matter: the same ratio inside the allowed range still blocks.
    assert (
        evaluate_policy(
            bundle, weights={"repetition_loopiness": 1e6, "context_adherence": 1e6}
        ).gating_decision
        == "BLOCK"
    )


def test_the_smallest_positive_weight_is_refused_not_underflowed_to_allow() -> None:
    # Full review F1: on shipped fixture 03, a sole weight of 5e-324 turned BLOCK/REFRESH into
    # ALLOW, because every product underflowed to 0.
    import json
    from pathlib import Path

    from lionlock.core.scoring import score_payload

    corpus = Path(__file__).resolve().parents[1] / "harness/specs/LL-0001/corpus.json"
    entry = next(e for e in json.loads(corpus.read_text())["payloads"] if e["id"].startswith("03"))
    bundle = score_payload({"prompt": entry["prompt"], "response": entry["response"]})
    assert bundle is not None
    ok = evaluate_policy(
        bundle, weights={"context_adherence": 1.0}, enabled_signals=["context_adherence"]
    )
    assert ok.gating_decision != "ALLOW"
    with pytest.raises(ValueError, match="between"):
        evaluate_policy(
            bundle, weights={"context_adherence": 5e-324}, enabled_signals=["context_adherence"]
        )


def test_aggregate_score_refuses_an_overflowing_weight_total() -> None:
    from lionlock.core.scoring import aggregate_score

    bundle = _bundle(repetition=0.85, context=0.85)
    with pytest.raises(ValueError, match="between"):
        aggregate_score(bundle, weights={"repetition_loopiness": 1e308, "context_adherence": 1e308})
    with pytest.raises(ValueError, match="between"):
        aggregate_score(bundle, weights={"repetition_loopiness": 5e-324})


def test_config_refuses_weights_whose_sum_overflows(tmp_path) -> None:
    from lionlock.config import load_config

    path = tmp_path / "lionlock.toml"
    path.write_text(
        "[signals.weights]\nrepetition_loopiness = 1e308\ncontext_adherence = 1e308\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="between"):
        load_config(str(path))


def test_latency_mean_is_the_same_on_every_python_version() -> None:
    # Full review F3: built-in sum() rounds differently from Python 3.12 on. [1e16, 1.0, 1.0]
    # sums to 1e16 on 3.11 and to 1e16 + 2 on 3.12; math.fsum gives 1e16 + 2 everywhere.
    import math

    from lionlock.core import scoring

    values = [1e16, 1.0, 1.0]
    assert math.fsum(values) == 1e16 + 2
    source = Path(scoring.__file__).read_text(encoding="utf-8")
    assert "sum(latencies)" not in source.replace("fsum(latencies)", "")
