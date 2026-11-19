"""A non-finite input is reported as a fault, never coerced into a trust verdict.

``max(0.0, min(1.0, nan))`` is 1.0. Before these checks a NaN risk therefore became trust 1.0 and
the label TRUSTED, a NaN in the score history became the confidence band [1.0, 1.0], and an
infinite trust score was labelled TRUSTED. The engine now raises ``ValueError`` naming the input.
"""

from __future__ import annotations

import math

import pytest

from lionlock.trust_overlay.engine import (
    assign_badge,
    compute_confidence_band,
    compute_trust_score,
    compute_volatility,
    detect_drift,
    map_label,
    trigger_flags,
)
from lionlock.trust_overlay.logger import build_trust_record

NAN = float("nan")
INF = float("inf")
DRIFT = {
    "recent_n": 20,
    "baseline_n": 80,
    "drift_detected": False,
    "threshold": -0.1,
    "delta": -0.08,
}


@pytest.mark.parametrize(
    "risk",
    [NAN, -INF, INF, "nan", "-inf", pytest.param(10**400, id="int-beyond-float-range")],
)
def test_non_finite_risk_is_an_error_not_trusted(risk: object) -> None:
    with pytest.raises(ValueError, match="signal_summary overall_risk is not"):
        compute_trust_score({"overall_risk": risk})


def test_non_finite_fatigue_score_names_its_key() -> None:
    with pytest.raises(ValueError, match="signal_summary fatigue_score is not finite: nan"):
        compute_trust_score({"fatigue_score": NAN})


def test_finite_risks_are_unchanged() -> None:
    assert compute_trust_score({"overall_risk": 0.2}) == 0.8
    assert compute_trust_score({"overall_risk": 0}) == 1.0
    assert compute_trust_score({"overall_risk": 1}) == 0.0
    assert compute_trust_score({"fatigue_score": 0.25}) == 0.75
    assert map_label(0.8) == "TRUSTED"
    assert map_label(0.0) == "UNTRUSTED"


@pytest.mark.parametrize("score", [NAN, INF, -INF])
def test_map_label_rejects_non_finite_scores(score: float) -> None:
    with pytest.raises(ValueError, match="trust score is not finite"):
        map_label(score)


@pytest.mark.parametrize("bad", [NAN, INF, -INF])
def test_history_with_a_non_finite_entry_is_an_error(bad: float) -> None:
    history = [0.8, 0.7, bad, 0.9]
    with pytest.raises(ValueError, match=r"score_history\[2\] is not finite"):
        compute_volatility(history)
    with pytest.raises(ValueError, match=r"score_history\[2\] is not finite"):
        compute_confidence_band({"overall_risk": 0.2}, history)
    with pytest.raises(ValueError, match=r"score_history\[2\] is not finite"):
        detect_drift(history, [])


def test_confidence_band_rejects_non_finite_k() -> None:
    with pytest.raises(ValueError, match="confidence band k is not finite"):
        compute_confidence_band({"overall_risk": 0.2}, [0.8, 0.7], k=NAN)


def test_badge_and_flags_reject_non_finite_inputs() -> None:
    with pytest.raises(ValueError, match="volatility is not finite"):
        assign_badge(0.9, NAN, DRIFT)
    with pytest.raises(ValueError, match="trust score is not finite"):
        assign_badge(NAN, 0.0, DRIFT)
    with pytest.raises(ValueError, match="volatility is not finite"):
        trigger_flags(0.9, NAN, DRIFT, "STANDARD")
    with pytest.raises(ValueError, match="trust score is not finite"):
        trigger_flags(INF, 0.0, DRIFT, "STANDARD")


def test_finite_history_results_are_unchanged() -> None:
    band = compute_confidence_band({"overall_risk": 0.2}, [0.8, 0.7, 0.9], window_n=3, k=1.0)
    assert band["n"] == 3
    assert math.isclose(band["std"], 0.08164965809277258, rel_tol=0, abs_tol=1e-15)
    assert compute_volatility([0.5, 0.5, 0.5]) == 0.0
    assert assign_badge(0.9, 0.0, DRIFT) == "STABLE"


def test_build_trust_record_refuses_a_nan_risk_instead_of_logging_trusted() -> None:
    with pytest.raises(ValueError, match="overall_risk is not finite"):
        build_trust_record(
            session_id="session-nan",
            turn_index=1,
            model_id="synthetic-model",
            prompt_type="qa",
            derived_signals={"overall_risk": NAN},
            aggregate_score=None,
            response_text=None,
            response_hash="0" * 64,
            score_history=[],
            timestamps=[],
            config={},
            timestamp_utc="2025-01-01T00:00:00Z",
        )
