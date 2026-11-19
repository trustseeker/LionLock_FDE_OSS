"""LL-0002 acceptance tests: one test per requirement, plus the golden comparison.

These run against whatever implementation exists. Before LL-0002 is implemented they fail, which is
the point: the spec describes work not yet done. R8 alone would catch a wrong implementation; the
others say which requirement was missed.
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import math
import sys
from pathlib import Path
from typing import Any

import pytest

SPEC_DIR = Path(__file__).resolve().parent
REPO_ROOT = SPEC_DIR.parents[2]
for candidate in (str(REPO_ROOT), str(REPO_ROOT / "src")):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from harness.fingerprint import canonical, fingerprint  # noqa: E402
from lionlock.core.gating import (  # noqa: E402
    DEFAULT_THRESHOLDS,
    decide_gate,
    evaluate_policy,
    severity_band,
)
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores  # noqa: E402
from lionlock.core.scoring import (  # noqa: E402
    DEFAULT_SIGNAL_WEIGHTS,
    SIGNAL_SCHEMA_VERSION,
    score_payload,
)

RANK = {"ALLOW": 0, "REFRESH": 1, "BLOCK": 2}
DEFAULT_ACTION = {"red": "BLOCK", "orange": "REFRESH", "yellow": "REFRESH", "green": "ALLOW"}
ADJUSTMENTS = {None, "warn_only_hallucination", "hard_gate_reason_disabled", "gating_disabled"}
SIGNALS = tuple(SignalScores.__dataclass_fields__)


def _load(name: str) -> Any:
    module_spec = importlib.util.spec_from_file_location(f"_ll0002_{name}", SPEC_DIR / f"{name}.py")
    assert module_spec is not None and module_spec.loader is not None
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def golden() -> dict[str, Any]:
    return json.loads((SPEC_DIR / "golden.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def product_module() -> Any:
    return _load("product")


@pytest.fixture(scope="module")
def product(product_module: Any) -> dict[str, Any]:
    return product_module.product()


def _valid_views(product: dict[str, Any]):
    for case in product["cases"]:
        if case.get("rejected"):
            continue
        for policy, view in case["evaluate_policy"].items():
            yield case, policy, view


def _bundle(scores: dict[str, float], low_conf: float, fatigue: float = 0.0) -> SignalBundle:
    """A hand-built bundle whose evidence is set directly, with every input declared present."""
    return SignalBundle(
        signal_schema_version=SIGNAL_SCHEMA_VERSION,
        signal_scores=SignalScores(**scores),
        derived_signals=DerivedSignals(
            fatigue_risk_index=fatigue,
            fatigue_risk_25t=fatigue,
            fatigue_risk_50t=fatigue,
            low_conf_halluc=low_conf,
            congestion_signature=0.0,
        ),
        missing_inputs=(),
    )


def test_r1_evidence_is_unchanged(golden: dict[str, Any], product: dict[str, Any]) -> None:
    before = {case["id"]: case.get("evidence") for case in golden["baseline"]["cases"]}
    for case in product["cases"]:
        assert canonical(case.get("evidence")) == canonical(before[case["id"]]), case["id"]
        for policy, view in case.get("evaluate_policy", {}).items():
            base = next(c for c in golden["baseline"]["cases"] if c["id"] == case["id"])
            assert canonical(view["decision_risk_score"]) == canonical(
                base["evaluate_policy"][policy]["decision_risk_score"]
            ), (case["id"], policy)


def test_r2_severity_is_the_band(product: dict[str, Any], product_module: Any) -> None:
    for case, policy, view in _valid_views(product):
        thresholds = product_module.POLICIES[policy].get("thresholds") or DEFAULT_THRESHOLDS
        assert view["severity"] == severity_band(view["decision_risk_score"], thresholds), (
            case["id"],
            policy,
        )


def test_r3_no_disabled_or_zero_weight_raw_trigger(product: dict[str, Any]) -> None:
    for case, policy, view in _valid_views(product):
        trigger = view["trigger_signal"]
        if policy == "context_only" and trigger in SIGNALS:
            assert trigger == "context_adherence", (case["id"], view)
        if policy in ("default", "block_mode", "log_only") and view["policy_adjustment"] is None:
            assert trigger != "hallucination_risk", (case["id"], policy, view)


def test_r4_off_topic_loop_is_blocked_and_hallucination_only_red_is_softened(
    product: dict[str, Any],
) -> None:
    by_id = {case["id"]: case for case in product["cases"]}
    for loop in ("18-policy-loop-on-topic", "19-banana-loop-off-topic"):
        for policy in ("default", "block_mode", "hallucination_weighted"):
            view = by_id[loop]["evaluate_policy"][policy]
            assert (view["severity"], view["gating_decision"]) == ("red", "BLOCK"), (loop, policy)
            assert view["reason_code"] != "hallucination_risk", (loop, policy)
    for case_id in ("05-fragments-no-metadata", "12-fragments-entropy-and-drift"):
        view = by_id[case_id]["evaluate_policy"]["default"]
        assert view["severity"] == "red"
        assert view["gating_decision"] == "REFRESH"
        assert view["policy_adjustment"] == "warn_only_hallucination"
        assert view["reason_code"] == "hallucination_risk"
        assert by_id[case_id]["evaluate_policy"]["block_mode"]["gating_decision"] == "BLOCK"


def test_r4_non_hallucination_red_names_its_own_driver() -> None:
    scores = dict.fromkeys(SIGNALS, 1.0)
    decision = evaluate_policy(_bundle(scores, low_conf=1.0))
    assert decision.gating_decision == "BLOCK"
    assert decision.reason_code != "hallucination_risk"
    assert decision.policy_adjustment is None


def test_r5_adjustment_is_explicit(product: dict[str, Any]) -> None:
    for case, policy, view in _valid_views(product):
        assert view["policy_adjustment"] in ADJUSTMENTS, (case["id"], policy)
        default = DEFAULT_ACTION[view["severity"]]
        assert (view["policy_adjustment"] is None) == (view["gating_decision"] == default), (
            case["id"],
            policy,
            view,
        )


@pytest.mark.parametrize(
    "policy",
    ["default", "block_mode", "hallucination_weighted", "repetition_not_hard_gated"],
)
def test_r6_raising_any_evidence_never_lowers_the_action(product_module: Any, policy: str) -> None:
    kwargs = product_module.POLICIES[policy]
    levels = (0.0, 0.3, 0.6, 0.9)
    lows = (0.0, 0.5, 0.85)

    def action(scores: tuple[float, ...], low: float) -> int:
        decision = evaluate_policy(_bundle(dict(zip(SIGNALS, scores)), low_conf=low), **kwargs)
        return RANK[decision.gating_decision]

    for scores in itertools.product(levels, repeat=len(SIGNALS)):
        for low in lows:
            here = action(scores, low)
            for index, value in enumerate(scores):
                higher = [level for level in levels if level > value]
                if higher:
                    raised = scores[:index] + (higher[0],) + scores[index + 1 :]
                    assert action(raised, low) >= here, (policy, scores, low, index)
            higher_low = [level for level in lows if level > low]
            if higher_low:
                assert action(scores, higher_low[0]) >= here, (policy, scores, low, "low_conf")


def test_r5_more_evidence_cannot_lift_a_hard_gated_block() -> None:
    # Found in review: a tie flipped the winning reason to an unlisted one.
    weights = {"repetition_loopiness": 1.0, "context_adherence": 1.0}
    kwargs = {
        "weights": weights,
        "hallucination_mode": "block",
        "hard_gate_reasons_enabled": ["repetition_loop"],
    }
    for context in (0.8, 1.0):
        scores = {**dict.fromkeys(SIGNALS, 0.0), "repetition_loopiness": 1.0}
        scores["context_adherence"] = context
        decision = evaluate_policy(_bundle(scores, low_conf=0.0), **kwargs)
        assert decision.gating_decision == "BLOCK", context
        assert decision.reason_code == "repetition_loop", context


def test_r4_out_of_range_scores_are_averaged_before_clamping() -> None:
    # Found in review: clamping each score first made a red reply look "not red without
    # hallucination evidence" even though hallucination carried no weight.
    scores = {**dict.fromkeys(SIGNALS, 0.0), "repetition_loopiness": 1.8}
    weights = {"repetition_loopiness": 1.0, "context_adherence": 1.0}
    decision = evaluate_policy(_bundle(scores, low_conf=0.0), weights=weights)
    assert (decision.severity, decision.gating_decision) == ("red", "BLOCK")
    assert decision.policy_adjustment is None


INVALID = {
    "nan weight": {"weights": {**DEFAULT_SIGNAL_WEIGHTS, "repetition_loopiness": math.nan}},
    "infinite weight": {"weights": {**DEFAULT_SIGNAL_WEIGHTS, "repetition_loopiness": math.inf}},
    "negative weight": {"weights": {**DEFAULT_SIGNAL_WEIGHTS, "context_adherence": -0.2}},
    "all weights zero": {"weights": dict.fromkeys(DEFAULT_SIGNAL_WEIGHTS, 0.0)},
    "unknown enabled signal": {"enabled_signals": ["no_such_signal"]},
    "only zero-weight signal enabled": {"enabled_signals": ["hallucination_risk"]},
    "unordered thresholds": {"thresholds": {"yellow": 0.7, "orange": 0.65, "red": 0.8}},
    "missing red": {"thresholds": {"yellow": 0.45, "orange": 0.65}},
    "nan red": {"thresholds": {"yellow": 0.45, "orange": 0.65, "red": math.nan}},
    "red above one": {"thresholds": {"yellow": 0.45, "orange": 0.65, "red": 1.5}},
    "misspelt mode": {"hallucination_mode": "warn_onyl"},
    "empty thresholds": {"thresholds": {}},
    "text weight": {"weights": {**DEFAULT_SIGNAL_WEIGHTS, "repetition_loopiness": "0.3"}},
}


@pytest.mark.parametrize("name", sorted(INVALID))
def test_r7_invalid_policy_is_refused(name: str) -> None:
    bundle = score_payload({"prompt": "Summarise the policy.", "response": "banana " * 50})
    assert bundle is not None
    with pytest.raises(ValueError):
        evaluate_policy(bundle, **INVALID[name])


@pytest.mark.parametrize("aggregate", [math.nan, math.inf, -math.inf])
def test_r7_decide_gate_refuses_a_non_finite_aggregate(aggregate: float) -> None:
    with pytest.raises(ValueError):
        decide_gate(aggregate, SignalScores(**dict.fromkeys(SIGNALS, 0.0)))


def test_r8_product_matches_golden(golden: dict[str, Any], product: dict[str, Any]) -> None:
    assert fingerprint(product) == golden["expected_fingerprint"]
    assert canonical(product) == canonical(golden["expected"])


def test_r9_gating_policy_documents_the_rule() -> None:
    text = (REPO_ROOT / "docs" / "GATING_POLICY.md").read_text(encoding="utf-8")
    for phrase in (
        "policy_adjustment",
        "warn_only_hallucination",
        "hard_gate_reason_disabled",
        "gating_disabled",
        "severity",
    ):
        assert phrase in text, phrase
