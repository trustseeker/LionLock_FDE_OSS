import math
from typing import Callable, Dict, Iterable

from .models import (
    DerivedSignals,
    GateDecision,
    SignalBundle,
    SignalScores,
    canonical_gating_decision,
)
from .scoring import (
    DEFAULT_SIGNAL_WEIGHTS,
    SIGNAL_SCHEMA_VERSION,
    aggregate_score,
    low_conf_halluc_score,
)

DEFAULT_THRESHOLDS: Dict[str, float] = {
    "yellow": 0.45,
    "orange": 0.65,
    "red": 0.8,
}

DEFAULT_HARD_GATE_REASONS: tuple[str, ...] = (
    "repetition_loop",
    "low_novelty",
    "low_coherence",
    "context_drift",
    "hallucination_risk",
)

REASON_CODE_MAP: Dict[str, str] = {
    "repetition_loopiness": "repetition_loop",
    "novelty_entropy_proxy": "low_novelty",
    "coherence_structure": "low_coherence",
    "context_adherence": "context_drift",
    "hallucination_risk": "hallucination_risk",
    "fatigue_risk_index": "fatigue_risk",
    "low_conf_halluc": "hallucination_risk",
    "congestion_signature": "congestion_risk",
}

DERIVED_RISK_KEYS = (
    "fatigue_risk_index",
    "low_conf_halluc",
    "congestion_signature",
)

# Metadata inputs that fatigue_risk_index is computed from. None of them has a definition in this
# repo, so any of them being absent means the fatigue score is an all-defaults artifact.
FATIGUE_INPUT_KEYS = (
    "entropy_decay",
    "turn_index",
    "drift_slope",
)

# Everything score_payload reports missing for a payload with no metadata. decide_gate never
# receives metadata at all, so it declares the same set, not only the fatigue inputs (LL-0001 R5).
NO_METADATA_MISSING_INPUTS = (
    *FATIGUE_INPUT_KEYS,
    "duration_ms",
    "latency_window_stats",
)

TRIGGER_SIGNAL_ORDER = (
    "fatigue_risk_index",
    "congestion_signature",
    "low_conf_halluc",
    "hallucination_risk",
    "context_adherence",
    "coherence_structure",
    "novelty_entropy_proxy",
    "repetition_loopiness",
)


def severity_band(aggregate_score: float, thresholds: Dict[str, float] | None = None) -> str:
    thresholds = thresholds or DEFAULT_THRESHOLDS
    if aggregate_score >= thresholds["red"]:
        return "red"
    if aggregate_score >= thresholds["orange"]:
        return "orange"
    if aggregate_score >= thresholds["yellow"]:
        return "yellow"
    return "green"


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _safe_unit_interval(value: float | int | None) -> float:
    if value is None or isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return _clamp(float(value))
    return 0.0


def _safe_signal_map(raw: Dict[str, float]) -> Dict[str, float]:
    return {key: _safe_unit_interval(value) for key, value in raw.items()}


def _reason_code_for(trigger_signal: str) -> str:
    if trigger_signal in REASON_CODE_MAP:
        return REASON_CODE_MAP[trigger_signal]
    return "policy_violation"


def gating_derived_risk_keys(missing_inputs: Iterable[str]) -> tuple[str, ...]:
    """Derived signals allowed to raise the severity band.

    SE-0.4.0: ``fatigue_risk_index`` is withheld from the decision channel when any of
    ``FATIGUE_INPUT_KEYS`` is missing. Its sigmoid is uncalibrated (see the note on
    ``FATIGUE_SIGMOID_GAIN`` in scoring.py), so a caller that supplies no fatigue metadata must not
    be gated on the resulting all-defaults score. The value is still reported in the bundle for
    observability; it just cannot move a band.
    """
    if set(missing_inputs) & set(FATIGUE_INPUT_KEYS):
        return tuple(key for key in DERIVED_RISK_KEYS if key != "fatigue_risk_index")
    return DERIVED_RISK_KEYS


def _pick_by_order(values: Dict[str, float], order: Iterable[str]) -> str:
    if not values:
        return "unknown"
    best_value = -1.0
    for key in order:
        if key in values:
            best_value = max(best_value, values[key])
    if best_value < 0.0:
        return "unknown"
    for key in order:
        if values.get(key, -1.0) == best_value:
            return key
    return "unknown"


HALLUCINATION_MODES = ("warn_only", "block")
# Evidence about hallucination: the raw signal and the derived signal computed from it. warn_only
# may soften a red decision only when this evidence alone is what makes it red (LL-0002, D1).
HALLUCINATION_EVIDENCE = ("hallucination_risk", "low_conf_halluc")
# The action each band calls for. A policy that changes it says so in
# GateDecision.policy_adjustment.
_DEFAULT_ACTION = {"red": "BLOCK", "orange": "REFRESH", "yellow": "REFRESH", "green": "ALLOW"}


def _is_finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:  # an int too large for a float
        return False


def _validate_policy(
    *,
    thresholds: Dict[str, float] | None,
    hallucination_mode: str,
    weights: Dict[str, float] | None,
    enabled_signals: Iterable[str] | None,
) -> None:
    """Refuse a policy that would otherwise be coerced into a decision (LL-0002 R7, review A1).

    Before this check a ``nan`` weight turned a BLOCK into an ALLOW, a ``nan`` red threshold meant
    nothing was ever red, a missing threshold raised KeyError mid-decision, and a misspelt mode
    silently behaved like "block".
    """
    if hallucination_mode not in HALLUCINATION_MODES:
        raise ValueError(
            f"hallucination_mode must be one of {HALLUCINATION_MODES}, got {hallucination_mode!r}"
        )
    if thresholds is not None:
        for key in ("yellow", "orange", "red"):
            if key not in thresholds:
                raise ValueError(f"thresholds is missing {key!r}")
            if not _is_finite_number(thresholds[key]):
                raise ValueError(
                    f"thresholds[{key!r}] must be a finite number, got {thresholds[key]!r}"
                )
        if not 0.0 <= thresholds["yellow"] < thresholds["orange"] < thresholds["red"] <= 1.0:
            raise ValueError(
                "thresholds must satisfy 0 <= yellow < orange < red <= 1, got "
                f"yellow={thresholds['yellow']!r} orange={thresholds['orange']!r} "
                f"red={thresholds['red']!r}"
            )
    resolved = weights or DEFAULT_SIGNAL_WEIGHTS
    for key, value in resolved.items():
        if not _is_finite_number(value) or value < 0:
            raise ValueError(f"weights[{key!r}] must be a finite number >= 0, got {value!r}")
    signals = tuple(SignalScores.__dataclass_fields__)
    enabled = None if enabled_signals is None else list(enabled_signals)
    if enabled is not None:
        unknown = [key for key in enabled if key not in signals]
        if unknown:
            raise ValueError(f"enabled_signals names unknown signals {unknown}; known: {signals}")
    if not any(resolved.get(key, 0.0) > 0 for key in signals if enabled is None or key in enabled):
        raise ValueError("no enabled signal has a positive weight, so nothing could ever gate")
    # Each weight can be finite while their sum is not: two weights of 1e308 add up to inf, and
    # the weighted mean then becomes finite / inf = 0.0, which would turn a BLOCK into an ALLOW.
    # Summed in the same order as aggregate_score.
    total = 0.0
    for key in signals:
        if enabled is None or key in enabled:
            total += resolved.get(key, 0.0)
    if not math.isfinite(total):
        raise ValueError(
            "the enabled signals' weights add up to more than a float can hold; "
            "scale them down (only their ratios matter)"
        )


def _validate_evidence(signal_scores: SignalScores, derived_signals: DerivedSignals) -> None:
    """Refuse evidence that is not a finite number (review A1).

    A ``nan`` or infinite score used to be read as 0.0, so broken evidence could lower the risk
    and turn into ALLOW. Finite values outside [0, 1] are still clamped, as before.
    """
    for group, values in (
        ("signal_scores", signal_scores.as_dict()),
        ("derived_signals", derived_signals.as_dict()),
    ):
        for key, value in values.items():
            if not _is_finite_number(value):
                raise ValueError(f"{group}[{key!r}] must be a finite number, got {value!r}")


def _restricted_risk(
    *,
    allowed: Callable[[str], bool],
    scores: Dict[str, float],
    weights: Dict[str, float],
    enabled_keys: list[str],
    derived_risk_map: Dict[str, float],
    contributions: Dict[str, float],
    thresholds: Dict[str, float],
) -> tuple[bool, str]:
    """Is the reply still red using only the allowed evidence, and which evidence drives it?

    The weighted mean uses the scores as given (finite, not clamped one by one) and is clamped
    afterwards: the same arithmetic as the raw channel, so with every signal allowed it equals it.
    Restricting evidence can only lower this risk, and raising any score can only raise it, which
    keeps warn-only and the hard-gate list monotone (LL-0002 R4, R5, R6).
    """
    weighted_sum = 0.0
    weight_total = 0.0
    for key in enabled_keys:
        if not allowed(key):
            continue
        weight = weights.get(key, 0.0)
        weighted_sum += float(scores[key]) * weight
        weight_total += weight
    sub_raw = _safe_unit_interval(weighted_sum / weight_total if weight_total else 0.0)
    sub_derived = {key: value for key, value in derived_risk_map.items() if allowed(key)}
    sub_derived_channel = max(sub_derived.values()) if sub_derived else 0.0
    is_red = severity_band(_clamp(max(sub_raw, sub_derived_channel)), thresholds) == "red"
    if sub_derived_channel >= sub_raw:
        return is_red, _pick_by_order(sub_derived, TRIGGER_SIGNAL_ORDER)
    sub_contributions = {key: value for key, value in contributions.items() if allowed(key)}
    return is_red, _pick_by_order(sub_contributions, TRIGGER_SIGNAL_ORDER)


def _evaluate_policy_with_scores(
    *,
    aggregate: float,
    signal_scores: SignalScores,
    derived_signals: DerivedSignals,
    thresholds: Dict[str, float] | None,
    gating_enabled: bool,
    hallucination_mode: str,
    hard_gate_reasons_enabled: Iterable[str] | None,
    signal_bundle: SignalBundle,
    weights: Dict[str, float] | None = None,
    enabled_signals: Iterable[str] | None = None,
) -> GateDecision:
    """The decision rule (LL-0002, decision D1).

    Severity is the band of ``decision_risk_score`` and is never rewritten. The trigger names the
    evidence acted on: the largest admitted derived signal when the derived channel leads,
    otherwise the enabled, positively weighted signal with the largest weighted contribution.
    Policy may change the action, and every such change is recorded in ``policy_adjustment``.
    """
    _validate_policy(
        thresholds=thresholds,
        hallucination_mode=hallucination_mode,
        weights=weights,
        enabled_signals=enabled_signals,
    )
    _validate_evidence(signal_scores, derived_signals)
    if not _is_finite_number(aggregate):
        raise ValueError(f"aggregate_score must be a finite number, got {aggregate!r}")
    thresholds = thresholds or DEFAULT_THRESHOLDS
    resolved_weights = weights or DEFAULT_SIGNAL_WEIGHTS
    enabled = None if enabled_signals is None else set(enabled_signals)
    safe_signal_scores = _safe_signal_map(signal_scores.as_dict())
    safe_derived = _safe_signal_map(derived_signals.as_dict())
    raw_channel = _safe_unit_interval(aggregate)
    gating_keys = gating_derived_risk_keys(signal_bundle.missing_inputs)
    derived_risk_map = {key: safe_derived.get(key, 0.0) for key in gating_keys}
    derived_channel = max(derived_risk_map.values()) if derived_risk_map else 0.0
    decision_risk_score = _clamp(max(raw_channel, derived_channel))
    severity = severity_band(decision_risk_score, thresholds=thresholds)

    enabled_keys = [key for key in safe_signal_scores if enabled is None or key in enabled]
    contributions = {
        key: resolved_weights.get(key, 0.0) * safe_signal_scores[key]
        for key in enabled_keys
        if resolved_weights.get(key, 0.0) > 0
    }
    if derived_channel >= raw_channel:
        trigger_signal = _pick_by_order(derived_risk_map, TRIGGER_SIGNAL_ORDER)
    else:
        trigger_signal = _pick_by_order(contributions, TRIGGER_SIGNAL_ORDER)

    gating_decision = _DEFAULT_ACTION[severity]
    policy_adjustment: str | None = None
    raw_scores = signal_scores.as_dict()

    def still_red(allowed: Callable[[str], bool]) -> tuple[bool, str]:
        return _restricted_risk(
            allowed=allowed,
            scores=raw_scores,
            weights=resolved_weights,
            enabled_keys=enabled_keys,
            derived_risk_map=derived_risk_map,
            contributions=contributions,
            thresholds=thresholds,
        )

    if severity == "red" and hallucination_mode == "warn_only":
        red_without_hallucination, driver = still_red(lambda key: key not in HALLUCINATION_EVIDENCE)
        if red_without_hallucination:
            # Red without the hallucination evidence: block, and name what justified it.
            trigger_signal = driver
        else:
            gating_decision = "REFRESH"
            policy_adjustment = "warn_only_hallucination"
            trigger_signal = (
                "low_conf_halluc" if derived_channel >= raw_channel else "hallucination_risk"
            )

    if gating_decision == "BLOCK" and hard_gate_reasons_enabled is not None:
        listed = set(hard_gate_reasons_enabled)

        def is_listed(key: str) -> bool:
            if hallucination_mode == "warn_only" and key in HALLUCINATION_EVIDENCE:
                return False
            return _reason_code_for(key) in listed

        red_on_listed, driver = still_red(is_listed)
        if red_on_listed:
            # The listed evidence alone justifies the block; the reason is always a listed one.
            trigger_signal = driver
        else:
            gating_decision = "REFRESH"
            policy_adjustment = "hard_gate_reason_disabled"
    reason_code = _reason_code_for(trigger_signal)

    if not gating_enabled and gating_decision != "ALLOW":
        gating_decision = "ALLOW"
        policy_adjustment = "gating_disabled"

    gating_decision = canonical_gating_decision(gating_decision)
    return GateDecision(
        severity=severity,
        decision=gating_decision,
        reason_code=reason_code,
        aggregate_score=raw_channel,
        signal_scores=safe_signal_scores,
        gating_decision=gating_decision,
        decision_risk_score=decision_risk_score,
        trigger_signal=trigger_signal,
        signal_bundle=signal_bundle.as_dict(),
        policy_adjustment=policy_adjustment,
    )


def evaluate_policy(
    bundle: SignalBundle,
    thresholds: Dict[str, float] | None = None,
    gating_enabled: bool = True,
    hallucination_mode: str = "warn_only",
    hard_gate_reasons_enabled: Iterable[str] | None = None,
    weights: Dict[str, float] | None = None,
    enabled_signals: list[str] | None = None,
) -> GateDecision:
    """Gate a scored bundle.

    ``weights`` and ``enabled_signals`` default to ``DEFAULT_SIGNAL_WEIGHTS`` and every signal.
    Pass a config's ``signals.weights`` / ``signals.enabled`` (and ``gating.thresholds`` /
    ``gating.hallucination_mode``) so the decision matches the ``config_hash`` you log with it.

    Raises ValueError for an invalid policy: a weight that is not a finite number >= 0, an unknown
    enabled signal, no enabled signal with a positive weight, thresholds that are missing, not
    finite or not ``0 <= yellow < orange < red <= 1``, or an unknown ``hallucination_mode``. Also
    raises ValueError, naming the field, when a signal or derived score is not a finite number.
    """
    _validate_policy(
        thresholds=thresholds,
        hallucination_mode=hallucination_mode,
        weights=weights,
        enabled_signals=enabled_signals,
    )
    _validate_evidence(bundle.signal_scores, bundle.derived_signals)
    aggregate = aggregate_score(bundle, weights=weights, enabled_signals=enabled_signals)
    return _evaluate_policy_with_scores(
        aggregate=aggregate,
        signal_scores=bundle.signal_scores,
        derived_signals=bundle.derived_signals,
        thresholds=thresholds,
        gating_enabled=gating_enabled,
        hallucination_mode=hallucination_mode,
        hard_gate_reasons_enabled=hard_gate_reasons_enabled,
        signal_bundle=bundle,
        weights=weights,
        enabled_signals=enabled_signals,
    )


def decide_gate(
    aggregate_score: float,
    scores: SignalScores,
    thresholds: Dict[str, float] | None = None,
    gating_enabled: bool = True,
    hallucination_mode: str = "warn_only",
    hard_gate_reasons_enabled: Iterable[str] | None = None,
) -> GateDecision:
    derived_signals = DerivedSignals(
        fatigue_risk_index=0.0,
        fatigue_risk_25t=0.0,
        fatigue_risk_50t=0.0,
        low_conf_halluc=low_conf_halluc_score(scores),
        congestion_signature=0.0,
    )
    bundle = SignalBundle(
        signal_schema_version=SIGNAL_SCHEMA_VERSION,
        signal_scores=scores,
        derived_signals=derived_signals,
        # SE-0.4.0: this entry point accepts raw signal scores only and never receives fatigue
        # metadata, so the fatigue_risk_index=0.0 above is an all-defaults placeholder rather than a
        # measurement. Declaring those inputs missing keeps the placeholder out of the decision
        # channel and out of trigger attribution. Without this, fatigue_risk_index stayed in the
        # derived map and, being first in TRIGGER_SIGNAL_ORDER, won ties: an all-zero call reported
        # reason_code "fatigue_risk". The non-fatigue inputs are declared too, because this entry
        # point receives no metadata of any kind; that changes reporting only, not the decision.
        missing_inputs=NO_METADATA_MISSING_INPUTS,
    )
    return _evaluate_policy_with_scores(
        aggregate=aggregate_score,
        signal_scores=scores,
        derived_signals=derived_signals,
        thresholds=thresholds,
        gating_enabled=gating_enabled,
        hallucination_mode=hallucination_mode,
        hard_gate_reasons_enabled=hard_gate_reasons_enabled,
        signal_bundle=bundle,
    )
