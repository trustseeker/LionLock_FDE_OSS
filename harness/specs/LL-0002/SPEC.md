+++
id = "LL-0002"
title = "Attribute every gate decision to its weighted evidence, and let policy change the action, never the severity (decision D1)"
status = "done"
tier = "public"
allowed_paths = [
  "src/lionlock/core/gating.py",
  "src/lionlock/core/models.py",
  "docs/GATING_POLICY.md",
  "tests/test_gating_attribution.py",
  "tests/test_module05_derived_influence.py",
  "tests/test_module06_replay_determinism.py",
]
+++

# LL-0002: the gate names the evidence it acted on

## Why

A review on 17 November 2026 found that a worse reply could get a milder decision. For a prompt
about a travel policy, a reply repeating "policy" 200 times was blocked, but a reply repeating
"banana" 200 times, which is strictly worse, was only refreshed. Two rules combine to cause it:

1. When the weighted aggregate drives the decision, the reported trigger is the highest
   *unweighted* signal. `hallucination_risk` has weight 0.00 by default but comes early in
   `TRIGGER_SIGNAL_ORDER`, so it can be named as the trigger of a decision it contributed nothing
   to. A disabled signal can be named the same way.
2. In `warn_only` mode a red decision whose reason is `hallucination_risk` is rewritten to orange.
   Because of rule 1, that happens to replies that are red for reasons that have nothing to do with
   hallucination.

The owner's decision D1: a worse reply must never get a milder decision. The trigger is chosen by
weighted contribution among enabled signals, and `warn_only` softens a red decision only when the
hallucination evidence alone is what makes it red.

The rewrite in rule 2 also confuses two things. `severity` is meant to describe the measured risk;
the action (`gating_decision`) is what a policy does about it. This spec keeps them apart: severity
always reports the band of `decision_risk_score`, and any policy that changes the action says so in a
new field, `policy_adjustment`.

The owner also approved failing closed on invalid policy settings (review item A1). An invalid
setting today is coerced, and a `nan` weight turns a BLOCK into an ALLOW. That is in scope here
because the gate is where the coercion happens.

## Definitions

- **Signals**: the five keys of `SignalScores`. **Derived signals**: the keys of `DERIVED_RISK_KEYS`
  that LL-0001 lets into the decision channel (`fatigue_risk_index` is withheld when any fatigue
  input is missing).
- **Hallucination evidence**: the signal `hallucination_risk` and the derived signal
  `low_conf_halluc`. Everything else is **non-hallucination evidence**.
- **Weights** `W`: the `weights` argument, or `DEFAULT_SIGNAL_WEIGHTS` when it is `None` or empty.
  **Enabled**: the `enabled_signals` argument, or every signal when it is `None`.
- **Raw channel**: the weighted aggregate, `aggregate_score(bundle, W, enabled)`, unchanged.
  **Derived channel**: the largest admitted derived value. `decision_risk_score` is
  `clamp(max(raw, derived))`, unchanged.
- **Contribution** of signal `k`: `W[k] * score[k]`. A signal is **eligible** to be a raw-channel
  trigger only if it is enabled and `W[k] > 0`.
- **Non-hallucination raw**: the weighted aggregate recomputed over the enabled signals other than
  `hallucination_risk`, in signal order, as `sum(W[k] * score[k]) / sum(W[k])`, and 0 if those
  weights sum to 0. It answers "how red would this reply be if hallucination evidence were
  ignored?". With the default weight of 0.00 on `hallucination_risk` it equals the raw channel.
- **Action rank**: ALLOW < REFRESH < BLOCK.

## Requirements

- **R1 Evidence is unchanged.** Signal scores, derived signals, the aggregate and
  `decision_risk_score` are identical to the behaviour before this change, for every case and every
  valid policy in the product.
- **R2 Severity is the band.** `severity == severity_band(decision_risk_score, thresholds)` always.
  No policy rewrites it.
- **R3 Attribution.** If the derived channel is at least the raw channel, the trigger is the largest
  admitted derived signal, ties broken by `TRIGGER_SIGNAL_ORDER` (as today). Otherwise it is the
  eligible signal with the largest contribution, ties broken by `TRIGGER_SIGNAL_ORDER`. A disabled
  or zero-weight signal is never a raw-channel trigger.
- **R4 Warn-only acts only on hallucination-only reds.** With `hallucination_mode = "warn_only"` and
  severity red, compute the risk without hallucination evidence: `clamp(max(non-hallucination raw,
  largest admitted non-hallucination derived value))`.
  - If that is still red, the action stays BLOCK and the trigger is chosen by R3's rule over
    non-hallucination evidence only, so the reason names what actually justified the block.
  - Otherwise the action is REFRESH, `policy_adjustment = "warn_only_hallucination"`, and the
    trigger is `low_conf_halluc` when the derived channel is at least the raw channel, else
    `hallucination_risk`.
  - With `hallucination_mode = "block"`, R3 applies unchanged and nothing is softened.
- **R5 Adjustments are explicit.** After R4, if the action is BLOCK and
  `hard_gate_reasons_enabled` is given and does not contain the reason code, the action is REFRESH
  with `policy_adjustment = "hard_gate_reason_disabled"`. If gating is disabled and the action is
  not ALLOW, the action is ALLOW with `policy_adjustment = "gating_disabled"`.
  `policy_adjustment` is `None` exactly when the action is the band's default (red BLOCK, orange and
  yellow REFRESH, green ALLOW).
- **R6 Monotone in evidence.** For every valid policy, raising any one signal score or derived value
  never lowers the action rank. This is a property of the gate's inputs. `low_conf_halluc` is itself
  computed from the scores and falls when novelty risk rises, by design, so no claim is made about
  reply text end to end.
- **R7 Invalid policy fails closed.** `evaluate_policy` raises `ValueError`, naming the setting, for:
  a weight that is not a finite number or is negative; an enabled signal name that is not a signal;
  no enabled signal with a positive weight; thresholds missing `yellow`, `orange` or `red`, holding a
  value that is not finite, or not satisfying `0 <= yellow < orange < red <= 1`; and a
  `hallucination_mode` other than `"warn_only"` or `"block"`. `decide_gate` raises `ValueError` for
  the same thresholds and mode problems and for an `aggregate_score` that is not a finite number. An
  invalid setting is never coerced into a decision.
- **R8** The product equals `golden.json`'s `expected` exactly, fingerprint included.
- **R9** `docs/GATING_POLICY.md` explains severity versus action, attribution, the three adjustments,
  and that severity is no longer rewritten.

## Effect on LL-0001

LL-0001's product records `severity` for its corpus. Under R2, two of its cases
(`05-fragments-no-metadata` and `12-fragments-entropy-and-drift`) change from severity `orange` to
`red`; their action stays REFRESH and their trigger and reason are unchanged. LL-0001's golden is
re-baselined by the maintainer from LL-0001's own oracle, updated to this decision rule, before the
implementation exists. Its previous expected product becomes the recorded baseline, so nothing is
lost. No other LL-0001 value changes.

## Effect on existing tests

Added to `allowed_paths` after the golden was generated, when the implementation showed that three
existing tests pin behaviour this spec deliberately replaces. The golden, oracle and product are
unchanged by this revision.

- `tests/test_module05_derived_influence.py`: `test_tie_break_deterministic_for_raw_signals`
  expected the zero-weight `hallucination_risk` as the trigger (R3 forbids it), and
  `test_risk_score_clamped_and_finite_with_bad_inputs` expected `nan` and infinite evidence to be
  read as 0.0. Review item A1 requires such evidence to be refused rather than coerced, so the gate
  now raises `ValueError` naming the field, and finite out-of-range values are still clamped.
- `tests/test_module06_replay_determinism.py`: its recorded event names `hallucination_risk` as
  the trigger, which the current rule no longer produces for that evidence, so the replay found a
  difference. The recorded event is updated to the trigger the rule produces.

## How this is checked

`make verify SPEC=LL-0002` runs the acceptance tests, then runs `product.py` twice under different
hash seeds and compares the canonical output with `golden.json`. The golden was generated before
the implementation by `oracle.py`, which recomputes every decision without calling the gate, and
whose `expected(apply_rule=False)` reproduces the library's behaviour before this change exactly.

## Report template

```
LL-0002: <PASS|FAIL>
fingerprint: <from make verify>
files changed: <list>
requirements: R1 <ok> R2 <ok> R3 <ok> R4 <ok> R5 <ok> R6 <ok> R7 <ok> R8 <ok> R9 <ok>
notes: <anything the spec did not anticipate>
```
