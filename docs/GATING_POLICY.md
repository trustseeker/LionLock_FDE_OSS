# Gating Policy: Passive (Log-Only) vs Active (Enforced)

LionLock computes a deterministic `GateDecision` for every evaluated signal bundle.

Whether that decision is **enforced** or treated as **log-only** is controlled by
`gating.enabled` with an environment override:

- Config key: `gating.enabled` (in `lionlock.toml`)
- Env var override: `LIONLOCK_GATING_ENABLED`

## Resolution order

1. If `LIONLOCK_GATING_ENABLED` is set to a boolean-like value (`true/false`, `1/0`, etc.), it overrides config.
2. Otherwise, LionLock uses `gating.enabled` from config.
3. If neither is provided, default behavior remains **enabled** (`true`).

## Behavior

- `gating.enabled = false` (or env override false):
  - LionLock still computes severity, risk score, trigger signal, and reason code.
  - Decision is emitted as `ALLOW` (log-only mode). When the policy would otherwise have
    refreshed or blocked, `policy_adjustment` is `"gating_disabled"`, so the log still shows what
    enforcement would have done.
- `gating.enabled = true` (or env override true):
  - LionLock enforces policy decisions (`ALLOW` / `REFRESH` / `BLOCK`) based on thresholds.

## How a decision is made

Since 1.0.0b2 (spec LL-0002) a `GateDecision` keeps three things apart: the evidence, how severe
it is, and what the policy does about it.

### Severity is the band, and is never rewritten

`decision_risk_score` is the larger of two channels: the **raw channel** (the weighted mean of the
enabled signals) and the **derived channel** (the largest derived signal admitted to the decision).
`severity` is always the band that score falls in:

| `decision_risk_score` | `severity` | default action |
| --- | --- | --- |
| at least `red` (0.80) | `red` | `BLOCK` |
| at least `orange` (0.65) | `orange` | `REFRESH` |
| at least `yellow` (0.45) | `yellow` | `REFRESH` |
| below `yellow` | `green` | `ALLOW` |

Before 1.0.0b2, warn-only mode and the hard-gate list softened a red decision by rewriting
`severity` to `orange`. They no longer do. Severity reports how bad the evidence is; the policy
changes only the action, and says so (see below).

### Attribution: which evidence the trigger names

- If the derived channel is at least the raw channel, `trigger_signal` is the largest admitted
  derived signal.
- Otherwise it is the signal with the largest **weighted contribution** (weight × score) among the
  signals that are enabled and have a weight above 0. A disabled or zero-weight signal is never
  named, because it did not move the score.
- Ties go to the first name in `TRIGGER_SIGNAL_ORDER`.

`reason_code` is derived from `trigger_signal`. Before 1.0.0b2 the raw-channel trigger was simply
the largest raw score, so a reply could be reported as `hallucination_risk` even though that signal
has weight 0 by default and contributed nothing.

### Policy adjustments

`policy_adjustment` is `None` exactly when the action is the default for the severity in the
table above. Otherwise it names the one policy that changed the action:

| `policy_adjustment` | when | action |
| --- | --- | --- |
| `"warn_only_hallucination"` | `hallucination_mode = "warn_only"`, severity is red, and the reply would **not** be red without the hallucination evidence (`hallucination_risk` and `low_conf_halluc`) | `REFRESH`, trigger `hallucination_risk` or `low_conf_halluc` |
| `"hard_gate_reason_disabled"` | the action is `BLOCK` and `hard_gate_reasons_enabled` is given but does not list the reason code | `REFRESH` |
| `"gating_disabled"` | gating is disabled and the action would not be `ALLOW` | `ALLOW` |

Warn-only works out how red the reply would be if hallucination evidence were ignored: the
weighted mean of the other enabled signals, and the largest other derived signal. If that is still
red, the reply is blocked and the trigger names the evidence that justified the block. A reply
that loops on one word is blocked for repetition even when its hallucination score is also high.
With `hallucination_mode = "block"` nothing is softened.

Raising any one signal score or derived value never lowers the action. This is a property of the
gate's inputs. `low_conf_halluc` is itself computed from the scores and falls as novelty risk
rises, by design, so no such claim is made about reply text end to end.

### Invalid settings are refused, not coerced

`evaluate_policy` and `decide_gate` raise `ValueError`, naming the setting, rather than turning a
bad value into a decision:

- `hallucination_mode` other than `"warn_only"` or `"block"`;
- thresholds missing `yellow`, `orange` or `red`, not finite, or not
  `0 <= yellow < orange < red <= 1`;
- a weight that is not a finite number, or is negative;
- an enabled signal name that is not a signal, or no enabled signal with a weight above 0;
- a signal score, derived signal or aggregate score that is not a finite number.

Finite scores outside 0 to 1 are still clamped into that range.

Pass the config's `signals.weights` and `signals.enabled` (and `gating.thresholds` and
`gating.hallucination_mode`) to `evaluate_policy`, so that the decision matches the `config_hash`
logged with it. The defaults are `DEFAULT_SIGNAL_WEIGHTS`, every signal enabled, and
`DEFAULT_THRESHOLDS`.

## Important runtime note

The OSS library returns a `GateDecision` object. Real-time interruption depends on the caller honoring `GateDecision.gating_decision`.

## Config templates

- TOML template: [`lionlock.toml.example`](../lionlock.toml.example)
- Env template, for database connection settings only: [`.env.example`](../.env.example)

Set gating in `lionlock.toml` (`[gating] enabled = true|false`) or by exporting
`LIONLOCK_GATING_ENABLED` in the process's real environment. A `.env` file that LionLock finds by
itself supplies database connection settings only; a `LIONLOCK_GATING_ENABLED` line in it is
ignored, so a file in an untrusted checkout cannot switch gating off.
