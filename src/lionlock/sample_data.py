"""Synthetic sample sessions shipped with the package, for the quickstart and smoke checks.

The sessions are invented text. They contain no real prompts, replies or identifiers.

    python -m lionlock.sample_data

scores and gates each sample in memory and prints the decision next to the sample's label. It
writes nothing to disk.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

SAMPLE_RESOURCE = "sample_sessions.json"


def load_sample_sessions() -> list[dict[str, Any]]:
    """Return the packaged synthetic sample sessions (id, text, response, label, notes)."""
    raw = resources.files("lionlock").joinpath(SAMPLE_RESOURCE).read_text(encoding="utf-8")
    records = json.loads(raw)
    if not isinstance(records, list):
        raise ValueError("sample sessions must be a list")
    return [record for record in records if isinstance(record, dict)]


def main() -> int:
    from lionlock.core.gating import evaluate_policy
    from lionlock.core.scoring import score_payload

    flagged = clean = 0
    for idx, record in enumerate(load_sample_sessions()):
        prompt = str(record.get("text", ""))
        response = str(record.get("response") or prompt)
        bundle = score_payload(
            {"prompt": prompt, "response": response, "metadata": {"turn_index": idx}}
        )
        if bundle is None:
            continue
        decision = evaluate_policy(bundle)
        is_flagged = decision.gating_decision in {"REFRESH", "BLOCK"}
        flagged += is_flagged
        clean += not is_flagged
        print(
            f"{record.get('id')}: label={record.get('label')} severity={decision.severity} "
            f"decision={decision.gating_decision} reason={decision.reason_code}"
        )
    print(f"Sample summary: FLAGGED={flagged} CLEAN={clean}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
