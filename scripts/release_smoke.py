"""Smoke check for an installed lionlock wheel. Mirrors the scoring example in README.md.

Run it with the interpreter of the environment under test, from outside the checkout:

    python scripts/release_smoke.py [expected_version]
"""

from __future__ import annotations

import sys
from importlib import metadata, resources

import lionlock
from lionlock.core.gating import evaluate_policy
from lionlock.core.scoring import score_response


def main(argv: list[str]) -> int:
    version = metadata.version("lionlock")
    print("installed version:", version)
    if lionlock.__version__ != version:
        print(f"FAIL: lionlock.__version__ {lionlock.__version__!r} != metadata {version!r}")
        return 1
    if len(argv) > 1 and argv[1] != version:
        print(f"FAIL: expected version {argv[1]!r}")
        return 1

    prompt = "What is the capital of France?"
    reply = "The capital of France is Paris."

    decision = evaluate_policy(score_response(prompt, reply))
    print(decision.severity, decision.gating_decision, decision.reason_code)
    if decision.gating_decision != "ALLOW":
        print("FAIL: the README example should be allowed")
        return 1

    if not resources.files("lionlock").joinpath("py.typed").is_file():
        print("FAIL: py.typed missing")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
