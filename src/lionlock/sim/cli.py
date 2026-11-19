from __future__ import annotations

import argparse
import sys

from . import runner


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lionlock-sim",
        description=(
            "LionLock Module 07 simulation harness. Feeds synthetic, hand-built signal bundles "
            "(not produced by the scorer) through the gating policy and records the decisions. "
            "It exercises gating, logging and replay; it does not test or calibrate detection. "
            "The database is never chosen for you and the network is never probed: pass --db "
            "or set LIONLOCK_DB_URL."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")
    run_parser = subparsers.add_parser("run", help="Run a deterministic simulation profile.")
    run_parser.add_argument("--profile", default=runner.DEFAULT_PROFILE, help="Profile name.")
    run_parser.add_argument("--turns", type=int, default=runner.DEFAULT_TURNS, help="Turn count.")
    run_parser.add_argument("--seed", type=int, default=runner.DEFAULT_SEED, help="Seed value.")
    run_parser.add_argument(
        "--out-dir",
        default="sim_out",
        help="Output directory for report and labels.",
    )
    run_parser.add_argument(
        "--db",
        help=(
            "Required unless LIONLOCK_DB_URL is set. SQL URI/DSN the run writes to: "
            f"{runner.SUGGESTED_SQLITE_URI} for a local file (no network), or a postgresql:// "
            "DSN. There is no default database and no automatic fallback."
        ),
    )
    run_parser.add_argument("--schema", help="Postgres schema or sqlite schema name.")
    run_parser.add_argument("--policy", default="dev-local", help="Policy version identifier.")
    run_parser.add_argument("--policy-registry", help="Policy registry TOML file path.")
    run_parser.add_argument(
        "--append-run",
        action="store_true",
        help=(
            "Write under a new run_id, <base>-<n>, where n is one more than the highest already "
            "in the database (no idempotent wipe). Deterministic for a given database; run "
            "append writers one at a time."
        ),
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command != "run":
        parser.print_help()
        return 2
    try:
        result = runner.run_simulation(
            profile=args.profile,
            turns=args.turns,
            seed=args.seed,
            output_dir=args.out_dir,
            db_url=args.db,
            schema=args.schema,
            policy_version=args.policy,
            policy_registry_path=args.policy_registry,
            append_run=args.append_run,
        )
        warnings = result.report.get("logging", {}).get("warnings", [])
        if isinstance(warnings, list):
            for warning in warnings:
                print(f"WARNING: {warning}", file=sys.stderr)
    except Exception as exc:
        print(f"sim error: {exc}", file=sys.stderr)
        return 1
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
