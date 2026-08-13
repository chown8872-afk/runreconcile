"""Command-line interface for snapshot and post-run reconciliation."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .checks import run_checks
from .contract import ContractError, load_contract
from .receipt import ReceiptWriteError, make_receipt, write_receipt_directory
from .snapshot import (
    SnapshotError,
    diff_snapshots,
    load_snapshot,
    save_snapshot,
    snapshot_contract,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="runreconcile",
        description="Reconcile declared automation outcomes against independently observed final state.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate a non-executable TOML contract")
    validate.add_argument("-c", "--contract", type=Path, required=True)

    snapshot = subparsers.add_parser("snapshot", help="capture the declared pre-run final state")
    snapshot.add_argument("-c", "--contract", type=Path, required=True)
    snapshot.add_argument("-o", "--output", type=Path, required=True)
    snapshot.add_argument("--run-id", default=None)

    verify = subparsers.add_parser("verify", help="compare final state and emit a public-safe receipt")
    verify.add_argument("-c", "--contract", type=Path, required=True)
    verify.add_argument("-b", "--before", type=Path, required=True)
    verify.add_argument("--before-sha256", required=True)
    verify.add_argument("-o", "--output-dir", type=Path, required=True)
    return parser


def _entry_count(snapshot) -> int:
    return sum(len(watch.entries) for watch in snapshot.watches.values())


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    try:
        contract = load_contract(args.contract)
    except (ContractError, OSError, FileNotFoundError) as exc:
        print(f"invalid contract: {exc}", file=sys.stderr)
        return 2

    if args.command == "validate":
        print(json.dumps({"valid": True, "schema_version": contract.schema_version, "project_id": contract.project_id}))
        return 0

    if args.command == "snapshot":
        run_id = args.run_id or str(uuid.uuid4())
        try:
            baseline = snapshot_contract(contract, run_id)
            baseline_sha256 = save_snapshot(baseline, args.output)
        except (SnapshotError, OSError):
            print("snapshot error: unable to create a complete snapshot", file=sys.stderr)
            return 3
        print(
            json.dumps(
                {"snapshot": "created", "run_id": run_id, "sha256": baseline_sha256},
                sort_keys=True,
            )
        )
        return 0

    if args.command == "verify":
        try:
            before = load_snapshot(args.before, expected_sha256=args.before_sha256)
            if before.contract_sha256 != contract.sha256:
                raise SnapshotError("baseline contract hash does not match the current contract")
            after = snapshot_contract(contract, before.run_id)
            diff = diff_snapshots(contract, before, after)
            checks = run_checks(contract, before, after)
            receipt = make_receipt(
                project_id=contract.project_id,
                public_label=contract.public_label,
                run_id=before.run_id,
                started_at=before.created_at,
                finished_at=after.created_at,
                contract_sha256=contract.sha256,
                checks=checks,
                diff=diff,
                entry_count_before=_entry_count(before),
                entry_count_after=_entry_count(after),
            )
            write_receipt_directory(receipt, args.output_dir)
        except ReceiptWriteError as exc:
            print(f"receipt error: {exc}", file=sys.stderr)
            return 3
        except (SnapshotError, OSError, ValueError) as exc:
            if isinstance(exc, SnapshotError) and str(exc) == "baseline digest mismatch":
                print("verification error: baseline digest mismatch", file=sys.stderr)
            else:
                print("verification error: unable to complete verification", file=sys.stderr)
            return 3
        print(json.dumps({"verdict": receipt["verdict"], "run_id": before.run_id}, sort_keys=True))
        if receipt["verdict"] == "ACCEPTED":
            return 0
        if receipt["verdict"] in {"FAILED", "BOUNDARY_VIOLATION"}:
            return 1
        return 3

    print("unsupported command", file=sys.stderr)
    return 2
