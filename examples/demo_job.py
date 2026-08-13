"""Local demo automation for RunReconcile; no network service is contacted."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Write deterministic-shape demo artifacts locally.")
    parser.add_argument("--run-id", required=True, help="must match the RunReconcile snapshot run ID")
    return parser


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", args.run_id):
        raise SystemExit("--run-id must match [A-Za-z0-9._-]{1,128}")

    completed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    output = Path(__file__).resolve().parent / "output"

    _write_json(
        output / "result.json",
        {
            "run_id": args.run_id,
            "status": "complete",
            "completed_at": completed_at,
            "records_processed": 3,
        },
    )
    _write_json(
        output / "delivery.json",
        {
            "run_id": args.run_id,
            "status": "delivered",
            "receipt_id": f"local-demo-{args.run_id}",
            "simulated": True,
        },
    )
    print(f"wrote local demo artifacts for run {args.run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
