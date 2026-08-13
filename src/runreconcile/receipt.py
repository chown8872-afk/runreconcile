"""Public-safe reconciliation receipts and atomic directory publication."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

from . import __version__
from .checks import CheckResult
from .snapshot import DiffResult


class ReceiptWriteError(RuntimeError):
    pass


def _duration_ms(started_at: str, finished_at: str) -> int:
    try:
        start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        finish = datetime.fromisoformat(finished_at.replace("Z", "+00:00"))
        return max(0, int((finish - start).total_seconds() * 1000))
    except (ValueError, TypeError):
        return 0


def _verdict(checks: Sequence[CheckResult], diff: DiffResult) -> str:
    if diff.unexpected:
        return "BOUNDARY_VIOLATION"
    required = [check for check in checks if check.required]
    if any(check.status in {"error", "skipped"} for check in required):
        return "INDETERMINATE"
    if any(check.status == "fail" for check in required):
        return "FAILED"
    return "ACCEPTED"


def make_receipt(
    *,
    project_id: str,
    public_label: str,
    run_id: str,
    started_at: str,
    finished_at: str,
    contract_sha256: str,
    checks: Sequence[CheckResult],
    diff: DiffResult,
    entry_count_before: int,
    entry_count_after: int,
) -> Dict[str, Any]:
    counts = {status: sum(item.status == status for item in checks) for status in ("pass", "fail", "error", "skipped")}
    return {
        "schema_version": "runreconcile.receipt.v1",
        "tool": {"name": "runreconcile", "version": __version__},
        "project": {"id": project_id, "public_label": public_label},
        "run": {
            "id": run_id,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_ms": _duration_ms(started_at, finished_at),
        },
        "contract": {"schema_version": "1", "sha256": contract_sha256},
        "verdict": _verdict(checks, diff),
        "summary": {
            "passed": counts["pass"],
            "failed": counts["fail"],
            "errors": counts["error"],
            "skipped": counts["skipped"],
        },
        "checks": [
            {
                "id": item.id,
                "type": item.type,
                "public_label": item.public_label,
                "required": item.required,
                "status": item.status,
                "code": item.code,
                "evidence": dict(item.evidence),
            }
            for item in checks
        ],
        "boundary": {
            "allowed_changes": len(diff.allowed),
            "unexpected_changes": len(diff.unexpected),
            "changed_entries": len(diff.allowed) + len(diff.unexpected),
        },
        "coverage": {
            "mode": "final_state_snapshot",
            "entry_count_before": entry_count_before,
            "entry_count_after": entry_count_after,
            "causal_attribution": False,
            "runtime_write_tracing": False,
        },
        "privacy": {
            "profile": "public-safe",
            "raw_values_included": False,
            "absolute_paths_included": False,
            "unexpected_path_names_included": False,
        },
        "limitations": [
            "Point-in-time final-state comparison; transient writes are not observed.",
            "Changes during the observation window are not attributed to a specific process.",
            "Only declared watch roots and post-run checks are covered.",
            "The receipt is integrity-hashed but is not digitally signed.",
        ],
    }


def render_markdown(receipt: Mapping[str, Any], json_sha256: str) -> str:
    def markdown_text(value: Any) -> str:
        return "".join(f"&#{ord(character)};" for character in str(value))

    lines = [
        "# RunReconcile receipt",
        "",
        f"Verdict: **{receipt['verdict']}**",
        "",
        f"Project: {markdown_text(receipt['project']['public_label'])} (`{receipt['project']['id']}`)",
        f"Run ID: `{receipt['run']['id']}`",
        f"Contract SHA-256: `{receipt['contract']['sha256']}`",
        f"Receipt JSON SHA-256: `{json_sha256}`",
        "",
        "## Checks",
        "",
        "| ID | Public label | Type | Status | Code |",
        "|---|---|---|---|---|",
    ]
    for item in receipt["checks"]:
        label = markdown_text(item["public_label"])
        lines.append(
            f"| `{item['id']}` | {label} | {item['type']} | {item['status']} | `{item['code']}` |"
        )
    boundary = receipt["boundary"]
    lines.extend(
        [
            "",
            "## Final write surface",
            "",
            f"- Allowed changes: {boundary['allowed_changes']}",
            f"- Unexpected changes: {boundary['unexpected_changes']}",
            "",
            "## Coverage limitations",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in receipt["limitations"])
    lines.extend(["", "The JSON receipt is the machine-readable source of truth.", ""])
    return "\n".join(lines)


def write_receipt_directory(receipt: Mapping[str, Any], output_dir: Path) -> None:
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    created_output = False
    try:
        json_bytes = (
            json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        ).encode("utf-8")
        json_sha256 = hashlib.sha256(json_bytes).hexdigest()
        markdown = render_markdown(receipt, json_sha256).encode("utf-8")
        try:
            output_dir.mkdir(mode=0o700)
            created_output = True
        except FileExistsError as exc:
            raise ReceiptWriteError("receipt output directory already exists") from exc
        payloads = {
            "receipt.json": json_bytes,
            "receipt.md": markdown,
        }
        for name, payload in payloads.items():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY  # type: ignore[attr-defined]
            descriptor = os.open(str(output_dir / name), flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        marker = (
            json.dumps(
                {"complete": True, "receipt_json_sha256": json_sha256},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        descriptor, temporary_name = tempfile.mkstemp(prefix=".complete-", dir=str(output_dir))
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(marker)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary_name, output_dir / "complete.json")
            os.unlink(temporary_name)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
    except BaseException as exc:
        if created_output:
            try:
                shutil.rmtree(output_dir)
            except OSError:
                pass
        if isinstance(exc, ReceiptWriteError):
            raise
        raise ReceiptWriteError("unable to publish receipt directory") from exc
