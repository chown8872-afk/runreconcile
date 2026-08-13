from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from runreconcile.cli import main


CONTRACT = '''
schema_version = "1"
project_id = "sample"
public_label = "Sample reconciliation"
[privacy]
profile = "public-safe"
[[watch]]
id = "workspace"
root = "workspace"
allow = ["dist/**", ".runreconcile/**"]
max_file_bytes = 1048576
[[checks]]
id = "report"
type = "artifact"
public_label = "report exists"
path = "workspace/dist/report.json"
kind = "file"
min_bytes = 2
changed_since_snapshot = true
record_sha256 = true
[[checks]]
id = "read-only"
type = "json"
public_label = "report declares read-only mode"
path = "workspace/dist/report.json"
pointer = "/meta/read_only"
op = "eq"
expected = true
'''


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        (self.root / "workspace" / "dist").mkdir(parents=True)
        self.contract = self.root / "runreconcile.toml"
        self.contract.write_text(CONTRACT, encoding="utf-8")
        self.before = self.root / ".runreconcile" / "before.json"
        self.receipt_dir = self.root / ".runreconcile" / "receipt"

    def invoke(self, arguments):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def create_snapshot(self, run_id: str):
        code, output, error = self.invoke(
            ["snapshot", "-c", str(self.contract), "-o", str(self.before), "--run-id", run_id]
        )
        self.assertEqual(0, code, error)
        payload = json.loads(output)
        return payload["sha256"]

    def test_snapshot_then_verify_writes_consistent_public_safe_receipts(self) -> None:
        baseline_sha256 = self.create_snapshot("demo-run")
        self.assertTrue(self.before.exists())

        report = self.root / "workspace" / "dist" / "report.json"
        report.write_text('{"meta":{"read_only":true}}\n', encoding="utf-8")
        code, output, error = self.invoke(
            [
                "verify",
                "--contract",
                str(self.contract),
                "--before",
                str(self.before),
                "--before-sha256",
                baseline_sha256,
                "--output-dir",
                str(self.receipt_dir),
            ]
        )

        self.assertEqual(0, code, error)
        receipt = json.loads((self.receipt_dir / "receipt.json").read_text(encoding="utf-8"))
        markdown = (self.receipt_dir / "receipt.md").read_text(encoding="utf-8")
        self.assertEqual("ACCEPTED", receipt["verdict"])
        self.assertIn("ACCEPTED", markdown)
        self.assertEqual(receipt["summary"]["passed"], markdown.count("| pass |"))
        serialized = json.dumps(receipt) + markdown
        self.assertNotIn(str(self.root), serialized)
        self.assertNotIn("report.json", serialized)

    def test_unexpected_change_returns_boundary_violation_without_leaking_path(self) -> None:
        baseline_sha256 = self.create_snapshot("boundary-run")
        (self.root / "workspace" / "dist" / "report.json").write_text(
            '{"meta":{"read_only":true}}\n',
            encoding="utf-8",
        )
        secret_name = "SECRET_CUSTOMER_NAME.txt"
        (self.root / "workspace" / secret_name).write_text("sensitive", encoding="utf-8")

        code, _, error = self.invoke(
            [
                "verify",
                "-c",
                str(self.contract),
                "-b",
                str(self.before),
                "--before-sha256",
                baseline_sha256,
                "-o",
                str(self.receipt_dir),
            ]
        )

        self.assertEqual(1, code, error)
        public_output = (self.receipt_dir / "receipt.json").read_text() + (self.receipt_dir / "receipt.md").read_text()
        self.assertIn("BOUNDARY_VIOLATION", public_output)
        self.assertNotIn(secret_name, public_output)

    def test_invalid_contract_returns_usage_error_without_traceback(self) -> None:
        self.contract.write_text(CONTRACT + "\ntelemetry = true\n", encoding="utf-8")

        code, _, error = self.invoke(["validate", "-c", str(self.contract)])

        self.assertEqual(2, code)
        self.assertIn("invalid contract", error.lower())
        self.assertNotIn("Traceback", error)

    def test_refuses_to_overwrite_an_existing_receipt_directory(self) -> None:
        baseline_sha256 = self.create_snapshot("no-overwrite")
        (self.root / "workspace" / "dist" / "report.json").write_text(
            '{"meta":{"read_only":true}}\n',
            encoding="utf-8",
        )
        self.receipt_dir.mkdir(parents=True)
        marker = self.receipt_dir / "keep.txt"
        marker.write_text("keep", encoding="utf-8")

        code, _, error = self.invoke(
            [
                "verify",
                "-c",
                str(self.contract),
                "-b",
                str(self.before),
                "--before-sha256",
                baseline_sha256,
                "-o",
                str(self.receipt_dir),
            ]
        )

        self.assertEqual(3, code)
        self.assertEqual("keep", marker.read_text(encoding="utf-8"))
        self.assertIn("already exists", error)

    def test_tampered_baseline_is_rejected_by_external_digest(self) -> None:
        baseline_sha256 = self.create_snapshot("tamper-run")
        baseline = json.loads(self.before.read_text(encoding="utf-8"))
        baseline["run_id"] = "attacker-controlled"
        self.before.write_text(json.dumps(baseline), encoding="utf-8")

        code, _, error = self.invoke(
            [
                "verify",
                "-c",
                str(self.contract),
                "-b",
                str(self.before),
                "--before-sha256",
                baseline_sha256,
                "-o",
                str(self.receipt_dir),
            ]
        )

        self.assertEqual(3, code)
        self.assertIn("digest mismatch", error)
        self.assertFalse(self.receipt_dir.exists())

    def test_snapshot_errors_do_not_echo_sensitive_file_names(self) -> None:
        self.contract.write_text(CONTRACT.replace("1048576", "3"), encoding="utf-8")
        secret_name = "SECRET_CUSTOMER_NAME.txt"
        (self.root / "workspace" / secret_name).write_bytes(b"1234")

        code, _, error = self.invoke(
            ["snapshot", "-c", str(self.contract), "-o", str(self.before), "--run-id", "private-error"]
        )

        self.assertEqual(3, code)
        self.assertNotIn(secret_name, error)
        self.assertEqual("snapshot error: unable to create a complete snapshot\n", error)

    def test_run_id_rejects_markdown_and_newline_injection(self) -> None:
        code, _, error = self.invoke(
            [
                "snapshot",
                "-c",
                str(self.contract),
                "-o",
                str(self.before),
                "--run-id",
                "ok\n# forged receipt",
            ]
        )

        self.assertEqual(3, code)
        self.assertFalse(self.before.exists())
        self.assertEqual("snapshot error: unable to create a complete snapshot\n", error)


if __name__ == "__main__":
    unittest.main()
