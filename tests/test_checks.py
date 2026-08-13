from __future__ import annotations

import json
import sys
import tempfile
import os
import stat
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from runreconcile.checks import run_checks
from runreconcile.contract import load_contract
from runreconcile.snapshot import snapshot_contract


BASE = '''
schema_version = "1"
project_id = "sample"
public_label = "Sample"
[privacy]
profile = "public-safe"
[[watch]]
id = "workspace"
root = "workspace"
allow = ["dist/**"]
max_file_bytes = 1048576
'''


class CheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        (self.root / "workspace" / "dist").mkdir(parents=True)

    def contract(self, checks: str):
        path = self.root / "runreconcile.toml"
        path.write_text(BASE + checks, encoding="utf-8")
        return load_contract(path)

    def test_artifact_check_uses_post_snapshot_evidence(self) -> None:
        contract = self.contract('''
[[checks]]
id = "report"
type = "artifact"
public_label = "report exists"
path = "workspace/dist/report.json"
kind = "file"
min_bytes = 2
changed_since_snapshot = true
record_sha256 = true
''')
        before = snapshot_contract(contract, "run-artifact")
        (self.root / "workspace" / "dist" / "report.json").write_text("{}\n", encoding="utf-8")
        after = snapshot_contract(contract, "run-artifact")

        result = run_checks(contract, before, after)[0]

        self.assertEqual("pass", result.status)
        self.assertEqual(3, result.evidence["size_bytes"])
        self.assertRegex(result.evidence["sha256"], r"^[0-9a-f]{64}$")

    def test_json_equality_is_type_strict(self) -> None:
        (self.root / "workspace" / "dist" / "report.json").write_text(
            '{"value": true}\n',
            encoding="utf-8",
        )
        contract = self.contract('''
[[checks]]
id = "value"
type = "json"
public_label = "numeric value matches"
path = "workspace/dist/report.json"
pointer = "/value"
op = "eq"
expected = 1
''')
        before = snapshot_contract(contract, "run-json")
        after = snapshot_contract(contract, "run-json")

        result = run_checks(contract, before, after)[0]

        self.assertEqual("fail", result.status)
        self.assertEqual("assertion_not_satisfied", result.code)
        serialized = json.dumps(asdict(result)).lower()
        self.assertNotIn('"actual"', serialized)
        self.assertNotIn('"expected"', serialized)

    def test_duplicate_json_keys_are_an_error(self) -> None:
        (self.root / "workspace" / "dist" / "report.json").write_text(
            '{"status":"ok","status":"bad"}',
            encoding="utf-8",
        )
        contract = self.contract('''
[[checks]]
id = "status"
type = "json"
public_label = "status exists"
path = "workspace/dist/report.json"
pointer = "/status"
op = "exists"
''')
        before = snapshot_contract(contract, "run-duplicate")
        after = snapshot_contract(contract, "run-duplicate")

        result = run_checks(contract, before, after)[0]

        self.assertEqual("error", result.status)
        self.assertEqual("invalid_json", result.code)

    def test_delivery_check_matches_run_without_exposing_receipt_id(self) -> None:
        contract = self.contract('''
[[checks]]
id = "delivery"
type = "delivery"
public_label = "delivery provider returned a receipt"
path = "workspace/dist/delivery.json"
run_id_pointer = "/run_id"
status_pointer = "/status"
accepted_statuses = ["sent", "delivered"]
receipt_id_pointer = "/message_id"
''')
        before = snapshot_contract(contract, "run-delivery")
        secret_receipt = "SECRET-MESSAGE-ID-123"
        (self.root / "workspace" / "dist" / "delivery.json").write_text(
            json.dumps(
                {
                    "run_id": "run-delivery",
                    "status": "sent",
                    "message_id": secret_receipt,
                }
            ),
            encoding="utf-8",
        )
        after = snapshot_contract(contract, "run-delivery")

        result = run_checks(contract, before, after)[0]
        serialized = json.dumps(asdict(result), sort_keys=True)

        self.assertEqual("pass", result.status)
        self.assertTrue(result.evidence["receipt_id_present"])
        self.assertNotIn(secret_receipt, serialized)

    def test_check_rejects_a_symlink_escape(self) -> None:
        outside = self.root / "private.json"
        outside.write_text("{}", encoding="utf-8")
        link = self.root / "workspace" / "dist" / "report.json"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable")
        contract = self.contract('''
[[checks]]
id = "report"
type = "artifact"
public_label = "report exists"
path = "workspace/dist/report.json"
kind = "file"
''')
        before = snapshot_contract(contract, "run-link")
        after = snapshot_contract(contract, "run-link")

        result = run_checks(contract, before, after)[0]

        self.assertEqual("error", result.status)
        self.assertEqual("unsafe_path", result.code)

    def test_delivery_freshness_requires_content_change_not_only_touch(self) -> None:
        receipt = self.root / "workspace" / "dist" / "delivery.json"
        receipt.write_text(
            json.dumps({"run_id": "fixed-run", "status": "sent", "message_id": "old"}),
            encoding="utf-8",
        )
        contract = self.contract('''
[[checks]]
id = "delivery"
type = "delivery"
public_label = "fresh delivery"
path = "workspace/dist/delivery.json"
run_id_pointer = "/run_id"
status_pointer = "/status"
accepted_statuses = ["sent"]
receipt_id_pointer = "/message_id"
''')
        before = snapshot_contract(contract, "fixed-run")
        stat_before = receipt.stat()
        os.utime(receipt, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns + 1_000_000))
        after = snapshot_contract(contract, "fixed-run")

        result = run_checks(contract, before, after)[0]

        self.assertEqual("fail", result.status)
        self.assertEqual("receipt_not_changed", result.code)

    def test_artifact_freshness_requires_content_change_not_only_touch(self) -> None:
        report = self.root / "workspace" / "dist" / "report.json"
        report.write_text("{}\n", encoding="utf-8")
        contract = self.contract('''
[[checks]]
id = "report"
type = "artifact"
public_label = "fresh report"
path = "workspace/dist/report.json"
kind = "file"
changed_since_snapshot = true
''')
        before = snapshot_contract(contract, "artifact-touch")
        stat_before = report.stat()
        os.utime(report, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns + 1_000_000))
        after = snapshot_contract(contract, "artifact-touch")

        result = run_checks(contract, before, after)[0]

        self.assertEqual("fail", result.status)
        self.assertEqual("artifact_not_changed", result.code)

    def test_json_artifact_is_read_through_a_bounded_descriptor(self) -> None:
        report = self.root / "workspace" / "dist" / "report.json"
        report.write_text('{"status":"complete"}\n', encoding="utf-8")
        contract = self.contract('''
[[checks]]
id = "json"
type = "json"
public_label = "bounded JSON read"
path = "workspace/dist/report.json"
pointer = "/status"
op = "eq"
expected = "complete"
max_bytes = 1024
''')
        before = snapshot_contract(contract, "bounded-read")
        after = snapshot_contract(contract, "bounded-read")

        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read")):
            result = run_checks(contract, before, after)[0]

        self.assertEqual("pass", result.status)

    def test_artifact_rejects_parent_swap_during_descriptor_walk(self) -> None:
        report = self.root / "workspace" / "dist" / "report.json"
        report.write_text("trusted\n", encoding="utf-8")
        contract = self.contract('''
[[checks]]
id = "report"
type = "artifact"
public_label = "stable parent binding"
path = "workspace/dist/report.json"
kind = "file"
''')
        before = snapshot_contract(contract, "parent-swap")
        after = snapshot_contract(contract, "parent-swap")
        saved = self.root / "workspace" / "dist-saved"
        external = self.root / "outside"
        external.mkdir()
        (external / "report.json").write_text("untrusted\n", encoding="utf-8")
        real_open = os.open
        attempted = False

        def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal attempted
            if path == "dist" and dir_fd is not None and flags & getattr(os, "O_DIRECTORY", 0):
                attempted = True
                report.parent.rename(saved)
                try:
                    report.parent.symlink_to(external, target_is_directory=True)
                except (OSError, NotImplementedError):
                    saved.rename(report.parent)
                    self.skipTest("directory symlinks are unavailable")
                try:
                    return real_open(path, flags, mode, dir_fd=dir_fd)
                finally:
                    report.parent.unlink()
                    saved.rename(report.parent)
            if dir_fd is None:
                return real_open(path, flags, mode)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("runreconcile.checks.os.open", side_effect=swapping_open):
            result = run_checks(contract, before, after)[0]

        self.assertTrue(attempted)
        self.assertEqual("error", result.status)
        self.assertIn(result.code, {"unsafe_path", "unstable_artifact"})

    def test_directory_artifact_is_revalidated_after_the_final_snapshot(self) -> None:
        artifact = self.root / "workspace" / "dist" / "bundle"
        artifact.mkdir()
        contract = self.contract('''
[[checks]]
id = "bundle"
type = "artifact"
public_label = "bundle directory remains bound"
path = "workspace/dist/bundle"
kind = "directory"
''')
        before = snapshot_contract(contract, "directory-binding")
        after = snapshot_contract(contract, "directory-binding")
        saved = self.root / "workspace" / "dist" / "bundle-saved"
        external = self.root / "external-bundle"
        external.mkdir()
        artifact.rename(saved)
        try:
            artifact.symlink_to(external, target_is_directory=True)
        except (OSError, NotImplementedError):
            saved.rename(artifact)
            self.skipTest("directory symlinks are unavailable")

        result = run_checks(contract, before, after)[0]

        self.assertEqual("error", result.status)
        self.assertIn(result.code, {"unsafe_path", "unstable_artifact"})

    def test_file_check_revalidates_parent_bindings_after_read(self) -> None:
        report = self.root / "workspace" / "dist" / "report.json"
        report.write_text("trusted\n", encoding="utf-8")
        contract = self.contract('''
[[checks]]
id = "report"
type = "artifact"
public_label = "parent remains bound after read"
path = "workspace/dist/report.json"
kind = "file"
''')
        before = snapshot_contract(contract, "post-read-swap")
        after = snapshot_contract(contract, "post-read-swap")
        directory = report.parent
        saved = self.root / "workspace" / "dist-saved-after-open"
        external = self.root / "external-after-open"
        external.mkdir()
        (external / "report.json").write_text("untrusted\n", encoding="utf-8")
        real_read = os.read
        swapped = False

        def swapping_read(descriptor, count):
            nonlocal swapped
            if not swapped:
                swapped = True
                directory.rename(saved)
                try:
                    directory.symlink_to(external, target_is_directory=True)
                except (OSError, NotImplementedError):
                    saved.rename(directory)
                    self.skipTest("directory symlinks are unavailable")
            return real_read(descriptor, count)

        try:
            with mock.patch("runreconcile.checks.os.read", side_effect=swapping_read):
                result = run_checks(contract, before, after)[0]
        finally:
            if directory.is_symlink():
                directory.unlink()
                saved.rename(directory)

        self.assertTrue(swapped)
        self.assertEqual("error", result.status)
        self.assertEqual("unstable_artifact", result.code)


if __name__ == "__main__":
    unittest.main()
