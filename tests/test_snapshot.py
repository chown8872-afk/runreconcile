from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from runreconcile.contract import load_contract
from runreconcile.snapshot import (
    SnapshotError,
    diff_snapshots,
    load_snapshot,
    matches_any,
    save_snapshot,
    snapshot_contract,
    snapshot_from_dict,
)
import runreconcile.snapshot as snapshot_module


CONTRACT_TEMPLATE = '''
schema_version = "1"
project_id = "sample"
public_label = "Sample"
[privacy]
profile = "public-safe"
[[watch]]
id = "workspace"
root = "workspace"
allow = ["dist/**", ".runreconcile/**"]
max_file_bytes = {max_file_bytes}
[[checks]]
id = "report"
type = "artifact"
public_label = "report exists"
path = "workspace/dist/report.json"
kind = "file"
min_bytes = 2
'''


class SnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        (self.root / "workspace" / "dist").mkdir(parents=True)
        self.contract_path = self.root / "runreconcile.toml"
        self.contract_path.write_text(
            CONTRACT_TEMPLATE.format(max_file_bytes=1024 * 1024),
            encoding="utf-8",
        )
        self.contract = load_contract(self.contract_path)

    def test_diff_classifies_allowed_and_unexpected_final_changes(self) -> None:
        source = self.root / "workspace" / "source.txt"
        source.write_text("before", encoding="utf-8")
        before = snapshot_contract(self.contract, run_id="run-1")

        source.write_text("after", encoding="utf-8")
        (self.root / "workspace" / "dist" / "report.json").write_text("{}\n", encoding="utf-8")
        after = snapshot_contract(self.contract, run_id="run-1")
        result = diff_snapshots(self.contract, before, after)

        self.assertEqual(["dist/report.json"], [item.path for item in result.allowed])
        self.assertEqual(["source.txt"], [item.path for item in result.unexpected])
        self.assertEqual("created", result.allowed[0].change)
        self.assertEqual("content-modified", result.unexpected[0].change)

    def test_snapshot_represents_symlink_without_following_it(self) -> None:
        outside = self.root / "outside.txt"
        outside.write_text("private", encoding="utf-8")
        link = self.root / "workspace" / "link"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable")

        snapshot = snapshot_contract(self.contract, run_id="run-2")
        entry = snapshot.watches["workspace"].entries["link"]

        self.assertEqual("symlink", entry.kind)
        self.assertIsNotNone(entry.link_target_sha256)
        self.assertNotIn("private", json.dumps(snapshot.to_dict()))
        self.assertNotIn(str(self.root), json.dumps(snapshot.to_dict()))

    def test_snapshot_rejects_windows_reparse_directories(self) -> None:
        reparse_directory = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755,
            st_file_attributes=0x400,
            st_size=0,
            st_mtime_ns=0,
        )

        self.assertTrue(snapshot_module._is_reparse_point(reparse_directory))

    def test_refuses_to_silently_skip_oversized_files(self) -> None:
        self.contract_path.write_text(
            CONTRACT_TEMPLATE.format(max_file_bytes=3),
            encoding="utf-8",
        )
        contract = load_contract(self.contract_path)
        (self.root / "workspace" / "large.bin").write_bytes(b"1234")

        with self.assertRaisesRegex(SnapshotError, "max_file_bytes"):
            snapshot_contract(contract, run_id="run-3")

    def test_segment_glob_has_predictable_double_star_semantics(self) -> None:
        patterns = ("dist/**", "state/?.json")

        self.assertTrue(matches_any("dist/report.json", patterns))
        self.assertTrue(matches_any("dist/nested/report.json", patterns))
        self.assertTrue(matches_any("dist", patterns))
        self.assertTrue(matches_any("state/a.json", patterns))
        self.assertFalse(matches_any("state/ab.json", patterns))
        self.assertFalse(matches_any("other/dist/report.json", patterns))

    def test_rejects_a_cross_file_snapshot_that_changes_between_scans(self) -> None:
        first = self.root / "workspace" / "a.txt"
        second = self.root / "workspace" / "b.txt"
        first.write_text("before", encoding="utf-8")
        second.write_text("stable", encoding="utf-8")
        original_scan = snapshot_module._scan_directory
        calls = 0

        def changing_scan(root_fd, limit):
            nonlocal calls
            calls += 1
            result = original_scan(root_fd, limit)
            if calls == 1:
                first.write_text("after", encoding="utf-8")
            return result

        with mock.patch.object(snapshot_module, "_scan_directory", side_effect=changing_scan):
            with self.assertRaisesRegex(SnapshotError, "stable final-state snapshot"):
                snapshot_contract(self.contract, run_id="run-race")

    def test_rejects_a_watch_root_swapped_for_an_external_symlink(self) -> None:
        (self.root / "workspace" / "inside.txt").write_text("inside", encoding="utf-8")
        external = self.root / "external"
        external.mkdir()
        (external / "SECRET_CUSTOMER.txt").write_text("secret", encoding="utf-8")
        original_scan = snapshot_module._scan_directory
        original_root = self.root / "workspace-original"
        watch_root = self.root / "workspace"
        calls = 0

        def swapping_scan(root_fd, limit):
            nonlocal calls
            calls += 1
            result = original_scan(root_fd, limit)
            if calls == 1:
                watch_root.rename(original_root)
                try:
                    watch_root.symlink_to(external, target_is_directory=True)
                except (OSError, NotImplementedError):
                    original_root.rename(watch_root)
                    self.skipTest("directory symlinks are unavailable")
            return result

        with mock.patch.object(snapshot_module, "_scan_directory", side_effect=swapping_scan):
            with self.assertRaises(SnapshotError):
                snapshot_contract(self.contract, run_id="run-root-swap")

    def test_rejects_a_nested_directory_swapped_before_open(self) -> None:
        pivot = self.root / "workspace" / "pivot"
        pivot.mkdir()
        (pivot / "inside.txt").write_text("inside", encoding="utf-8")
        saved = self.root / "workspace" / "pivot-saved"
        external = self.root / "external-race"
        external.mkdir()
        (external / "SECRET_CUSTOMER.txt").write_text("secret", encoding="utf-8")
        real_open = os.open
        attempted = False

        def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal attempted
            if path == "pivot" and dir_fd is not None and flags & getattr(os, "O_DIRECTORY", 0):
                attempted = True
                pivot.rename(saved)
                try:
                    pivot.symlink_to(external, target_is_directory=True)
                except (OSError, NotImplementedError):
                    saved.rename(pivot)
                    self.skipTest("directory symlinks are unavailable")
                try:
                    return real_open(path, flags, mode, dir_fd=dir_fd)
                finally:
                    pivot.unlink()
                    saved.rename(pivot)
            if dir_fd is None:
                return real_open(path, flags, mode)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(snapshot_module.os, "open", side_effect=swapping_open):
            with self.assertRaises(SnapshotError):
                snapshot_contract(self.contract, run_id="run-nested-race")

        self.assertTrue(attempted)

    def test_rejects_an_intermediate_symlink_in_a_watch_root(self) -> None:
        outside = self.root / "outside-root"
        (outside / "workspace" / "dist").mkdir(parents=True)
        (outside / "workspace" / "dist" / "report.json").write_text("{}\n", encoding="utf-8")
        intermediate = self.root / "outer"
        try:
            intermediate.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlinks are unavailable")
        text = CONTRACT_TEMPLATE.format(max_file_bytes=1024 * 1024)
        text = text.replace('root = "workspace"', 'root = "outer/workspace"')
        text = text.replace('path = "workspace/dist/report.json"', 'path = "outer/workspace/dist/report.json"')
        self.contract_path.write_text(text, encoding="utf-8")
        contract = load_contract(self.contract_path)

        with self.assertRaises(SnapshotError):
            snapshot_contract(contract, run_id="intermediate-link")

    def test_snapshot_enforces_an_entry_count_limit(self) -> None:
        (self.root / "workspace" / "a.txt").write_text("a", encoding="utf-8")
        (self.root / "workspace" / "b.txt").write_text("b", encoding="utf-8")

        with mock.patch.object(snapshot_module, "MAX_SCAN_ENTRIES", 1):
            with self.assertRaisesRegex(SnapshotError, "entry count"):
                snapshot_contract(self.contract, run_id="entry-limit")

    def test_directory_permission_changes_are_not_ignored(self) -> None:
        directory = self.root / "workspace" / "private"
        directory.mkdir()
        directory.chmod(0o700)
        before = snapshot_contract(self.contract, run_id="run-mode")
        directory.chmod(0o755)
        after = snapshot_contract(self.contract, run_id="run-mode")

        result = diff_snapshots(self.contract, before, after)

        self.assertEqual(["private"], [item.path for item in result.unexpected])
        self.assertEqual("metadata-modified", result.unexpected[0].change)

    def test_watch_root_permission_changes_are_not_ignored(self) -> None:
        workspace = self.root / "workspace"
        workspace.chmod(0o700)
        before = snapshot_contract(self.contract, run_id="run-root-mode")
        workspace.chmod(0o755)
        after = snapshot_contract(self.contract, run_id="run-root-mode")

        result = diff_snapshots(self.contract, before, after)

        self.assertEqual(["."], [item.path for item in result.unexpected])
        self.assertEqual("metadata-modified", result.unexpected[0].change)

    def test_snapshot_publish_never_clobbers_an_existing_path(self) -> None:
        snapshot = snapshot_contract(self.contract, run_id="run-no-clobber")
        target = self.root / "baseline.json"
        target.write_text("competitor", encoding="utf-8")
        original_exists = Path.exists

        def stale_exists(path):
            if path == target:
                return False
            return original_exists(path)

        with mock.patch.object(Path, "exists", autospec=True, side_effect=stale_exists):
            with self.assertRaises(SnapshotError):
                save_snapshot(snapshot, target)

        self.assertEqual("competitor", target.read_text(encoding="utf-8"))

    def test_snapshot_timestamp_must_be_timezone_aware_rfc3339(self) -> None:
        raw = snapshot_contract(self.contract, run_id="run-time").to_dict()
        raw["created_at"] = "not-a-time"

        with self.assertRaisesRegex(SnapshotError, "timestamp"):
            snapshot_from_dict(raw)

    def test_baseline_read_enforces_limit_on_the_open_descriptor(self) -> None:
        path = self.root / "baseline.json"
        payload = json.dumps(snapshot_contract(self.contract, run_id="run-bounded").to_dict())
        path.write_text(payload, encoding="utf-8")
        fake_stat = SimpleNamespace(st_size=1)

        with mock.patch.object(Path, "stat", return_value=fake_stat):
            with self.assertRaisesRegex(SnapshotError, "size limit"):
                load_snapshot(path, max_bytes=1)


if __name__ == "__main__":
    unittest.main()
