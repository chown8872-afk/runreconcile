from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from runreconcile.checks import CheckResult
from runreconcile.receipt import ReceiptWriteError, make_receipt, render_markdown, write_receipt_directory
from runreconcile.snapshot import Change, DiffResult


class ReceiptTests(unittest.TestCase):
    def test_required_errors_are_indeterminate(self) -> None:
        result = CheckResult(
            id="report",
            type="artifact",
            public_label="report exists",
            required=True,
            status="error",
            code="unstable_artifact",
            evidence={},
        )

        receipt = make_receipt(
            project_id="demo",
            public_label="Demo",
            run_id="run-1",
            started_at="2026-08-13T00:00:00Z",
            finished_at="2026-08-13T00:00:01Z",
            contract_sha256="a" * 64,
            checks=(result,),
            diff=DiffResult((), ()),
            entry_count_before=1,
            entry_count_after=1,
        )

        self.assertEqual("INDETERMINATE", receipt["verdict"])

    def test_known_boundary_violation_takes_precedence(self) -> None:
        result = CheckResult("report", "artifact", "report", True, "fail", "artifact_missing", {})
        diff = DiffResult((), (Change("workspace", "private/name.txt", "created"),))

        receipt = make_receipt(
            project_id="demo",
            public_label="Demo",
            run_id="run-2",
            started_at="2026-08-13T00:00:00Z",
            finished_at="2026-08-13T00:00:01Z",
            contract_sha256="b" * 64,
            checks=(result,),
            diff=diff,
            entry_count_before=1,
            entry_count_after=2,
        )

        self.assertEqual("BOUNDARY_VIOLATION", receipt["verdict"])
        self.assertEqual(1, receipt["boundary"]["unexpected_changes"])
        self.assertNotIn("name.txt", str(receipt))

    def test_markdown_escapes_public_labels_as_data(self) -> None:
        result = CheckResult("report", "artifact", "<h1>forged</h1>", True, "pass", "satisfied", {})
        receipt = make_receipt(
            project_id="demo",
            public_label="<script>alert(1)</script>",
            run_id="run-3",
            started_at="2026-08-13T00:00:00Z",
            finished_at="2026-08-13T00:00:01Z",
            contract_sha256="c" * 64,
            checks=(result,),
            diff=DiffResult((), ()),
            entry_count_before=1,
            entry_count_after=1,
        )

        markdown = render_markdown(receipt, "d" * 64)

        self.assertNotIn("<script>", markdown)
        self.assertNotIn("<h1>", markdown)
        self.assertIn("&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;", markdown)

    def test_markdown_disables_image_and_link_syntax_in_labels(self) -> None:
        injected = "![tracking pixel](https://example.invalid/pixel)"
        result = CheckResult("report", "artifact", injected, True, "pass", "satisfied", {})
        receipt = make_receipt(
            project_id="demo",
            public_label=injected,
            run_id="run-markdown",
            started_at="2026-08-13T00:00:00Z",
            finished_at="2026-08-13T00:00:01Z",
            contract_sha256="f" * 64,
            checks=(result,),
            diff=DiffResult((), ()),
            entry_count_before=1,
            entry_count_after=1,
        )

        markdown = render_markdown(receipt, "a" * 64)

        self.assertNotIn(injected, markdown)
        self.assertNotIn("![tracking", markdown)

    def test_receipt_publish_never_replaces_an_existing_empty_directory(self) -> None:
        receipt = make_receipt(
            project_id="demo",
            public_label="Demo",
            run_id="run-4",
            started_at="2026-08-13T00:00:00Z",
            finished_at="2026-08-13T00:00:01Z",
            contract_sha256="e" * 64,
            checks=(),
            diff=DiffResult((), ()),
            entry_count_before=0,
            entry_count_after=0,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "receipt"
            target.mkdir()
            original_exists = Path.exists

            def stale_exists(path):
                if path == target:
                    return False
                return original_exists(path)

            with mock.patch.object(Path, "exists", autospec=True, side_effect=stale_exists):
                with self.assertRaises(ReceiptWriteError):
                    write_receipt_directory(receipt, target)

            self.assertEqual([], list(target.iterdir()))

    def test_completion_marker_is_published_only_after_full_write(self) -> None:
        receipt = make_receipt(
            project_id="demo",
            public_label="Demo",
            run_id="run-complete",
            started_at="2026-08-13T00:00:00Z",
            finished_at="2026-08-13T00:00:01Z",
            contract_sha256="a" * 64,
            checks=(),
            diff=DiffResult((), ()),
            entry_count_before=0,
            entry_count_after=0,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "receipt"
            real_link = os.link
            observed = []

            def inspect_then_link(source, destination, *args, **kwargs):
                destination_path = Path(destination)
                if destination_path.name == "complete.json":
                    self.assertFalse(destination_path.exists())
                    marker = json.loads(Path(source).read_text(encoding="utf-8"))
                    self.assertTrue(marker["complete"])
                    observed.append(True)
                return real_link(source, destination, *args, **kwargs)

            with mock.patch("runreconcile.receipt.os.link", side_effect=inspect_then_link):
                write_receipt_directory(receipt, target)

            self.assertEqual([True], observed)


if __name__ == "__main__":
    unittest.main()
