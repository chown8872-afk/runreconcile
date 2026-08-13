from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from runreconcile.contract import ContractError, load_contract


VALID_CONTRACT = '''
schema_version = "1"
project_id = "sample-export"
public_label = "Sample export"

[privacy]
profile = "public-safe"

[[watch]]
id = "workspace"
root = "workspace"
allow = ["dist/**", ".runreconcile/**"]
max_file_bytes = 10485760

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


class ContractTests(unittest.TestCase):
    def write_contract(self, text: str) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / "runreconcile.toml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_loads_a_strict_public_safe_contract(self) -> None:
        contract = load_contract(self.write_contract(VALID_CONTRACT))

        self.assertEqual("sample-export", contract.project_id)
        self.assertEqual("public-safe", contract.privacy_profile)
        self.assertEqual("workspace", contract.watches[0].root.as_posix())
        self.assertEqual("artifact", contract.checks[0].type)

    def test_rejects_unknown_top_level_fields(self) -> None:
        path = self.write_contract(VALID_CONTRACT + '\ntelemetry = true\n')

        with self.assertRaisesRegex(ContractError, "unknown field"):
            load_contract(path)

    def test_rejects_absolute_and_parent_traversal_paths(self) -> None:
        absolute = self.write_contract(VALID_CONTRACT.replace('root = "workspace"', 'root = "/tmp"'))
        traversal = self.write_contract(
            VALID_CONTRACT.replace(
                'path = "workspace/dist/report.json"',
                'path = "../private/report.json"',
                1,
            )
        )

        with self.assertRaisesRegex(ContractError, "relative"):
            load_contract(absolute)
        with self.assertRaisesRegex(ContractError, "parent traversal"):
            load_contract(traversal)

    def test_rejects_duplicate_check_ids(self) -> None:
        duplicate = VALID_CONTRACT.replace('id = "read-only"', 'id = "report"')

        with self.assertRaisesRegex(ContractError, "duplicate check id"):
            load_contract(self.write_contract(duplicate))

    def test_rejects_invalid_json_pointer_during_validation(self) -> None:
        invalid = VALID_CONTRACT.replace('pointer = "/meta/read_only"', 'pointer = "/bad~2escape"')

        with self.assertRaisesRegex(ContractError, "JSON Pointer"):
            load_contract(self.write_contract(invalid))

    def test_rejects_checks_outside_declared_watch_roots(self) -> None:
        uncovered = VALID_CONTRACT.replace(
            'path = "workspace/dist/report.json"',
            'path = "other/report.json"',
        )

        with self.assertRaisesRegex(ContractError, "not covered"):
            load_contract(self.write_contract(uncovered))

    def test_rejects_overlapping_watch_roots(self) -> None:
        overlapping = VALID_CONTRACT.replace(
            '[[checks]]\nid = "report"',
            '''[[watch]]
id = "nested"
root = "workspace/dist"
allow = ["**"]
max_file_bytes = 10485760

[[checks]]
id = "report"''',
        )

        with self.assertRaisesRegex(ContractError, "overlap"):
            load_contract(self.write_contract(overlapping))

    def test_rejects_inverted_artifact_size_bounds(self) -> None:
        inverted = VALID_CONTRACT.replace(
            "min_bytes = 2",
            "min_bytes = 10\nmax_bytes = 2",
        )

        with self.assertRaisesRegex(ContractError, "min_bytes"):
            load_contract(self.write_contract(inverted))

    def test_rejects_file_only_constraints_on_directory_artifacts(self) -> None:
        directory = VALID_CONTRACT.replace('kind = "file"', 'kind = "directory"')

        with self.assertRaisesRegex(ContractError, "directory"):
            load_contract(self.write_contract(directory))


if __name__ == "__main__":
    unittest.main()
