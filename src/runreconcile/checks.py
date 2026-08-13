"""Read-only post-run checks whose public results omit raw values and paths."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from .contract import CheckSpec, Contract, WatchSpec
from .json_pointer import JsonPointerError, resolve_pointer
from .posix_fs import (
    DirectoryChain,
    FilesystemSafetyError,
    file_flags,
    identity,
    is_reparse_point,
    open_directory_chain,
)
from .snapshot import DiffResult, Entry, Snapshot, diff_snapshots


@dataclass(frozen=True)
class CheckResult:
    id: str
    type: str
    public_label: str
    required: bool
    status: str
    code: str
    evidence: Mapping[str, Any]


class _CheckError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _DuplicateKey(ValueError):
    pass


def _open_chain(contract: Contract, parts: Tuple[str, ...]) -> DirectoryChain:
    try:
        return open_directory_chain(
            contract.source.parent,
            parts,
            expected_base=(contract.base_device, contract.base_inode),
        )
    except (FilesystemSafetyError, OSError) as exc:
        raise _CheckError("unsafe_path") from exc


def _open_regular_beneath(
    contract: Contract,
    relative: Path,
) -> Tuple[int, os.stat_result, DirectoryChain, str]:
    if not relative.parts:
        raise _CheckError("unsafe_path")
    chain = _open_chain(contract, relative.parts[:-1])
    name = relative.parts[-1]
    descriptor: Optional[int] = None
    try:
        before = os.stat(name, dir_fd=chain.leaf_fd, follow_symlinks=False)
        descriptor = os.open(name, file_flags(), dir_fd=chain.leaf_fd)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or is_reparse_point(before)
            or is_reparse_point(opened)
            or identity(before) != identity(opened)
        ):
            os.close(descriptor)
            raise _CheckError("unsafe_path")
        return descriptor, opened, chain, name
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        chain.close()
        raise _CheckError("unstable_artifact") from exc
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        chain.close()
        raise


def _covered_entry(
    contract: Contract,
    snapshot: Snapshot,
    relative: Path,
) -> Tuple[WatchSpec, str, Optional[Entry]]:
    candidates = []
    for watch in contract.watches:
        try:
            nested = relative.relative_to(watch.root).as_posix()
        except ValueError:
            continue
        if nested == ".":
            continue
        candidates.append((len(watch.root.parts), watch, nested))
    if not candidates:
        raise _CheckError("uncovered_path")
    _, watch, nested = max(candidates, key=lambda item: item[0])
    return watch, nested, snapshot.watches[watch.id].entries.get(nested)


def _file_bytes(contract: Contract, relative: Path, entry: Entry, max_bytes: int) -> bytes:
    if entry.kind != "file":
        raise _CheckError("wrong_kind")
    if entry.size_bytes is None or entry.size_bytes > max_bytes:
        raise _CheckError("file_too_large")
    descriptor, before, chain, name = _open_regular_beneath(contract, relative)
    chunks = []
    total = 0
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise _CheckError("unsafe_path")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise _CheckError("unstable_artifact")
        while True:
            block = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > max_bytes:
                raise _CheckError("file_too_large")
        after = os.fstat(descriptor)
        rebound = os.stat(name, dir_fd=chain.leaf_fd, follow_symlinks=False)
        chain.revalidate()
    except OSError as exc:
        raise _CheckError("unstable_artifact") from exc
    except FilesystemSafetyError as exc:
        raise _CheckError("unstable_artifact") from exc
    finally:
        try:
            os.close(descriptor)
        finally:
            chain.close()
    data = b"".join(chunks)
    observed = hashlib.sha256(data).hexdigest()
    stable = (
        identity(before) == identity(after) == identity(rebound)
        and before.st_size == after.st_size == rebound.st_size == len(data) == entry.size_bytes
        and before.st_mtime_ns == after.st_mtime_ns == rebound.st_mtime_ns == entry.mtime_ns
        and stat.S_IMODE(after.st_mode) == stat.S_IMODE(rebound.st_mode) == entry.mode
        and observed == entry.sha256
    )
    if not stable:
        raise _CheckError("unstable_artifact")
    return data


def _verify_directory(contract: Contract, relative: Path, entry: Entry) -> None:
    chain = _open_chain(contract, relative.parts)
    try:
        before = os.fstat(chain.leaf_fd)
        if (
            not stat.S_ISDIR(before.st_mode)
            or is_reparse_point(before)
            or stat.S_IMODE(before.st_mode) != entry.mode
            or before.st_mtime_ns != entry.mtime_ns
        ):
            raise _CheckError("unstable_artifact")
        chain.revalidate()
        after = os.fstat(chain.leaf_fd)
        if (
            identity(before) != identity(after)
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_mode != after.st_mode
        ):
            raise _CheckError("unstable_artifact")
    except FilesystemSafetyError as exc:
        raise _CheckError("unstable_artifact") from exc
    except OSError as exc:
        raise _CheckError("unstable_artifact") from exc
    finally:
        chain.close()


def _strict_json(data: bytes) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise _DuplicateKey(key)
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("non-standard JSON number")

    try:
        text = data.decode("utf-8")
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError) as exc:
        raise _CheckError("invalid_json") from exc


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _strict_equal(left: Any, right: Any) -> bool:
    return _type_name(left) == _type_name(right) and left == right


def _numeric(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _assertion(document: Any, pointer: str, operation: str, expected: Any = None) -> bool:
    try:
        found, actual = resolve_pointer(document, pointer)
    except JsonPointerError as exc:
        raise _CheckError("invalid_pointer") from exc
    if operation == "exists":
        return found
    if operation == "absent":
        return not found
    if not found:
        return False
    if operation == "eq":
        return _strict_equal(actual, expected)
    if operation == "ne":
        return not _strict_equal(actual, expected)
    if operation in {"gt", "gte", "lt", "lte"}:
        if not (_numeric(actual) and _numeric(expected)):
            return False
        return {
            "gt": actual > expected,
            "gte": actual >= expected,
            "lt": actual < expected,
            "lte": actual <= expected,
        }[operation]
    if operation == "type":
        return isinstance(expected, str) and _type_name(actual) == expected
    if operation == "in":
        return isinstance(expected, list) and any(_strict_equal(actual, item) for item in expected)
    if operation == "contains":
        if isinstance(actual, list):
            return any(_strict_equal(expected, item) for item in actual)
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual
        if isinstance(actual, dict) and isinstance(expected, str):
            return expected in actual
        return False
    if operation == "length_eq":
        return (
            isinstance(expected, int)
            and not isinstance(expected, bool)
            and isinstance(actual, (str, list, dict))
            and len(actual) == expected
        )
    raise _CheckError("unsupported_operation")


def _changed(diff: DiffResult, watch_id: str, nested: str) -> bool:
    return any(item.watch_id == watch_id and item.path == nested for item in diff.all_changes)


def _content_changed(before: Snapshot, after: Snapshot, watch_id: str, nested: str) -> bool:
    before_entry = before.watches[watch_id].entries.get(nested)
    after_entry = after.watches[watch_id].entries.get(nested)
    if before_entry is None or after_entry is None:
        return before_entry != after_entry
    if before_entry.kind != after_entry.kind:
        return True
    if before_entry.kind == "file":
        return before_entry.sha256 != after_entry.sha256
    if before_entry.kind == "symlink":
        return before_entry.link_target_sha256 != after_entry.link_target_sha256
    return False


def _artifact(
    contract: Contract,
    check: CheckSpec,
    before: Snapshot,
    after: Snapshot,
    diff: DiffResult,
) -> CheckResult:
    watch, nested, entry = _covered_entry(contract, after, check.options["path"])
    if entry is None:
        return _result(check, "fail", "artifact_missing")
    if entry.kind == "symlink":
        raise _CheckError("unsafe_path")
    expected_kind = check.options.get("kind", "file")
    if entry.kind != expected_kind:
        return _result(check, "fail", "wrong_kind")
    if check.options.get("changed_since_snapshot") and not _content_changed(before, after, watch.id, nested):
        return _result(check, "fail", "artifact_not_changed")
    evidence: Dict[str, Any] = {"kind": entry.kind}
    if entry.kind == "file":
        if entry.size_bytes is None:
            raise _CheckError("unstable_artifact")
        minimum = check.options.get("min_bytes")
        maximum = check.options.get("max_bytes")
        if minimum is not None and entry.size_bytes < minimum:
            return _result(check, "fail", "artifact_too_small")
        if maximum is not None and entry.size_bytes > maximum:
            return _result(check, "fail", "artifact_too_large")
        evidence["size_bytes"] = entry.size_bytes
        read_limit = min(watch.max_file_bytes, maximum) if maximum is not None else watch.max_file_bytes
        _file_bytes(contract, check.options["path"], entry, read_limit)
        if "sha256" in check.options and entry.sha256 != check.options["sha256"]:
            return _result(check, "fail", "digest_mismatch")
        if check.options.get("record_sha256"):
            evidence["sha256"] = entry.sha256
    else:
        _verify_directory(contract, check.options["path"], entry)
    return _result(check, "pass", "satisfied", evidence)


def _json_check(
    contract: Contract,
    check: CheckSpec,
    before: Snapshot,
    after: Snapshot,
    diff: DiffResult,
) -> CheckResult:
    watch, nested, entry = _covered_entry(contract, after, check.options["path"])
    if entry is None:
        return _result(check, "fail", "artifact_missing")
    if check.options.get("changed_since_snapshot") and not _content_changed(before, after, watch.id, nested):
        return _result(check, "fail", "artifact_not_changed")
    maximum = min(check.options.get("max_bytes", watch.max_file_bytes), watch.max_file_bytes)
    document = _strict_json(_file_bytes(contract, check.options["path"], entry, maximum))
    passed = _assertion(
        document,
        check.options["pointer"],
        check.options["op"],
        check.options.get("expected"),
    )
    return _result(
        check,
        "pass" if passed else "fail",
        "satisfied" if passed else "assertion_not_satisfied",
        {"assertion_evaluated": True},
    )


def _delivery(
    contract: Contract,
    check: CheckSpec,
    before: Snapshot,
    after: Snapshot,
    diff: DiffResult,
) -> CheckResult:
    watch, nested, entry = _covered_entry(contract, after, check.options["path"])
    if entry is None:
        return _result(check, "fail", "receipt_missing")
    if check.options.get("changed_since_snapshot") and not _content_changed(before, after, watch.id, nested):
        return _result(check, "fail", "receipt_not_changed")
    maximum = min(check.options.get("max_bytes", watch.max_file_bytes), watch.max_file_bytes)
    document = _strict_json(_file_bytes(contract, check.options["path"], entry, maximum))
    try:
        run_found, receipt_run_id = resolve_pointer(document, check.options["run_id_pointer"])
        status_found, receipt_status = resolve_pointer(document, check.options["status_pointer"])
        id_found, receipt_id = resolve_pointer(document, check.options["receipt_id_pointer"])
    except JsonPointerError as exc:
        raise _CheckError("invalid_pointer") from exc
    if not run_found or receipt_run_id != before.run_id:
        return _result(check, "fail", "run_id_mismatch")
    if not status_found or receipt_status not in check.options["accepted_statuses"]:
        return _result(check, "fail", "delivery_status_not_accepted")
    receipt_present = id_found and isinstance(receipt_id, str) and bool(receipt_id)
    if not receipt_present:
        return _result(check, "fail", "receipt_id_missing")
    return _result(
        check,
        "pass",
        "satisfied",
        {"accepted_status": True, "receipt_id_present": True},
    )


def _result(
    check: CheckSpec,
    status: str,
    code: str,
    evidence: Optional[Mapping[str, Any]] = None,
) -> CheckResult:
    return CheckResult(
        id=check.id,
        type=check.type,
        public_label=check.public_label,
        required=check.required,
        status=status,
        code=code,
        evidence=dict(evidence or {}),
    )


def run_checks(contract: Contract, before: Snapshot, after: Snapshot) -> Tuple[CheckResult, ...]:
    diff = diff_snapshots(contract, before, after)
    results = []
    implementations = {
        "artifact": _artifact,
        "json": _json_check,
        "delivery": _delivery,
    }
    for check in contract.checks:
        try:
            result = implementations[check.type](contract, check, before, after, diff)
        except _CheckError as exc:
            result = _result(check, "error", exc.code)
        except (OSError, ValueError):
            result = _result(check, "error", "check_error")
        results.append(result)
    return tuple(results)
