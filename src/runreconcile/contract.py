"""Strict, non-executable contract loading for RunReconcile."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Mapping, Tuple

from .json_pointer import JsonPointerError, validate_pointer
from .posix_fs import descriptor_support_available

try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # Python 3.9-3.10
    import tomli as tomllib  # type: ignore[no-redef]


class ContractError(ValueError):
    """Raised when a contract is ambiguous, unsafe, or unsupported."""


@dataclass(frozen=True)
class WatchSpec:
    id: str
    root: Path
    allow: Tuple[str, ...]
    max_file_bytes: int


@dataclass(frozen=True)
class CheckSpec:
    id: str
    type: str
    public_label: str
    required: bool
    options: Mapping[str, Any]


@dataclass(frozen=True)
class Contract:
    source: Path
    base_device: int
    base_inode: int
    sha256: str
    schema_version: str
    project_id: str
    public_label: str
    privacy_profile: str
    watches: Tuple[WatchSpec, ...]
    checks: Tuple[CheckSpec, ...]


_TOP_LEVEL_FIELDS = {
    "schema_version",
    "project_id",
    "public_label",
    "privacy",
    "watch",
    "checks",
}
_PRIVACY_FIELDS = {"profile"}
_WATCH_FIELDS = {"id", "root", "allow", "max_file_bytes"}
_COMMON_CHECK_FIELDS = {"id", "type", "public_label", "required"}
_CHECK_FIELDS = {
    "artifact": _COMMON_CHECK_FIELDS
    | {
        "path",
        "kind",
        "min_bytes",
        "max_bytes",
        "changed_since_snapshot",
        "record_sha256",
        "sha256",
    },
    "json": _COMMON_CHECK_FIELDS
    | {
        "path",
        "pointer",
        "op",
        "expected",
        "changed_since_snapshot",
        "max_bytes",
    },
    "delivery": _COMMON_CHECK_FIELDS
    | {
        "path",
        "run_id_pointer",
        "status_pointer",
        "accepted_statuses",
        "receipt_id_pointer",
        "changed_since_snapshot",
        "max_bytes",
    },
}
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_JSON_OPS = {"exists", "absent", "eq", "ne", "gt", "gte", "lt", "lte", "type", "in", "contains", "length_eq"}
_JSON_TYPES = {"null", "boolean", "integer", "number", "string", "array", "object"}


def _unknown_fields(value: Mapping[str, Any], allowed: set[str], location: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ContractError(f"{location}: unknown field(s): {', '.join(unknown)}")


def _identifier(value: Any, location: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ContractError(f"{location}: must match {_ID_RE.pattern}")
    return value


def _label(value: Any, location: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 120
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ContractError(f"{location}: must be a single non-empty line of at most 120 characters")
    return value.strip()


def _safe_relative_path(value: Any, location: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{location}: path must be a non-empty relative string")
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or re.match(r"^[A-Za-z]:", normalized):
        raise ContractError(f"{location}: path must be relative")
    if ".." in path.parts:
        raise ContractError(f"{location}: parent traversal is not allowed")
    if any(part in {"", "."} for part in path.parts):
        if normalized != ".":
            raise ContractError(f"{location}: path contains an empty or ambiguous segment")
    return Path(*path.parts)


def _safe_pattern(value: Any, location: str) -> str:
    path = _safe_relative_path(value, location).as_posix()
    if "[" in path or "]" in path:
        raise ContractError(f"{location}: character classes are unsupported; use *, ?, or **")
    for segment in path.split("/"):
        if "**" in segment and segment != "**":
            raise ContractError(f"{location}: ** must occupy a complete path segment")
    return path


def _positive_int(value: Any, location: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError(f"{location}: must be an integer >= {minimum}")
    return value


def _optional_bool(value: Mapping[str, Any], key: str, default: bool, location: str) -> bool:
    result = value.get(key, default)
    if not isinstance(result, bool):
        raise ContractError(f"{location}.{key}: must be true or false")
    return result


def _parse_watch(raw: Any, index: int) -> WatchSpec:
    location = f"watch[{index}]"
    if not isinstance(raw, dict):
        raise ContractError(f"{location}: must be a table")
    _unknown_fields(raw, _WATCH_FIELDS, location)
    watch_id = _identifier(raw.get("id"), f"{location}.id")
    root = _safe_relative_path(raw.get("root"), f"{location}.root")
    allow_raw = raw.get("allow")
    if not isinstance(allow_raw, list) or not allow_raw:
        raise ContractError(f"{location}.allow: must be a non-empty array")
    allow = tuple(_safe_pattern(item, f"{location}.allow") for item in allow_raw)
    max_file_bytes = _positive_int(
        raw.get("max_file_bytes", 50 * 1024 * 1024),
        f"{location}.max_file_bytes",
    )
    return WatchSpec(watch_id, root, allow, max_file_bytes)


def _require_path(raw: Mapping[str, Any], location: str) -> Path:
    return _safe_relative_path(raw.get("path"), f"{location}.path")


def _json_pointer(value: Any, location: str, *, allow_root: bool) -> str:
    if not isinstance(value, str):
        raise ContractError(f"{location}: must be an RFC 6901 JSON Pointer")
    try:
        validate_pointer(value, allow_root=allow_root)
    except JsonPointerError as exc:
        raise ContractError(f"{location}: invalid RFC 6901 JSON Pointer") from exc
    return value


def _parse_check(raw: Any, index: int) -> CheckSpec:
    location = f"checks[{index}]"
    if not isinstance(raw, dict):
        raise ContractError(f"{location}: must be a table")
    check_type = raw.get("type")
    if check_type not in _CHECK_FIELDS:
        raise ContractError(f"{location}.type: unsupported check type {check_type!r}")
    _unknown_fields(raw, _CHECK_FIELDS[check_type], location)
    check_id = _identifier(raw.get("id"), f"{location}.id")
    public_label = _label(raw.get("public_label"), f"{location}.public_label")
    required = _optional_bool(raw, "required", True, location)
    options: Dict[str, Any] = {key: value for key, value in raw.items() if key not in _COMMON_CHECK_FIELDS}
    options["path"] = _require_path(raw, location)

    if check_type == "artifact":
        kind = raw.get("kind", "file")
        if kind not in {"file", "directory"}:
            raise ContractError(f"{location}.kind: must be file or directory")
        options["kind"] = kind
        for key in ("min_bytes", "max_bytes"):
            if key in raw:
                options[key] = _positive_int(raw[key], f"{location}.{key}", minimum=0)
        if (
            "min_bytes" in options
            and "max_bytes" in options
            and options["min_bytes"] > options["max_bytes"]
        ):
            raise ContractError(f"{location}.min_bytes: must be <= max_bytes")
        for key, default in (("changed_since_snapshot", False), ("record_sha256", False)):
            options[key] = _optional_bool(raw, key, default, location)
        if "sha256" in raw:
            digest = raw["sha256"]
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ContractError(f"{location}.sha256: must be 64 lowercase hexadecimal characters")
        if kind == "directory":
            unsupported = [
                key
                for key in ("min_bytes", "max_bytes", "record_sha256", "sha256")
                if key in raw
            ]
            if unsupported:
                raise ContractError(
                    f"{location}: directory artifacts do not support {', '.join(unsupported)}"
                )

    elif check_type == "json":
        options["pointer"] = _json_pointer(raw.get("pointer"), f"{location}.pointer", allow_root=True)
        op = raw.get("op")
        if op not in _JSON_OPS:
            raise ContractError(f"{location}.op: unsupported operation {op!r}")
        if op not in {"exists", "absent"} and "expected" not in raw:
            raise ContractError(f"{location}.expected: required for operation {op}")
        expected = raw.get("expected")
        if op in {"gt", "gte", "lt", "lte"} and (
            isinstance(expected, bool) or not isinstance(expected, (int, float))
        ):
            raise ContractError(f"{location}.expected: must be a number for operation {op}")
        if op == "type" and expected not in _JSON_TYPES:
            raise ContractError(f"{location}.expected: unsupported JSON type")
        if op == "in" and not isinstance(expected, list):
            raise ContractError(f"{location}.expected: must be an array for operation in")
        if op == "length_eq" and (
            isinstance(expected, bool) or not isinstance(expected, int) or expected < 0
        ):
            raise ContractError(f"{location}.expected: must be an integer >= 0 for operation length_eq")
        options["changed_since_snapshot"] = _optional_bool(raw, "changed_since_snapshot", False, location)
        if "max_bytes" in raw:
            options["max_bytes"] = _positive_int(raw["max_bytes"], f"{location}.max_bytes")

    elif check_type == "delivery":
        for key in ("run_id_pointer", "status_pointer", "receipt_id_pointer"):
            options[key] = _json_pointer(raw.get(key), f"{location}.{key}", allow_root=False)
        statuses = raw.get("accepted_statuses")
        if not isinstance(statuses, list) or not statuses or any(not isinstance(item, str) or not item for item in statuses):
            raise ContractError(f"{location}.accepted_statuses: must be a non-empty string array")
        options["accepted_statuses"] = tuple(statuses)
        options["changed_since_snapshot"] = _optional_bool(raw, "changed_since_snapshot", True, location)
        if "max_bytes" in raw:
            options["max_bytes"] = _positive_int(raw["max_bytes"], f"{location}.max_bytes")

    return CheckSpec(check_id, check_type, public_label, required, options)


def load_contract(path: Path) -> Contract:
    if not descriptor_support_available():
        raise ContractError("this release requires POSIX descriptor-relative filesystem support")
    source = path.resolve(strict=True)
    base_info = source.parent.stat()
    if not source.parent.is_dir():
        raise ContractError("contract directory is not a directory")
    raw_bytes = source.read_bytes()
    try:
        parsed = tomllib.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ContractError(f"invalid TOML contract: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ContractError("contract root must be a table")
    _unknown_fields(parsed, _TOP_LEVEL_FIELDS, "contract")
    if parsed.get("schema_version") != "1":
        raise ContractError("schema_version: only version \"1\" is supported")
    project_id = _identifier(parsed.get("project_id"), "project_id")
    public_label = _label(parsed.get("public_label"), "public_label")

    privacy = parsed.get("privacy")
    if not isinstance(privacy, dict):
        raise ContractError("privacy: table is required")
    _unknown_fields(privacy, _PRIVACY_FIELDS, "privacy")
    if privacy.get("profile") != "public-safe":
        raise ContractError('privacy.profile: only "public-safe" is supported')

    watches_raw = parsed.get("watch")
    checks_raw = parsed.get("checks")
    if not isinstance(watches_raw, list) or not watches_raw:
        raise ContractError("watch: at least one watch table is required")
    if not isinstance(checks_raw, list) or not checks_raw:
        raise ContractError("checks: at least one check table is required")
    watches = tuple(_parse_watch(item, index) for index, item in enumerate(watches_raw))
    checks = tuple(_parse_check(item, index) for index, item in enumerate(checks_raw))

    watch_ids = [item.id for item in watches]
    check_ids = [item.id for item in checks]
    if len(watch_ids) != len(set(watch_ids)):
        raise ContractError("duplicate watch id")
    if len(check_ids) != len(set(check_ids)):
        raise ContractError("duplicate check id")

    watch_parts = [(watch.id, watch.root.parts) for watch in watches]
    for index, (left_id, left_parts) in enumerate(watch_parts):
        for right_id, right_parts in watch_parts[index + 1 :]:
            shorter = min(len(left_parts), len(right_parts))
            if left_parts[:shorter] == right_parts[:shorter]:
                raise ContractError(f"watch roots overlap: {left_id} and {right_id}")

    for check in checks:
        check_parts = check.options["path"].parts
        covering = [
            watch.id
            for watch in watches
            if len(check_parts) > len(watch.root.parts)
            and check_parts[: len(watch.root.parts)] == watch.root.parts
        ]
        if len(covering) != 1:
            raise ContractError(f"checks.{check.id}.path: not covered by exactly one watch root")

    return Contract(
        source=source,
        base_device=base_info.st_dev,
        base_inode=base_info.st_ino,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        schema_version="1",
        project_id=project_id,
        public_label=public_label,
        privacy_profile="public-safe",
        watches=watches,
        checks=checks,
    )
