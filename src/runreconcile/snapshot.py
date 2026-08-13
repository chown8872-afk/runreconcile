"""Final-state filesystem snapshots with explicit coverage limits."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from .contract import Contract
from .posix_fs import (
    FilesystemSafetyError,
    directory_flags,
    file_flags,
    identity,
    is_reparse_point,
    open_directory_chain,
)


MAX_SCAN_ENTRIES = 100_000
MAX_SCAN_DEPTH = 64
MAX_SCAN_TOTAL_BYTES = 1024 * 1024 * 1024


class SnapshotError(RuntimeError):
    """Raised when a complete, trustworthy point-in-time snapshot is impossible."""


@dataclass(frozen=True)
class Entry:
    kind: str
    size_bytes: Optional[int]
    mtime_ns: int
    mode: int
    sha256: Optional[str] = None
    link_target_sha256: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "kind": self.kind,
            "mtime_ns": self.mtime_ns,
            "mode": self.mode,
        }
        if self.size_bytes is not None:
            result["size_bytes"] = self.size_bytes
        if self.sha256 is not None:
            result["sha256"] = self.sha256
        if self.link_target_sha256 is not None:
            result["link_target_sha256"] = self.link_target_sha256
        return result


@dataclass(frozen=True)
class WatchSnapshot:
    root_mode: int
    entries: Mapping[str, Entry]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_mode": self.root_mode,
            "entries": {key: value.to_dict() for key, value in sorted(self.entries.items())},
        }


@dataclass(frozen=True)
class Snapshot:
    run_id: str
    contract_sha256: str
    created_at: str
    created_at_ns: int
    watches: Mapping[str, WatchSnapshot]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "runreconcile.snapshot.v1",
            "run_id": self.run_id,
            "contract_sha256": self.contract_sha256,
            "created_at": self.created_at,
            "created_at_ns": self.created_at_ns,
            "watches": {key: value.to_dict() for key, value in sorted(self.watches.items())},
            "coverage": {
                "mode": "final_state_snapshot",
                "followed_symlinks": False,
                "file_count": sum(
                    entry.kind == "file"
                    for watch in self.watches.values()
                    for entry in watch.entries.values()
                ),
                "entry_count": sum(len(watch.entries) for watch in self.watches.values()),
            },
        }


@dataclass(frozen=True)
class Change:
    watch_id: str
    path: str
    change: str


@dataclass(frozen=True)
class DiffResult:
    allowed: Tuple[Change, ...]
    unexpected: Tuple[Change, ...]

    @property
    def all_changes(self) -> Tuple[Change, ...]:
        return tuple(sorted(self.allowed + self.unexpected, key=lambda item: (item.watch_id, item.path)))


def _is_reparse_point(info: Any) -> bool:
    return is_reparse_point(info)


def _identity(info: os.stat_result) -> Tuple[int, int]:
    return identity(info)


def _hash_regular_file_at(directory_fd: int, name: str, before: os.stat_result, limit: int) -> str:
    if before.st_size > limit:
        raise SnapshotError("file exceeds max_file_bytes; snapshot is incomplete")
    digest = hashlib.sha256()
    total = 0
    try:
        descriptor = os.open(name, file_flags(), dir_fd=directory_fd)
    except OSError as exc:
        raise SnapshotError("unable to open a stable regular file") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SnapshotError("file changed type while being fingerprinted")
        if _identity(opened) != _identity(before):
            raise SnapshotError("file changed identity while being fingerprinted")
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not block:
                break
            total += len(block)
            if total > limit:
                raise SnapshotError("file grew beyond max_file_bytes while being fingerprinted")
            digest.update(block)
        after = os.fstat(descriptor)
        rebound = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    finally:
        os.close(descriptor)
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_mode")
    if any(
        getattr(before, field) != getattr(value, field)
        for value in (after, rebound)
        for field in stable_fields
    ):
        raise SnapshotError("file changed while being fingerprinted")
    return digest.hexdigest()


def _symlink_entry_at(directory_fd: int, name: str, info: os.stat_result) -> Entry:
    try:
        target = os.readlink(name, dir_fd=directory_fd).encode("utf-8", errors="surrogateescape")
        after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise SnapshotError("unable to read a stable symlink") from exc
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_mode")
    if any(getattr(info, field) != getattr(after, field) for field in stable_fields):
        raise SnapshotError("symlink changed while being fingerprinted")
    return Entry(
        kind="symlink",
        size_bytes=info.st_size,
        mtime_ns=info.st_mtime_ns,
        mode=stat.S_IMODE(info.st_mode),
        link_target_sha256=hashlib.sha256(target).hexdigest(),
    )


def _scan_directory(
    root_fd: int,
    max_file_bytes: int,
) -> Dict[str, Entry]:
    entries: Dict[str, Entry] = {}
    total_bytes = 0

    def visit(directory_fd: int, prefix: Tuple[str, ...]) -> None:
        nonlocal total_bytes
        if len(prefix) > MAX_SCAN_DEPTH:
            raise SnapshotError("watched tree exceeds maximum depth")
        try:
            with os.scandir(directory_fd) as iterator:
                names = sorted(item.name for item in iterator)
        except OSError as exc:
            raise SnapshotError("unable to list watched directory") from exc
        for name in names:
            if len(entries) >= MAX_SCAN_ENTRIES:
                raise SnapshotError("watched tree exceeds maximum entry count")
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise SnapshotError("unable to inspect watched entry") from exc
            if _is_reparse_point(info):
                raise SnapshotError("unsupported filesystem reparse point")
            relative = "/".join(prefix + (name,))
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                entries[relative] = _symlink_entry_at(directory_fd, name, info)
                continue
            if stat.S_ISREG(info.st_mode):
                total_bytes += info.st_size
                if total_bytes > MAX_SCAN_TOTAL_BYTES:
                    raise SnapshotError("watched tree exceeds maximum total file bytes")
                digest = _hash_regular_file_at(directory_fd, name, info, max_file_bytes)
                entries[relative] = Entry("file", info.st_size, info.st_mtime_ns, mode, sha256=digest)
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise SnapshotError("unsupported filesystem entry type")
            try:
                child_fd = os.open(name, directory_flags(), dir_fd=directory_fd)
            except OSError as exc:
                raise SnapshotError("unable to open watched directory safely") from exc
            try:
                opened = os.fstat(child_fd)
                if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != _identity(info):
                    raise SnapshotError("directory changed identity while being opened")
                entries[relative] = Entry(
                    "directory",
                    None,
                    opened.st_mtime_ns,
                    stat.S_IMODE(opened.st_mode),
                )
                visit(child_fd, prefix + (name,))
                after = os.fstat(child_fd)
                rebound = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                stable_fields = ("st_dev", "st_ino", "st_mtime_ns", "st_mode")
                if any(
                    getattr(opened, field) != getattr(value, field)
                    for value in (after, rebound)
                    for field in stable_fields
                ):
                    raise SnapshotError("directory changed while being scanned")
            finally:
                os.close(child_fd)

    opened_root = os.fstat(root_fd)
    if not stat.S_ISDIR(opened_root.st_mode) or _is_reparse_point(opened_root):
        raise SnapshotError("watch root is not a safe directory")
    visit(root_fd, ())
    after_root = os.fstat(root_fd)
    stable_fields = ("st_dev", "st_ino", "st_mtime_ns", "st_mode")
    if any(getattr(opened_root, field) != getattr(after_root, field) for field in stable_fields):
        raise SnapshotError("watch root changed while being scanned")
    return entries


def snapshot_contract(contract: Contract, run_id: str) -> Snapshot:
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", run_id):
        raise SnapshotError("invalid public run_id")
    created_at_ns = time.time_ns()
    created_at = datetime.fromtimestamp(created_at_ns / 1_000_000_000, timezone.utc).isoformat().replace("+00:00", "Z")
    watches: Dict[str, WatchSnapshot] = {}
    for watch in contract.watches:
        try:
            chain = open_directory_chain(
                contract.source.parent,
                watch.root.parts,
                expected_base=(contract.base_device, contract.base_inode),
            )
        except FilesystemSafetyError as exc:
            raise SnapshotError(f"watch {watch.id}: unsafe directory binding") from exc
        with chain:
            root_before = os.fstat(chain.leaf_fd)
            first = _scan_directory(chain.leaf_fd, watch.max_file_bytes)
            try:
                chain.revalidate()
            except FilesystemSafetyError as exc:
                raise SnapshotError(f"watch {watch.id}: directory binding changed") from exc
            root_after_first = os.fstat(chain.leaf_fd)
            second = _scan_directory(chain.leaf_fd, watch.max_file_bytes)
            try:
                chain.revalidate()
            except FilesystemSafetyError as exc:
                raise SnapshotError(f"watch {watch.id}: directory binding changed") from exc
            root_after_second = os.fstat(chain.leaf_fd)
            stable_fields = ("st_dev", "st_ino", "st_mtime_ns", "st_mode")
            if first != second or any(
                getattr(root_before, field) != getattr(value, field)
                for value in (root_after_first, root_after_second)
                for field in stable_fields
            ):
                raise SnapshotError(f"watch {watch.id}: unable to obtain a stable final-state snapshot")
            watches[watch.id] = WatchSnapshot(stat.S_IMODE(root_after_second.st_mode), second)
    return Snapshot(run_id, contract.sha256, created_at, created_at_ns, watches)


def _entry_from_dict(raw: Any) -> Entry:
    if not isinstance(raw, dict):
        raise SnapshotError("invalid snapshot entry")
    kind = raw.get("kind")
    if kind not in {"file", "directory", "symlink"}:
        raise SnapshotError("invalid snapshot entry kind")
    try:
        mtime_ns = raw["mtime_ns"]
        mode = raw["mode"]
    except KeyError as exc:
        raise SnapshotError("invalid snapshot entry") from exc
    if isinstance(mtime_ns, bool) or not isinstance(mtime_ns, int):
        raise SnapshotError("invalid snapshot mtime")
    if isinstance(mode, bool) or not isinstance(mode, int):
        raise SnapshotError("invalid snapshot mode")
    size = raw.get("size_bytes")
    if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
        raise SnapshotError("invalid snapshot size")
    digest = raw.get("sha256")
    link_digest = raw.get("link_target_sha256")
    for value in (digest, link_digest):
        if value is not None and (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise SnapshotError("invalid snapshot digest")
    if kind == "file" and (size is None or digest is None):
        raise SnapshotError("file snapshot is missing evidence")
    if kind == "directory" and size is not None:
        raise SnapshotError("directory snapshot has invalid size evidence")
    if kind == "symlink" and link_digest is None:
        raise SnapshotError("symlink snapshot is missing evidence")
    return Entry(kind, size, mtime_ns, mode, digest, link_digest)


def snapshot_from_dict(raw: Any) -> Snapshot:
    if not isinstance(raw, dict) or raw.get("schema_version") != "runreconcile.snapshot.v1":
        raise SnapshotError("unsupported snapshot schema")
    run_id = raw.get("run_id")
    contract_sha256 = raw.get("contract_sha256")
    created_at = raw.get("created_at")
    created_at_ns = raw.get("created_at_ns")
    watches_raw = raw.get("watches")
    if not isinstance(run_id, str) or not run_id:
        raise SnapshotError("invalid snapshot run_id")
    if not isinstance(contract_sha256, str) or len(contract_sha256) != 64:
        raise SnapshotError("invalid snapshot contract digest")
    if not isinstance(created_at, str) or not created_at:
        raise SnapshotError("invalid snapshot timestamp")
    try:
        parsed_time = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SnapshotError("invalid snapshot timestamp") from exc
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        raise SnapshotError("snapshot timestamp must include a timezone")
    if isinstance(created_at_ns, bool) or not isinstance(created_at_ns, int):
        raise SnapshotError("invalid snapshot timestamp")
    if not isinstance(watches_raw, dict):
        raise SnapshotError("invalid snapshot watch set")
    watches: Dict[str, WatchSnapshot] = {}
    for watch_id, watch_raw in watches_raw.items():
        if not isinstance(watch_id, str) or not isinstance(watch_raw, dict):
            raise SnapshotError("invalid snapshot watch")
        entries_raw = watch_raw.get("entries")
        root_mode = watch_raw.get("root_mode")
        if isinstance(root_mode, bool) or not isinstance(root_mode, int):
            raise SnapshotError("invalid snapshot watch root mode")
        if not isinstance(entries_raw, dict):
            raise SnapshotError("invalid snapshot entries")
        entries: Dict[str, Entry] = {}
        for relative, entry_raw in entries_raw.items():
            if (
                not isinstance(relative, str)
                or not relative
                or relative.startswith("/")
                or ".." in relative.split("/")
            ):
                raise SnapshotError("invalid snapshot relative path")
            entries[relative] = _entry_from_dict(entry_raw)
        watches[watch_id] = WatchSnapshot(root_mode, entries)
    return Snapshot(run_id, contract_sha256, created_at, created_at_ns, watches)


def save_snapshot(snapshot: Snapshot, path: Path) -> str:
    if path.exists():
        raise SnapshotError("snapshot output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(snapshot.to_dict(), sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    descriptor, temporary_name = tempfile.mkstemp(prefix=".runreconcile-snapshot-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary_name, path)
        except FileExistsError as exc:
            raise SnapshotError("snapshot output already exists") from exc
        os.unlink(temporary_name)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return payload_sha256


def load_snapshot(
    path: Path,
    max_bytes: int = 64 * 1024 * 1024,
    expected_sha256: Optional[str] = None,
) -> Snapshot:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise SnapshotError("invalid baseline size limit")
    if expected_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise SnapshotError("invalid expected baseline digest")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY  # type: ignore[attr-defined]
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW  # type: ignore[attr-defined]
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise SnapshotError("unable to read baseline snapshot") from exc
    chunks = []
    total = 0
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse_point(opened):
            raise SnapshotError("invalid baseline snapshot type")
        while True:
            block = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > max_bytes:
                raise SnapshotError("baseline snapshot exceeds size limit")
        after = os.fstat(descriptor)
    except OSError as exc:
        raise SnapshotError("unable to read baseline snapshot") from exc
    finally:
        os.close(descriptor)
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_mode")
    if any(getattr(opened, field) != getattr(after, field) for field in stable_fields):
        raise SnapshotError("baseline snapshot changed while being read")
    raw_bytes = b"".join(chunks)

    def reject_duplicates(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SnapshotError("baseline snapshot contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        if expected_sha256 is not None:
            if hashlib.sha256(raw_bytes).hexdigest() != expected_sha256:
                raise SnapshotError("baseline digest mismatch")
        raw = json.loads(
            raw_bytes.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(SnapshotError("invalid JSON number")),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotError("invalid baseline snapshot") from exc
    return snapshot_from_dict(raw)


def _segment_match(path_segments: Tuple[str, ...], pattern_segments: Tuple[str, ...], i: int, j: int) -> bool:
    if j == len(pattern_segments):
        return i == len(path_segments)
    pattern = pattern_segments[j]
    if pattern == "**":
        return _segment_match(path_segments, pattern_segments, i, j + 1) or (
            i < len(path_segments) and _segment_match(path_segments, pattern_segments, i + 1, j)
        )
    return (
        i < len(path_segments)
        and fnmatch.fnmatchcase(path_segments[i], pattern)
        and _segment_match(path_segments, pattern_segments, i + 1, j + 1)
    )


def matches_any(path: str, patterns: Iterable[str]) -> bool:
    path_segments = tuple(part for part in path.split("/") if part)
    return any(
        _segment_match(path_segments, tuple(part for part in pattern.split("/") if part), 0, 0)
        for pattern in patterns
    )


def _change(before: Optional[Entry], after: Optional[Entry]) -> Optional[str]:
    if before is None:
        return "created"
    if after is None:
        return "deleted"
    if before.kind != after.kind:
        return "type-changed"
    if before.kind == "file" and before.sha256 != after.sha256:
        return "content-modified"
    if before.kind == "symlink" and before.link_target_sha256 != after.link_target_sha256:
        return "content-modified"
    if before.kind == "directory":
        if before.mode != after.mode:
            return "metadata-modified"
        return None
    if (before.size_bytes, before.mtime_ns, before.mode) != (
        after.size_bytes,
        after.mtime_ns,
        after.mode,
    ):
        return "metadata-modified"
    return None


def diff_snapshots(contract: Contract, before: Snapshot, after: Snapshot) -> DiffResult:
    if before.run_id != after.run_id:
        raise SnapshotError("snapshot run_id mismatch")
    if before.contract_sha256 != contract.sha256 or after.contract_sha256 != contract.sha256:
        raise SnapshotError("snapshot contract hash mismatch")
    allowed = []
    unexpected = []
    watch_specs = {watch.id: watch for watch in contract.watches}
    if set(before.watches) != set(watch_specs) or set(after.watches) != set(watch_specs):
        raise SnapshotError("snapshot watch set mismatch")
    for watch_id, spec in watch_specs.items():
        before_entries = before.watches[watch_id].entries
        after_entries = after.watches[watch_id].entries
        if before.watches[watch_id].root_mode != after.watches[watch_id].root_mode:
            root_change = Change(watch_id, ".", "metadata-modified")
            if matches_any(".", spec.allow):
                allowed.append(root_change)
            else:
                unexpected.append(root_change)
        for path in sorted(set(before_entries) | set(after_entries)):
            change_kind = _change(before_entries.get(path), after_entries.get(path))
            if change_kind is None:
                continue
            item = Change(watch_id, path, change_kind)
            if matches_any(path, spec.allow):
                allowed.append(item)
            else:
                unexpected.append(item)
    return DiffResult(tuple(allowed), tuple(unexpected))
