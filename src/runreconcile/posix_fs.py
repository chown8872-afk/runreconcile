"""Descriptor-relative POSIX directory traversal helpers."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


class FilesystemSafetyError(RuntimeError):
    pass


Identity = Tuple[int, int]


def identity(info: os.stat_result) -> Identity:
    return info.st_dev, info.st_ino


def is_reparse_point(info: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(info, "st_file_attributes", 0) & flag)


_DESCRIPTOR_SUPPORT_AVAILABLE = (
    os.name == "posix"
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
    and os.readlink in os.supports_dir_fd
    and os.scandir in os.supports_fd
)


def descriptor_support_available() -> bool:
    return _DESCRIPTOR_SUPPORT_AVAILABLE


def directory_flags() -> int:
    if not descriptor_support_available():
        raise FilesystemSafetyError("descriptor-relative filesystem support is unavailable")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def file_flags() -> int:
    if not descriptor_support_available():
        raise FilesystemSafetyError("descriptor-relative filesystem support is unavailable")
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY  # type: ignore[attr-defined]
    return flags


class DirectoryChain:
    """Keep every validated directory descriptor open until final revalidation."""

    def __init__(self, base_path: Path, descriptors: List[int], names: List[str]):
        self.base_path = base_path
        self.descriptors = descriptors
        self.names = names
        self._closed = False

    @property
    def leaf_fd(self) -> int:
        if self._closed:
            raise FilesystemSafetyError("directory chain is closed")
        return self.descriptors[-1]

    def revalidate(self) -> None:
        if self._closed:
            raise FilesystemSafetyError("directory chain is closed")
        try:
            rebound_base = os.open(str(self.base_path), directory_flags())
        except OSError as exc:
            raise FilesystemSafetyError("contract directory binding changed") from exc
        try:
            if identity(os.fstat(rebound_base)) != identity(os.fstat(self.descriptors[0])):
                raise FilesystemSafetyError("contract directory binding changed")
        finally:
            os.close(rebound_base)
        for index, name in enumerate(self.names):
            try:
                rebound = os.stat(
                    name,
                    dir_fd=self.descriptors[index],
                    follow_symlinks=False,
                )
                opened = os.fstat(self.descriptors[index + 1])
            except OSError as exc:
                raise FilesystemSafetyError("directory binding changed") from exc
            if (
                not stat.S_ISDIR(rebound.st_mode)
                or not stat.S_ISDIR(opened.st_mode)
                or is_reparse_point(rebound)
                or is_reparse_point(opened)
                or identity(rebound) != identity(opened)
            ):
                raise FilesystemSafetyError("directory binding changed")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for descriptor in reversed(self.descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass

    def __enter__(self) -> "DirectoryChain":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


def open_directory_chain(
    base_path: Path,
    parts: Iterable[str],
    *,
    expected_base: Optional[Identity] = None,
) -> DirectoryChain:
    descriptors: List[int] = []
    names: List[str] = []
    try:
        base_fd = os.open(str(base_path), directory_flags())
        descriptors.append(base_fd)
        base_info = os.fstat(base_fd)
        if (
            not stat.S_ISDIR(base_info.st_mode)
            or is_reparse_point(base_info)
            or (expected_base is not None and identity(base_info) != expected_base)
        ):
            raise FilesystemSafetyError("contract directory is not the validated directory")
        for name in parts:
            parent_fd = descriptors[-1]
            try:
                before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                child_fd = os.open(name, directory_flags(), dir_fd=parent_fd)
            except OSError as exc:
                raise FilesystemSafetyError("unable to open a safe directory component") from exc
            try:
                opened = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(before.st_mode)
                    or not stat.S_ISDIR(opened.st_mode)
                    or is_reparse_point(before)
                    or is_reparse_point(opened)
                    or identity(before) != identity(opened)
                ):
                    raise FilesystemSafetyError("directory changed identity while being opened")
            except BaseException:
                os.close(child_fd)
                raise
            descriptors.append(child_fd)
            names.append(name)
        chain = DirectoryChain(base_path, descriptors, names)
        chain.revalidate()
        return chain
    except BaseException:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
