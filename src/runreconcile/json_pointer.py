"""Small, strict RFC 6901 JSON Pointer resolver."""

from __future__ import annotations

from typing import Any, Tuple


class JsonPointerError(ValueError):
    pass


def _decode(segment: str) -> str:
    output = []
    index = 0
    while index < len(segment):
        if segment[index] != "~":
            output.append(segment[index])
            index += 1
            continue
        if index + 1 >= len(segment) or segment[index + 1] not in {"0", "1"}:
            raise JsonPointerError("invalid JSON Pointer escape")
        output.append("~" if segment[index + 1] == "0" else "/")
        index += 2
    return "".join(output)


def validate_pointer(pointer: str, *, allow_root: bool = True) -> None:
    """Validate RFC 6901 syntax without resolving against a document."""
    if not isinstance(pointer, str):
        raise JsonPointerError("JSON Pointer must be a string")
    if pointer == "":
        if allow_root:
            return
        raise JsonPointerError("JSON Pointer must not select the document root")
    if not pointer.startswith("/"):
        raise JsonPointerError("JSON Pointer must be empty or begin with /")
    for raw_segment in pointer[1:].split("/"):
        _decode(raw_segment)


def resolve_pointer(document: Any, pointer: str) -> Tuple[bool, Any]:
    validate_pointer(pointer)
    if pointer == "":
        return True, document
    current = document
    for raw_segment in pointer[1:].split("/"):
        segment = _decode(raw_segment)
        if isinstance(current, dict):
            if segment not in current:
                return False, None
            current = current[segment]
        elif isinstance(current, list):
            if segment == "-" or not segment.isdigit() or (len(segment) > 1 and segment.startswith("0")):
                return False, None
            index = int(segment)
            if index >= len(current):
                return False, None
            current = current[index]
        else:
            return False, None
    return True, current
