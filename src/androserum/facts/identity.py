"""DEX descriptors, content hashes and versioned run-scoped identifiers."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any
from uuid import uuid4

ID_VERSION = "program-id.v1"
_CLASS = re.compile(r"L[^.;\[\s()/]+(?:/[^.;\[\s()/]+)*;")
_NAME = re.compile(r"(?:<init>|<clinit>|[^.;/\[\s()<>:]+)")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_file(path: str | Path) -> str:
    checksum = hashlib.sha256()
    with filesystem_path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def filesystem_path(path: str | Path) -> Path:
    """Use Windows extended absolute paths for deeply nested evidence bundles."""
    resolved = Path(path).resolve()
    text = str(resolved)
    if os.name == "nt" and not text.startswith("\\\\?\\"):
        text = "\\\\?\\UNC\\" + text[2:] if text.startswith("\\\\") else "\\\\?\\" + text
    return Path(text)


def new_run_id() -> str:
    return "run:" + uuid4().hex


def record_id(run_ref: str, namespace: str, identity: Any) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", namespace):
        raise ValueError("Invalid identifier namespace")
    return namespace + ":" + fingerprint([ID_VERSION, run_ref, namespace, identity])[:32]


def class_descriptor(value: str) -> str:
    if not _CLASS.fullmatch(value):
        raise ValueError("Expected a complete DEX class descriptor, e.g. Lexample/Reporter;")
    return value


def _type_end(text: str, start: int, *, allow_void: bool = False) -> int:
    cursor = start
    while cursor < len(text) and text[cursor] == "[":
        cursor += 1
    dimensions = cursor - start
    if dimensions > 255 or cursor == len(text):
        raise ValueError("Invalid DEX type descriptor")
    char = text[cursor]
    if char in "ZBSCIJFD":
        return cursor + 1
    if char == "V" and allow_void and dimensions == 0:
        return cursor + 1
    if char == "L":
        end = text.find(";", cursor)
        if end != -1:
            class_descriptor(text[cursor:end + 1])
            return end + 1
    raise ValueError("Invalid DEX type descriptor")


def type_descriptor(value: str, *, allow_void: bool = False) -> str:
    if _type_end(value, 0, allow_void=allow_void) != len(value):
        raise ValueError("Trailing content in DEX type descriptor")
    return value


def parse_method_signature(value: str) -> tuple[str, str, tuple[str, ...], str]:
    owner, separator, tail = value.partition("->")
    if not separator:
        raise ValueError("Expected full Dalvik method signature")
    class_descriptor(owner)
    name, left, rest = tail.partition("(")
    parameters, right, result = rest.partition(")")
    if not left or not right or not _NAME.fullmatch(name):
        raise ValueError("Invalid Dalvik method name or parameter list")
    parsed = []
    cursor = 0
    while cursor < len(parameters):
        end = _type_end(parameters, cursor)
        parsed.append(parameters[cursor:end])
        cursor = end
    type_descriptor(result, allow_void=True)
    if name in {"<init>", "<clinit>"} and result != "V":
        raise ValueError("Constructors and class initializers return V")
    if name == "<clinit>" and parsed:
        raise ValueError("Class initializers have no parameters")
    return owner, name, tuple(parsed), result


def method_signature(value: str) -> str:
    parse_method_signature(value)
    return value


def field_signature(value: str) -> str:
    owner, separator, tail = value.partition("->")
    name, colon, descriptor = tail.partition(":")
    if not separator or not colon or not _NAME.fullmatch(name) or name.startswith("<"):
        raise ValueError("Expected full Dalvik field signature")
    class_descriptor(owner)
    type_descriptor(descriptor)
    return value


def archive_path(value: str) -> str:
    if not value or "\\" in value or value.startswith("/") or ":" in value:
        raise ValueError("Expected a relative APK archive path using forward slashes")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("Invalid APK archive path")
    return value
