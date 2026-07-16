"""ATL Canonical JSON v1 and framed content identities."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

MAX_INTEROPERABLE_INTEGER = 9_007_199_254_740_991
MAX_CANONICAL_BYTES = 64 * 1024 * 1024
MAX_CANONICAL_NESTING = 64
MAX_CANONICAL_NODES = 100_000
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
FAMILY_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


class CanonicalJSONError(ValueError):
    """A value cannot be represented by ATL Canonical JSON v1."""


def _reject_float(_value: str) -> None:
    raise CanonicalJSONError("canonical JSON forbids floating-point values")


def _reject_constant(_value: str) -> None:
    raise CanonicalJSONError("canonical JSON forbids non-finite values")


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CanonicalJSONError("canonical JSON forbids duplicate object members")
        value[key] = item
    return value


def parse_canonical_json(payload: bytes) -> Any:
    """Parse strict UTF-8 JSON into the ATL canonical data model."""

    if len(payload) > MAX_CANONICAL_BYTES:
        raise CanonicalJSONError("canonical JSON input exceeds the byte limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalJSONError("canonical JSON input must be valid UTF-8") from exc
    if text.startswith("\ufeff"):
        raise CanonicalJSONError("canonical JSON input must not contain a BOM")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_members,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalJSONError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise CanonicalJSONError("canonical JSON input is not valid JSON") from exc
    validate_canonical_value(value)
    return value


def _validate_string(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise CanonicalJSONError("canonical JSON forbids isolated UTF-16 surrogates")


def validate_canonical_value(value: Any) -> None:
    """Validate the bounded ATL Canonical JSON v1 data model iteratively."""

    pending = [(value, 0)]
    visited = 0
    while pending:
        current, depth = pending.pop()
        visited += 1
        if visited > MAX_CANONICAL_NODES:
            raise CanonicalJSONError("canonical JSON exceeds the node limit")
        if current is None or isinstance(current, bool):
            continue
        if isinstance(current, int):
            if not -MAX_INTEROPERABLE_INTEGER <= current <= MAX_INTEROPERABLE_INTEGER:
                raise CanonicalJSONError(
                    "canonical JSON integer exceeds the interoperable range"
                )
            continue
        if isinstance(current, str):
            _validate_string(current)
            continue
        if isinstance(current, list):
            if current and depth >= MAX_CANONICAL_NESTING:
                raise CanonicalJSONError("canonical JSON exceeds the nesting limit")
            pending.extend((item, depth + 1) for item in reversed(current))
            continue
        if isinstance(current, dict):
            if current and depth >= MAX_CANONICAL_NESTING:
                raise CanonicalJSONError("canonical JSON exceeds the nesting limit")
            for key in current:
                if not isinstance(key, str):
                    raise CanonicalJSONError(
                        "canonical JSON object keys must be strings"
                    )
                _validate_string(key)
            pending.extend(
                (item, depth + 1) for item in reversed(tuple(current.values()))
            )
            continue
        if isinstance(current, float):
            raise CanonicalJSONError("canonical JSON forbids floating-point values")
        raise CanonicalJSONError("value is outside the canonical JSON data model")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize one value according to ATL Canonical JSON v1."""

    validate_canonical_value(value)
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        payload = text.encode("utf-8")
    except (RecursionError, TypeError, UnicodeEncodeError, ValueError) as exc:
        raise CanonicalJSONError("value cannot be serialized canonically") from exc
    if len(payload) > MAX_CANONICAL_BYTES:
        raise CanonicalJSONError("canonical JSON output exceeds the byte limit")
    return payload


def canonicalize_json(payload: bytes) -> bytes:
    """Parse strict JSON and return its ATL Canonical JSON v1 bytes."""

    return canonical_json_bytes(parse_canonical_json(payload))


def framed_content_digest(*, family: str, schema_version: str, value: Any) -> str:
    """Hash the unambiguous ATL-CONTENT-ID v1 frame for one canonical value."""

    if FAMILY_RE.fullmatch(family) is None:
        raise CanonicalJSONError("content family is not a canonical family token")
    if SEMVER_RE.fullmatch(schema_version) is None:
        raise CanonicalJSONError("schema version is not strict semantic versioning")
    canonical = canonical_json_bytes(value)
    frame = (
        b"\0".join(
            (
                b"ATL-CONTENT-ID",
                b"v1",
                family.encode("ascii"),
                schema_version.encode("ascii"),
            )
        )
        + b"\0"
        + str(len(canonical)).encode("ascii")
        + b":"
        + canonical
    )
    return hashlib.sha256(frame).hexdigest()
