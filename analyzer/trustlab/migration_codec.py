"""Deterministic encoding for preserved legacy report evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def encode_legacy_report(source: dict[str, Any]) -> str:
    """Encode a JSON report losslessly as canonical-safe string data."""

    return json.dumps(
        source,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def legacy_report_digest(encoded_source: str) -> str:
    """Return the SHA-256 digest of a preserved legacy JSON encoding."""

    return hashlib.sha256(encoded_source.encode("utf-8")).hexdigest()
