"""Content provenance and stable identity primitives for current reports."""

from __future__ import annotations

import hashlib
import re
import secrets
from copy import deepcopy
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Any

from .canonical_json import CanonicalJSONError, framed_content_digest
from .exceptions import CollectionError, SchemaValidationError

REPORT_SCHEMA_VERSION = "6.0.0"
REDACTION_STATES = frozenset(
    {"not_required", "redacted", "verified", "withheld", "unknown"}
)
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,127}$")
VERSION_RE = re.compile(
    r"^(?:unknown|[0-9]+\.[0-9]+\.[0-9]+(?:[-.]?[A-Za-z0-9][A-Za-z0-9.-]*)?)$"
)


@dataclass(frozen=True, slots=True)
class RawArtifactReference:
    """Structured provenance for one exact source byte sequence."""

    logical_id: str
    relative_path: str
    sha256: str
    byte_size: int
    media_type: str
    collector_name: str
    collector_version: str
    collection_id: str
    status: str
    redaction_state: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_relative_artifact_path(path: str) -> None:
    """Require one bounded, normalized, platform-neutral artifact path."""

    pure = PurePosixPath(path)
    if (
        not path
        or len(path) > 1024
        or pure.is_absolute()
        or path != pure.as_posix()
        or "\\" in path
        or ":" in path
        or any(part in {"", ".", ".."} for part in pure.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise CollectionError("raw artifact path must be normalized and relative")


def make_raw_artifact_reference(
    payload: bytes,
    *,
    logical_id: str | None,
    relative_path: str,
    media_type: str = "text/plain",
    collector_name: str = "unknown",
    collector_version: str = "unknown",
    collection_id: str,
    status: str = "observed",
    redaction_state: str = "unknown",
    expected_sha256: str | None = None,
    expected_byte_size: int | None = None,
) -> RawArtifactReference:
    """Hash exact bytes and construct a validated structured source reference."""

    digest = hashlib.sha256(payload).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise CollectionError("raw artifact digest does not match provenance")
    if expected_byte_size is not None and len(payload) != expected_byte_size:
        raise CollectionError("raw artifact byte size does not match provenance")
    validate_relative_artifact_path(relative_path)
    resolved_logical_id = logical_id or f"raw-{digest[:32]}"
    if IDENTIFIER_RE.fullmatch(resolved_logical_id) is None:
        raise CollectionError("raw artifact logical ID is invalid")
    if IDENTIFIER_RE.fullmatch(collector_name) is None:
        raise CollectionError("raw artifact collector name is invalid")
    if VERSION_RE.fullmatch(collector_version) is None:
        raise CollectionError("raw artifact collector version is invalid")
    if IDENTIFIER_RE.fullmatch(collection_id) is None:
        raise CollectionError("raw artifact collection ID is invalid")
    if status != "observed":
        raise CollectionError("raw artifact references require observed source bytes")
    if redaction_state not in REDACTION_STATES:
        raise CollectionError("raw artifact redaction state is invalid")
    if not media_type or len(media_type) > 127 or "/" not in media_type:
        raise CollectionError("raw artifact media type is invalid")
    return RawArtifactReference(
        logical_id=resolved_logical_id,
        relative_path=relative_path,
        sha256=digest,
        byte_size=len(payload),
        media_type=media_type,
        collector_name=collector_name,
        collector_version=collector_version,
        collection_id=collection_id,
        status=status,
        redaction_state=redaction_state,
    )


def derive_collection_id(
    *,
    timestamp: str,
    experiment_id: str,
    target_type: str,
    observer_type: str,
    collection_method: str,
    raw_sha256: str,
) -> str:
    """Derive a deterministic fallback collection ID for unmanifested input."""

    digest = framed_content_digest(
        family="collection_event",
        schema_version="1.0.0",
        value={
            "collection_method": collection_method,
            "experiment_id": experiment_id,
            "observer_type": observer_type,
            "raw_sha256": raw_sha256,
            "target_type": target_type,
            "timestamp": timestamp,
        },
    )
    return f"atlcol-{digest[:32]}"


def collection_event_identity(
    *,
    collection_id: str,
    timestamp: str,
    experiment_id: str,
    target_type: str,
    observer_type: str,
    collection_method: str,
    collection_manifest_sha256: str | None = None,
) -> str:
    """Identify one collection event separately from its evidence content."""

    event = {
        "collection_id": collection_id,
        "collection_method": collection_method,
        "experiment_id": experiment_id,
        "observer_type": observer_type,
        "target_type": target_type,
        "timestamp": timestamp,
    }
    if collection_manifest_sha256 is not None:
        if re.fullmatch(r"[a-f0-9]{64}", collection_manifest_sha256) is None:
            raise CollectionError("collection manifest digest is invalid")
        event["collection_manifest_sha256"] = collection_manifest_sha256
    digest = framed_content_digest(
        family="collection_event",
        schema_version="1.0.0",
        value=event,
    )
    return f"atlevent-{digest[:32]}"


REPORT_EVIDENCE_FIELDS = (
    "target",
    "observer",
    "boot_state",
    "verified_boot",
    "selinux",
    "mounts",
    "properties",
    "root_state",
    "magisk_state",
    "process_state",
    "emulator_state",
    "limitations",
)


def report_content_projection(report: dict[str, Any]) -> dict[str, Any]:
    """Return the documented nonvolatile evidence projection for report identity."""

    source_version = report["provenance"]["source_schema_version"]
    migrated_v2_source = source_version == "2.0.0" or (
        source_version in {"3.0.0", "4.0.0"}
        and "org.androidtrustlab.migration-v3" in report["extensions"]
    )
    raw_artifacts = (
        []
        if migrated_v2_source
        else sorted(
            [
                {
                    "byte_size": artifact["byte_size"],
                    "media_type": artifact["media_type"],
                    "redaction_state": artifact["redaction_state"],
                    "sha256": artifact["sha256"],
                    "status": artifact["status"],
                }
                for artifact in report["raw_artifacts"]
            ],
            key=lambda artifact: (
                artifact["sha256"],
                artifact["media_type"],
                artifact["byte_size"],
                artifact["redaction_state"],
                artifact["status"],
            ),
        )
    )
    projection = {
        **{field: deepcopy(report[field]) for field in REPORT_EVIDENCE_FIELDS},
        "raw_artifacts": raw_artifacts,
    }
    comparison_context = report.get("extensions", {}).get(
        "org.androidtrustlab.comparison-context"
    )
    if comparison_context is not None:
        bound_context = deepcopy(comparison_context)
        if isinstance(bound_context, dict):
            # The report ID already binds collection_event_id. Keep the evidence
            # digest stable across repeat measurements of identical evidence.
            bound_context.pop("measurement_id", None)
        projection["comparison_context"] = bound_context
    return projection


def calculate_report_content_digest(report: dict[str, Any]) -> str:
    """Calculate the canonical evidence-content identity for a current report."""

    return framed_content_digest(
        family="report",
        schema_version=str(report.get("schema_version", REPORT_SCHEMA_VERSION)),
        value=report_content_projection(report),
    )


def calculate_report_id(
    *,
    collection_event_id: str,
    content_digest: str,
    schema_version: str = REPORT_SCHEMA_VERSION,
) -> str:
    """Bind one report event to its exact evidence content with 128-bit display."""

    digest = framed_content_digest(
        family="report",
        schema_version=schema_version,
        value={
            "collection_event_id": collection_event_id,
            "content_digest": content_digest,
        },
    )
    return f"atlrep-{digest[:32]}"


def finalize_report_identity(report: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with deterministic content and report identities populated."""

    finalized = deepcopy(report)
    content_digest = calculate_report_content_digest(finalized)
    finalized["content_digest"] = content_digest
    finalized["report_id"] = calculate_report_id(
        collection_event_id=finalized["collection_event_id"],
        content_digest=content_digest,
        schema_version=str(finalized.get("schema_version", REPORT_SCHEMA_VERSION)),
    )
    return finalized


def validate_report_identities(report: dict[str, Any]) -> None:
    """Reject a v3 report whose declared identities do not match its content."""

    try:
        expected_digest = calculate_report_content_digest(report)
    except CanonicalJSONError as exc:
        raise SchemaValidationError(
            "report evidence is outside the canonical identity model"
        ) from exc
    if not secrets.compare_digest(str(report.get("content_digest")), expected_digest):
        raise SchemaValidationError("report content digest does not match evidence")
    expected_report_id = calculate_report_id(
        collection_event_id=report["collection_event_id"],
        content_digest=expected_digest,
        schema_version=str(report.get("schema_version", REPORT_SCHEMA_VERSION)),
    )
    if not secrets.compare_digest(str(report.get("report_id")), expected_report_id):
        raise SchemaValidationError(
            "report ID does not bind its collection event and content"
        )
