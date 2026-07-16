"""Build content-addressed report v3 documents from strict v2 evidence."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Any

from ._version import __version__
from .canonical_json import canonical_json_bytes, framed_content_digest
from .exceptions import CollectionError, SchemaValidationError
from .identity import (
    REPORT_EVIDENCE_FIELDS,
    RawArtifactReference,
    collection_event_identity,
    derive_collection_id,
    finalize_report_identity,
    make_raw_artifact_reference,
    validate_relative_artifact_path,
)

REPORT_V2_VERSION = "2.0.0"
REPORT_V3_VERSION = "3.0.0"
HOST_ABSOLUTE_PATH_RE = re.compile(
    r"(?:^|[\s('\"\[=:])(?:"
    r"/(?!/)[^\s'\"\])}]+|"
    r"[A-Za-z]:[\\/]+[^\s'\"\])}]+|"
    r"\\{2,}[^\\/\s]+[\\/]+[^\\/\s]+"
    r")"
)
V3_RESERVED_EXTENSION_KEYS = frozenset(
    {
        "org.androidtrustlab.collection",
        "org.androidtrustlab.migration-v3",
    }
)


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _strings(item)]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    return []


def _migration_carried_free_text(source: dict[str, Any]) -> list[str]:
    extensions = {
        key: value
        for key, value in source["extensions"].items()
        if key != "org.androidtrustlab.migration"
    }
    values: list[object] = [source["limitations"], source["provenance"], extensions]
    legacy_extension = source["extensions"].get("org.androidtrustlab.migration")
    if isinstance(legacy_extension, dict):
        encoded_legacy = legacy_extension.get("source_report_json")
        if isinstance(encoded_legacy, str):
            legacy_source = json.loads(encoded_legacy)
            if isinstance(legacy_source, dict):
                legacy_extensions = legacy_source.get("extensions", {})
                if not isinstance(legacy_extensions, dict):
                    legacy_extensions = {}
                values.extend(
                    [
                        legacy_source.get("limitations", {}),
                        legacy_source.get("provenance", {}),
                        legacy_extensions,
                    ]
                )
    return [text for value in values for text in _strings(value)]


def _validate_migration_source_portability(source: dict[str, Any]) -> None:
    reserved = V3_RESERVED_EXTENSION_KEYS.intersection(source["extensions"])
    if reserved:
        raise SchemaValidationError(
            "report migration source uses a reserved v3 extension key"
        )
    references = list(source["raw_artifacts"])
    legacy_extension = source["extensions"].get("org.androidtrustlab.migration")
    if isinstance(legacy_extension, dict):
        encoded_legacy = legacy_extension.get("source_report_json")
        if isinstance(encoded_legacy, str):
            legacy_source = json.loads(encoded_legacy)
            if isinstance(legacy_source, dict):
                legacy_references = legacy_source.get("raw_artifacts", [])
                if isinstance(legacy_references, list):
                    references.extend(legacy_references)
    try:
        for reference in references:
            if not isinstance(reference, str):
                raise CollectionError("raw artifact path must be a string")
            validate_relative_artifact_path(reference)
    except CollectionError as exc:
        raise SchemaValidationError(
            "report migration source contains a nonportable raw artifact reference"
        ) from exc
    if any(
        HOST_ABSOLUTE_PATH_RE.search(value)
        for value in _migration_carried_free_text(source)
    ):
        raise SchemaValidationError(
            "report migration source contains an unredacted host absolute path"
        )


def _migration_history(
    source: dict[str, Any], *, add_v2_to_v3: bool
) -> list[dict[str, Any]]:
    historical_version = source["provenance"]["normalizer"]["version"]
    records = [
        {
            **record,
            "implementation": {
                "name": "trustlab-migration",
                "version": historical_version,
            },
        }
        for record in source["provenance"]["migration_history"]
    ]
    if add_v2_to_v3:
        records.append(
            {
                "migration_id": "report-v2-to-v3",
                "source_schema_version": REPORT_V2_VERSION,
                "target_schema_version": REPORT_V3_VERSION,
                "implementation": {
                    "name": "trustlab-migration",
                    "version": __version__,
                },
            }
        )
    return records


def report_v3_from_v2_shape(
    source: dict[str, Any],
    *,
    raw_artifacts: list[RawArtifactReference],
    collection_event_id: str,
    source_schema_version: str,
    generator_name: str,
    generator_version: str = __version__,
    add_v2_to_v3_migration: bool = False,
    extra_extensions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Upgrade v2-shaped evidence while assigning v3 provenance and identities."""

    report = deepcopy(source)
    report["report_id"] = "atlrep-" + "0" * 32
    report["schema_version"] = REPORT_V3_VERSION
    report["collection_event_id"] = collection_event_id
    report["content_digest"] = "0" * 64
    report["raw_artifacts"] = [artifact.to_dict() for artifact in raw_artifacts]
    report["provenance"] = {
        "source_schema_version": source_schema_version,
        "normalizer": deepcopy(source["provenance"]["normalizer"]),
        "generator": {
            "name": generator_name,
            "version": generator_version,
        },
        "migration_history": _migration_history(
            source, add_v2_to_v3=add_v2_to_v3_migration
        ),
        "command_results": deepcopy(source["provenance"]["command_results"]),
    }
    report["extensions"] = deepcopy(source["extensions"])
    if extra_extensions:
        report["extensions"].update(deepcopy(extra_extensions))
    return finalize_report_identity(report)


def migrate_v2_source_reference(
    source: dict[str, Any],
) -> tuple[RawArtifactReference, str, dict[str, Any]]:
    """Bind an exact canonical v2 source document for deterministic migration."""

    _validate_migration_source_portability(source)
    payload = canonical_json_bytes(source)
    timestamp = source["collection_timestamp"]
    digest = hashlib.sha256(payload).hexdigest()
    evidence_digest = framed_content_digest(
        family="report",
        schema_version=REPORT_V2_VERSION,
        value={field: source[field] for field in REPORT_EVIDENCE_FIELDS},
    )
    collection_id = derive_collection_id(
        timestamp=timestamp,
        experiment_id=source["experiment_id"],
        target_type=source["target"]["target_type"],
        observer_type=source["observer"]["observer_type"],
        collection_method="report_v2_migration",
        raw_sha256=evidence_digest,
    )
    reference = make_raw_artifact_reference(
        payload,
        logical_id=f"migration-source-{digest[:32]}",
        relative_path=f"migration_sources/{digest}.json",
        media_type="application/json",
        collector_name=source["provenance"]["normalizer"]["name"],
        collector_version=source["provenance"]["normalizer"]["version"],
        collection_id=collection_id,
        status="observed",
        redaction_state="unknown",
    )
    event_id = collection_event_identity(
        collection_id=collection_id,
        timestamp=timestamp,
        experiment_id=source["experiment_id"],
        target_type=source["target"]["target_type"],
        observer_type=source["observer"]["observer_type"],
        collection_method="report_v2_migration",
    )
    extension = {
        "org.androidtrustlab.migration-v3": {
            "encoding": "atl-canonical-json-v1",
            "source_report_json": payload.decode("utf-8"),
            "source_sha256": digest,
        }
    }
    return reference, event_id, extension
