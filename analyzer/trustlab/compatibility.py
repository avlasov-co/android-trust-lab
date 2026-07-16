"""Machine-readable schema compatibility policy."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from .exceptions import SchemaValidationError, UnsupportedSchemaVersionError


class EvidenceStatus(StrEnum):
    """Canonical evidence outcomes; absence and collection failures stay distinct."""

    OBSERVED = "observed"
    OBSERVED_ABSENT = "observed_absent"
    INACCESSIBLE = "inaccessible"
    NOT_COLLECTED = "not_collected"
    COMMAND_ERROR = "command_error"
    UNSUPPORTED = "unsupported"


class SchemaFamily(StrEnum):
    """Independently versioned JSON contract families."""

    REPORT = "report"
    DIFF = "diff"
    DATASET_MANIFEST = "dataset_manifest"
    COLLECTION_MANIFEST = "collection_manifest"
    EXPERIMENT_SPEC = "experiment_spec"


@dataclass(frozen=True, slots=True)
class SchemaSupport:
    """Read/write support declared for one schema family."""

    current_write_version: str | None
    readable_versions: frozenset[str]
    planned_version: str | None = None


@dataclass(frozen=True, slots=True)
class MigrationStep:
    """One registered, directional report-schema migration."""

    migration_id: str
    source_schema_version: str
    target_schema_version: str

    def to_compatibility_dict(self) -> dict[str, str]:
        return {
            "migration_id": self.migration_id,
            "source_schema_version": self.source_schema_version,
            "target_schema_version": self.target_schema_version,
        }


SCHEMA_SUPPORT: Final[Mapping[SchemaFamily, SchemaSupport]] = MappingProxyType(
    {
        SchemaFamily.REPORT: SchemaSupport(
            current_write_version="6.0.0",
            readable_versions=frozenset(
                {"1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0"}
            ),
        ),
        SchemaFamily.DIFF: SchemaSupport(
            current_write_version="2.5.0",
            readable_versions=frozenset(
                {
                    "1.0.0",
                    "2.0.0",
                    "2.1.0",
                    "2.2.0",
                    "2.3.0",
                    "2.4.0",
                    "2.5.0",
                }
            ),
        ),
        SchemaFamily.DATASET_MANIFEST: SchemaSupport(
            current_write_version="2.0.0",
            readable_versions=frozenset({"1.0.0", "2.0.0"}),
        ),
        SchemaFamily.COLLECTION_MANIFEST: SchemaSupport(
            current_write_version="1.0.0",
            readable_versions=frozenset({"1.0.0"}),
        ),
        SchemaFamily.EXPERIMENT_SPEC: SchemaSupport(
            current_write_version=None,
            readable_versions=frozenset(),
            planned_version="1.0.0",
        ),
    }
)

SCHEMA_RESOURCE_REGISTRY: Final[Mapping[tuple[SchemaFamily, str], str]] = (
    MappingProxyType(
        {
            (SchemaFamily.REPORT, "1.0.0"): "trust_report_v1_0_0.schema.json",
            (SchemaFamily.REPORT, "2.0.0"): "trust_report_v2_0_0.schema.json",
            (SchemaFamily.REPORT, "3.0.0"): "trust_report_v3_0_0.schema.json",
            (SchemaFamily.REPORT, "4.0.0"): "trust_report_v4_0_0.schema.json",
            (SchemaFamily.REPORT, "5.0.0"): "trust_report_v5_0_0.schema.json",
            (SchemaFamily.REPORT, "6.0.0"): "trust_report_v6_0_0.schema.json",
            (SchemaFamily.DIFF, "1.0.0"): "trust_diff.schema.json",
            (SchemaFamily.DIFF, "2.0.0"): "trust_diff_v2_0_0.schema.json",
            (SchemaFamily.DIFF, "2.1.0"): "trust_diff_v2_1_0.schema.json",
            (SchemaFamily.DIFF, "2.2.0"): "trust_diff_v2_2_0.schema.json",
            (SchemaFamily.DIFF, "2.3.0"): "trust_diff_v2_3_0.schema.json",
            (SchemaFamily.DIFF, "2.4.0"): "trust_diff_v2_4_0.schema.json",
            (SchemaFamily.DIFF, "2.5.0"): "trust_diff_v2_5_0.schema.json",
            (SchemaFamily.DATASET_MANIFEST, "1.0.0"): (
                "dataset_manifest_v1_0_0.schema.json"
            ),
            (SchemaFamily.DATASET_MANIFEST, "2.0.0"): (
                "dataset_manifest_v2_0_0.schema.json"
            ),
            (SchemaFamily.COLLECTION_MANIFEST, "1.0.0"): (
                "collection_manifest_v1_0_0.schema.json"
            ),
        }
    )
)

SEMANTIC_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)

REPORT_MIGRATION_REGISTRY: Final[Mapping[str, MigrationStep]] = MappingProxyType(
    {
        "1.0.0": MigrationStep("report-v1-to-v2", "1.0.0", "2.0.0"),
        "2.0.0": MigrationStep("report-v2-to-v3", "2.0.0", "3.0.0"),
        "3.0.0": MigrationStep("report-v3-to-v4", "3.0.0", "4.0.0"),
        "4.0.0": MigrationStep("report-v4-to-v5", "4.0.0", "5.0.0"),
        "5.0.0": MigrationStep("report-v5-to-v6", "5.0.0", "6.0.0"),
    }
)


def schema_support(family: SchemaFamily) -> SchemaSupport:
    """Return the immutable compatibility declaration for a schema family."""

    return SCHEMA_SUPPORT[family]


def supported_schema_versions(family: SchemaFamily) -> frozenset[str]:
    """Return versions accepted as inputs for a schema family."""

    return schema_support(family).readable_versions


def current_write_version(family: SchemaFamily) -> str:
    """Return the only version that writers may emit for a schema family."""

    version = schema_support(family).current_write_version
    if version is None:
        raise SchemaValidationError(
            f"no writable {family.value} schema version is registered"
        )
    return version


def schema_resource_name(family: SchemaFamily, version: str) -> str:
    """Resolve an exact schema resource without latest-version fallback."""

    support = schema_support(family)
    if version not in support.readable_versions:
        raise UnsupportedSchemaVersionError(
            f"unsupported {family.value} schema version"
        )
    try:
        return SCHEMA_RESOURCE_REGISTRY[(family, version)]
    except KeyError as exc:
        raise SchemaValidationError(
            f"no validator is registered for {family.value} schema version {version}"
        ) from exc


def require_supported_schema_version(family: SchemaFamily, value: object) -> str:
    """Reject malformed and unregistered versions before schema dispatch."""

    if not isinstance(value, str) or SEMANTIC_VERSION_RE.fullmatch(value) is None:
        raise SchemaValidationError(
            f"{family.value} schema version must be a semantic version"
        )
    if value not in supported_schema_versions(family):
        raise UnsupportedSchemaVersionError(
            f"unsupported {family.value} schema version"
        )
    return value


def report_migration_path(
    source_version: object, *, target_version: str | None = None
) -> tuple[MigrationStep, ...]:
    """Resolve an exact report migration chain through the immutable registry."""

    source = require_supported_schema_version(SchemaFamily.REPORT, source_version)
    target = require_supported_schema_version(
        SchemaFamily.REPORT,
        target_version or current_write_version(SchemaFamily.REPORT),
    )
    if tuple(map(int, source.split("."))) > tuple(map(int, target.split("."))):
        raise UnsupportedSchemaVersionError(
            "report downgrade migrations are not supported"
        )
    steps: list[MigrationStep] = []
    current = source
    while current != target:
        try:
            step = REPORT_MIGRATION_REGISTRY[current]
        except KeyError as exc:
            raise UnsupportedSchemaVersionError(
                "no registered report migration path"
            ) from exc
        steps.append(step)
        current = step.target_schema_version
        if len(steps) > len(REPORT_MIGRATION_REGISTRY):
            raise SchemaValidationError("report migration registry contains a cycle")
    return tuple(steps)


def prepare_report_for_comparison(
    report: object, *, side: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validate, identity-check, and temporarily migrate one diff input."""

    if side not in {"base", "compare"}:
        raise SchemaValidationError("comparison side must be base or compare")
    if not isinstance(report, dict):
        raise SchemaValidationError(f"{side} report must be a JSON object")
    original_version = require_supported_schema_version(
        SchemaFamily.REPORT, report.get("schema_version")
    )

    # Local imports avoid coupling the schema registry to validation internals.
    from .migration_codec import encode_legacy_report, legacy_report_digest
    from .migrations import migrate_report_to_current
    from .validators import validate_report

    validate_report(report)
    steps = report_migration_path(original_version)
    canonical = migrate_report_to_current(report)
    canonical_version = current_write_version(SchemaFamily.REPORT)
    if canonical.get("schema_version") != canonical_version:
        raise SchemaValidationError(
            "report migration did not produce the canonical comparison schema"
        )
    applied_migrations = (
        canonical["provenance"]["migration_history"][-len(steps) :] if steps else []
    )
    observed_steps = [
        (
            migration["migration_id"],
            migration["source_schema_version"],
            migration["target_schema_version"],
        )
        for migration in applied_migrations
    ]
    expected_steps = [
        (step.migration_id, step.source_schema_version, step.target_schema_version)
        for step in steps
    ]
    if observed_steps != expected_steps:
        raise SchemaValidationError(
            "report migration did not use the registered compatibility path"
        )

    canonical_identity = {
        "report_id": canonical["report_id"],
        "content_digest": canonical["content_digest"],
        "schema_version": canonical["schema_version"],
    }
    provenance = {
        "original_report_id": report.get("report_id", "unknown"),
        "original_schema_version": original_version,
        "original_content_digest": report.get("content_digest")
        if original_version in {"3.0.0", "4.0.0", "5.0.0", "6.0.0"}
        else None,
        "original_document_digest": legacy_report_digest(encode_legacy_report(report)),
        "common_report": canonical_identity,
        "applied_migrations": applied_migrations,
    }
    compatibility = {
        "schema_version": original_version,
        "migrations": [step.to_compatibility_dict() for step in steps],
        "warnings": ([f"{side}_input_migrated_temporarily_in_memory"] if steps else []),
    }
    return canonical, provenance, compatibility
