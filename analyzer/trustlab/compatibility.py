"""Machine-readable schema compatibility policy."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

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


SCHEMA_SUPPORT: Final[Mapping[SchemaFamily, SchemaSupport]] = MappingProxyType(
    {
        SchemaFamily.REPORT: SchemaSupport(
            current_write_version="2.0.0",
            readable_versions=frozenset({"1.0.0", "2.0.0"}),
        ),
        SchemaFamily.DIFF: SchemaSupport(
            current_write_version="1.0.0",
            readable_versions=frozenset({"1.0.0"}),
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
            (SchemaFamily.DIFF, "1.0.0"): "trust_diff.schema.json",
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
