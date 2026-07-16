"""Validated declarative trust-dimension registry.

The packaged JSON document is metadata only.  It may select behavior through
the fixed Python lookup tables in this module, but it cannot provide Python
expressions or import paths.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib.resources import files
from types import MappingProxyType
from typing import Any, Final, TypeAlias, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from .compatibility import EvidenceStatus, SchemaFamily, current_write_version

REGISTRY_SCHEMA_VERSION: Final = "1.0.0"
REGISTRY_ID: Final = "android-trust-lab-dimensions"
REGISTRY_RESOURCE_NAME: Final = "trust_dimensions_v1_0_0.json"
REGISTRY_SCHEMA_RESOURCE_NAME: Final = "trust_dimension_registry_v1_0_0.schema.json"

CANONICAL_EVIDENCE_STATUSES: Final = tuple(status.value for status in EvidenceStatus)
CONTEXTUAL_DIMENSION_IDS: Final = frozenset(
    {"physical_device_state", "app_visible_state", "root_visible_state"}
)


class TrustDimensionRegistryError(ValueError):
    """Raised when packaged trust-dimension metadata is invalid or unsafe."""


@dataclass(frozen=True, slots=True)
class MaterialityRule:
    policy_id: str
    value: str


@dataclass(frozen=True, slots=True)
class DirectionRule:
    policy_id: str


@dataclass(frozen=True, slots=True)
class ConfidencePolicy:
    policy_id: str


@dataclass(frozen=True, slots=True)
class RendererHints:
    renderer_id: str
    matrix_order: int | None


@dataclass(frozen=True, slots=True)
class TrustDimension:
    """One immutable trust-dimension definition."""

    id: str
    title: str
    description: str
    interpretation: str
    category: str
    supported_report_versions: tuple[str, ...]
    extractor_id: str
    comparator_id: str
    expected_statuses: tuple[str, ...]
    materiality_rule: MaterialityRule
    direction_rule: DirectionRule
    confidence_policy: ConfidencePolicy
    evidence_paths: tuple[str, ...]
    renderer_hints: RendererHints
    contextual: bool
    enabled_by_default: bool


DimensionReference: TypeAlias = str | TrustDimension
Extractor: TypeAlias = Callable[[Mapping[str, Any], TrustDimension], Any]
Comparator: TypeAlias = Callable[[Any, Any, TrustDimension], bool]


def _comparison_value(value: Any) -> Any:
    """Project evidence onto status/value semantics, excluding reference noise."""

    if isinstance(value, dict) and {"status", "value", "reason"} <= value.keys():
        return {"status": value["status"], "value": value["value"]}
    if (
        isinstance(value, dict)
        and {"status", "reason", "evidence_refs"} <= value.keys()
    ):
        return {"status": value["status"]}
    if isinstance(value, dict):
        return {
            key: _comparison_value(item)
            for key, item in value.items()
            if key != "evidence_refs"
        }
    if isinstance(value, list):
        return [_comparison_value(item) for item in value]
    return value


def _nested_path_v1(report: Mapping[str, Any], definition: TrustDimension) -> Any:
    path = definition.evidence_paths[0]
    current: Any = report
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return "unknown"
        current = current.get(part, "unknown")
    return current


def _contextual_sentinel() -> dict[str, Any]:
    return {
        "status": "not_collected",
        "value": None,
        "reason": "direct supporting payload is not available",
        "evidence_refs": [],
    }


def _contextual_unavailable_extractor_v1(
    report: Mapping[str, Any], definition: TrustDimension
) -> dict[str, Any]:
    del report, definition
    return _contextual_sentinel()


def _canonical_equality_v1(before: Any, after: Any, definition: TrustDimension) -> bool:
    del definition
    return bool(_comparison_value(before) == _comparison_value(after))


def _contextual_unavailable_comparator_v1(
    before: Any, after: Any, definition: TrustDimension
) -> bool:
    del definition
    sentinel = _contextual_sentinel()
    if before != sentinel or after != sentinel:
        raise TrustDimensionRegistryError(
            "contextual dimensions may only compare the canonical not-collected sentinel"
        )
    return True


EXTRACTOR_LOOKUP: Final[Mapping[str, Extractor]] = MappingProxyType(
    {
        "nested_path_v1": _nested_path_v1,
        "contextual_unavailable_v1": _contextual_unavailable_extractor_v1,
    }
)
COMPARATOR_LOOKUP: Final[Mapping[str, Comparator]] = MappingProxyType(
    {
        "canonical_equality_v1": _canonical_equality_v1,
        "contextual_unavailable_v1": _contextual_unavailable_comparator_v1,
    }
)


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise TrustDimensionRegistryError(
                f"trust dimension registry contains duplicate key: {key}"
            )
        value[key] = item
    return value


def _read_json_resource(package: str, name: str) -> dict[str, Any]:
    resource = files(package).joinpath(name)
    try:
        text = resource.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise TrustDimensionRegistryError(
            f"required packaged registry resource is missing: {name}"
        ) from exc
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise TrustDimensionRegistryError(
            f"packaged registry resource is invalid JSON: {name}"
        ) from exc
    if not isinstance(value, dict):
        raise TrustDimensionRegistryError(
            f"packaged registry resource must be an object: {name}"
        )
    return value


def _schema() -> dict[str, Any]:
    schema = _read_json_resource("trustlab.schemas", REGISTRY_SCHEMA_RESOURCE_NAME)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise TrustDimensionRegistryError(
            "packaged trust dimension registry schema is invalid"
        ) from exc
    return schema


def _schema_error(error: ValidationError) -> str:
    location = "/" + "/".join(str(part) for part in error.absolute_path)
    return f"trust dimension registry schema validation failed at {location}: {error.message}"


def _definition(value: Mapping[str, Any]) -> TrustDimension:
    materiality = cast(Mapping[str, Any], value["materiality_rule"])
    direction = cast(Mapping[str, Any], value["direction_rule"])
    confidence = cast(Mapping[str, Any], value["confidence_policy"])
    renderer = cast(Mapping[str, Any], value["renderer_hints"])
    return TrustDimension(
        id=cast(str, value["id"]),
        title=cast(str, value["title"]),
        description=cast(str, value["description"]),
        interpretation=cast(str, value["interpretation"]),
        category=cast(str, value["category"]),
        supported_report_versions=tuple(
            cast(Sequence[str], value["supported_report_versions"])
        ),
        extractor_id=cast(str, value["extractor_id"]),
        comparator_id=cast(str, value["comparator_id"]),
        expected_statuses=tuple(cast(Sequence[str], value["expected_statuses"])),
        materiality_rule=MaterialityRule(
            policy_id=cast(str, materiality["policy_id"]),
            value=cast(str, materiality["value"]),
        ),
        direction_rule=DirectionRule(policy_id=cast(str, direction["policy_id"])),
        confidence_policy=ConfidencePolicy(
            policy_id=cast(str, confidence["policy_id"])
        ),
        evidence_paths=tuple(cast(Sequence[str], value["evidence_paths"])),
        renderer_hints=RendererHints(
            renderer_id=cast(str, renderer["renderer_id"]),
            matrix_order=cast(int | None, renderer["matrix_order"]),
        ),
        contextual=cast(bool, value["contextual"]),
        enabled_by_default=cast(bool, value["enabled_by_default"]),
    )


def _validate_common_definition(
    definition: TrustDimension, *, current_report_version: str
) -> None:
    if definition.supported_report_versions != (current_report_version,):
        raise TrustDimensionRegistryError(
            f"{definition.id} must support only current report version {current_report_version}"
        )
    if definition.materiality_rule.policy_id != "fixed_v1":
        raise TrustDimensionRegistryError(
            f"{definition.id} has an unsupported materiality policy"
        )
    if definition.confidence_policy.policy_id != "factorized_evidence_v1":
        raise TrustDimensionRegistryError(
            f"{definition.id} has an unsupported confidence policy"
        )
    if definition.extractor_id not in EXTRACTOR_LOOKUP:
        raise TrustDimensionRegistryError(
            f"{definition.id} references an unknown extractor"
        )
    if definition.comparator_id not in COMPARATOR_LOOKUP:
        raise TrustDimensionRegistryError(
            f"{definition.id} references an unknown comparator"
        )


def _validate_contextual_definition(definition: TrustDimension) -> None:
    if definition.enabled_by_default:
        raise TrustDimensionRegistryError(
            f"contextual dimension {definition.id} cannot be enabled by default"
        )
    if definition.evidence_paths:
        raise TrustDimensionRegistryError(
            f"contextual dimension {definition.id} cannot fabricate an evidence path"
        )
    if definition.expected_statuses != (EvidenceStatus.NOT_COLLECTED.value,):
        raise TrustDimensionRegistryError(
            f"contextual dimension {definition.id} must be not-collected"
        )
    if definition.extractor_id != "contextual_unavailable_v1" or (
        definition.comparator_id != "contextual_unavailable_v1"
    ):
        raise TrustDimensionRegistryError(
            f"contextual dimension {definition.id} must use contextual functions"
        )
    if definition.direction_rule.policy_id != "context_only_v1":
        raise TrustDimensionRegistryError(
            f"contextual dimension {definition.id} must use context-only direction"
        )
    if definition.renderer_hints.renderer_id != "not_applicable_v1" or (
        definition.renderer_hints.matrix_order is not None
    ):
        raise TrustDimensionRegistryError(
            f"contextual dimension {definition.id} must remain out of measured renderers"
        )


def _validate_measured_definition(definition: TrustDimension) -> None:
    if not definition.enabled_by_default:
        raise TrustDimensionRegistryError(
            f"measured dimension {definition.id} must be enabled by default"
        )
    if len(definition.evidence_paths) != 1:
        raise TrustDimensionRegistryError(
            f"measured dimension {definition.id} must have one evidence path"
        )
    if definition.expected_statuses != CANONICAL_EVIDENCE_STATUSES:
        raise TrustDimensionRegistryError(
            f"measured dimension {definition.id} has non-canonical statuses"
        )
    if definition.extractor_id != "nested_path_v1" or (
        definition.comparator_id != "canonical_equality_v1"
    ):
        raise TrustDimensionRegistryError(
            f"measured dimension {definition.id} must use measured functions"
        )


def _semantic_validation(definitions: tuple[TrustDimension, ...]) -> None:
    if len(definitions) != 30:
        raise TrustDimensionRegistryError(
            "trust dimension registry must contain exactly 30 dimensions"
        )

    ids = tuple(definition.id for definition in definitions)
    if len(set(ids)) != len(ids):
        raise TrustDimensionRegistryError("trust dimension IDs must be unique")

    current_report_version = current_write_version(SchemaFamily.REPORT)
    all_paths: list[str] = []
    default_count = 0
    contextual_ids: set[str] = set()
    defaults_finished = False
    for definition in definitions:
        _validate_common_definition(
            definition, current_report_version=current_report_version
        )
        if definition.contextual:
            defaults_finished = True
            contextual_ids.add(definition.id)
            _validate_contextual_definition(definition)
            continue
        if defaults_finished:
            raise TrustDimensionRegistryError(
                "enabled measured dimensions must precede contextual dimensions"
            )
        default_count += 1
        _validate_measured_definition(definition)
        all_paths.extend(definition.evidence_paths)

    if default_count != 27 or contextual_ids != CONTEXTUAL_DIMENSION_IDS:
        raise TrustDimensionRegistryError(
            "registry must contain 27 measured dimensions and the three canonical contextual dimensions"
        )
    if len(set(all_paths)) != len(all_paths):
        raise TrustDimensionRegistryError(
            "measured dimension evidence paths must be unique"
        )

    matrix_orders = sorted(
        definition.renderer_hints.matrix_order
        for definition in definitions
        if definition.renderer_hints.matrix_order is not None
    )
    if matrix_orders != list(range(1, len(matrix_orders) + 1)):
        raise TrustDimensionRegistryError(
            "matrix renderer order must be unique and contiguous from one"
        )

    referenced_extractors = {definition.extractor_id for definition in definitions}
    referenced_comparators = {definition.comparator_id for definition in definitions}
    if referenced_extractors != set(EXTRACTOR_LOOKUP):
        raise TrustDimensionRegistryError(
            "every public registry extractor must be referenced"
        )
    if referenced_comparators != set(COMPARATOR_LOOKUP):
        raise TrustDimensionRegistryError(
            "every public registry comparator must be referenced"
        )


def validate_registry_document(document: object) -> tuple[TrustDimension, ...]:
    """Validate a registry document and return immutable typed definitions."""

    validator = Draft202012Validator(_schema())
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: (
            tuple(str(part) for part in error.absolute_path),
            error.message,
        ),
    )
    if errors:
        raise TrustDimensionRegistryError(_schema_error(errors[0]))
    assert isinstance(document, dict)
    if document["schema_version"] != REGISTRY_SCHEMA_VERSION:
        raise TrustDimensionRegistryError(
            "trust dimension registry schema version is not supported"
        )
    if document["registry_id"] != REGISTRY_ID:
        raise TrustDimensionRegistryError("trust dimension registry ID is invalid")
    definitions = tuple(
        _definition(value)
        for value in cast(Sequence[Mapping[str, Any]], document["dimensions"])
    )
    _semantic_validation(definitions)
    return definitions


def _load_registry() -> tuple[TrustDimension, ...]:
    document = _read_json_resource("trustlab.registry", REGISTRY_RESOURCE_NAME)
    return validate_registry_document(document)


TRUST_DIMENSION_DEFINITIONS: Final = _load_registry()
TRUST_DIMENSIONS_BY_ID: Final[Mapping[str, TrustDimension]] = MappingProxyType(
    {definition.id: definition for definition in TRUST_DIMENSION_DEFINITIONS}
)
DEFAULT_DIMENSIONS: Final = tuple(
    definition
    for definition in TRUST_DIMENSION_DEFINITIONS
    if definition.enabled_by_default
)
CONTEXTUAL_DIMENSION_DEFINITIONS: Final = tuple(
    definition for definition in TRUST_DIMENSION_DEFINITIONS if definition.contextual
)


def dimension_definition(dimension: DimensionReference) -> TrustDimension:
    """Resolve a canonical immutable definition, failing closed for unknown IDs."""

    if isinstance(dimension, TrustDimension):
        canonical = TRUST_DIMENSIONS_BY_ID.get(dimension.id)
        if canonical != dimension:
            raise TrustDimensionRegistryError(
                "trust dimension definition is not the canonical registry value"
            )
        return dimension
    try:
        return TRUST_DIMENSIONS_BY_ID[dimension]
    except KeyError as exc:
        raise TrustDimensionRegistryError(
            f"unknown trust dimension: {dimension}"
        ) from exc


def extract_dimension(report: Mapping[str, Any], dimension: DimensionReference) -> Any:
    """Extract one dimension using its fixed, typed extractor implementation."""

    definition = dimension_definition(dimension)
    return EXTRACTOR_LOOKUP[definition.extractor_id](report, definition)


def dimensions_equal(dimension: DimensionReference, before: Any, after: Any) -> bool:
    """Compare two extracted values using the registry's fixed comparator."""

    definition = dimension_definition(dimension)
    return COMPARATOR_LOOKUP[definition.comparator_id](before, after, definition)


def comparison_value(value: Any) -> Any:
    """Project raw evidence exactly as the canonical comparator does."""

    return _comparison_value(value)
