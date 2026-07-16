"""Registry-backed rendering for trust dimensions.

Registry documents select only the fixed renderer IDs in this module.  They do
not contain format strings, expressions, or import paths.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any, Final, TypeAlias

from .dimension_registry import (
    DEFAULT_DIMENSIONS,
    TRUST_DIMENSION_DEFINITIONS,
    DimensionReference,
    TrustDimension,
    TrustDimensionRegistryError,
    dimension_definition,
    extract_dimension,
)

Renderer: TypeAlias = Callable[[Mapping[str, Any], TrustDimension], str]


def _evidence_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        if "status" in value:
            status = value["status"]
            if "value" not in value or status not in {"observed", "observed_absent"}:
                return status
            return _evidence_value(value["value"])
        return {
            key: _evidence_value(item)
            for key, item in value.items()
            if key not in {"evidence_refs", "reason"}
        }
    if isinstance(value, list):
        return [_evidence_value(item) for item in value]
    return value


def _format_value(value: Any) -> str:
    if isinstance(value, list):
        if not value:
            return "none"
        if all(not isinstance(item, (Mapping, list)) for item in value):
            return ", ".join(map(str, value))
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    if isinstance(value, Mapping):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value)


def _evidence_v1(report: Mapping[str, Any], definition: TrustDimension) -> str:
    return _format_value(_evidence_value(extract_dimension(report, definition)))


def _presence_v1(report: Mapping[str, Any], definition: TrustDimension) -> str:
    evidence = extract_dimension(report, definition)
    if (
        isinstance(evidence, Mapping)
        and {
            "status",
            "value",
            "reason",
        }
        <= evidence.keys()
    ):
        if evidence["status"] not in {"observed", "observed_absent"}:
            return _format_value(evidence["status"])
        if evidence["value"] is True:
            return "present"
        if evidence["value"] is False:
            return "not present"
        return _format_value(evidence["value"])
    return _format_value(evidence)


def _mount_integrity_v1(report: Mapping[str, Any], definition: TrustDimension) -> str:
    integrity = extract_dimension(report, definition)
    if not isinstance(integrity, Mapping):
        return _format_value(integrity)
    writable = _evidence_value(integrity.get("writable_sensitive_mounts", "unknown"))
    overlay = _evidence_value(integrity.get("overlay_detected", "unknown"))
    return (
        f"writable={_format_value(writable)}; overlay={_format_value(overlay).lower()}"
    )


def _property_map_v1(report: Mapping[str, Any], definition: TrustDimension) -> str:
    return _format_value(_evidence_value(extract_dimension(report, definition)))


def _not_applicable_v1(report: Mapping[str, Any], definition: TrustDimension) -> str:
    return _format_value(_evidence_value(extract_dimension(report, definition)))


RENDERER_LOOKUP: Final[Mapping[str, Renderer]] = MappingProxyType(
    {
        "evidence_v1": _evidence_v1,
        "presence_v1": _presence_v1,
        "mount_integrity_v1": _mount_integrity_v1,
        "property_map_v1": _property_map_v1,
        "not_applicable_v1": _not_applicable_v1,
    }
)


def _validate_renderer_references() -> None:
    referenced = {
        definition.renderer_hints.renderer_id
        for definition in TRUST_DIMENSION_DEFINITIONS
    }
    missing = referenced - set(RENDERER_LOOKUP)
    if missing:
        raise TrustDimensionRegistryError(
            "trust dimension registry references unknown renderers: "
            + ", ".join(sorted(missing))
        )
    unreferenced = set(RENDERER_LOOKUP) - referenced
    if unreferenced:
        raise TrustDimensionRegistryError(
            "public trust dimension renderers are not referenced: "
            + ", ".join(sorted(unreferenced))
        )


_validate_renderer_references()

MATRIX_DIMENSIONS: Final = tuple(
    sorted(
        (
            definition
            for definition in DEFAULT_DIMENSIONS
            if definition.renderer_hints.matrix_order is not None
        ),
        key=lambda definition: definition.renderer_hints.matrix_order or 0,
    )
)


def render_dimension(report: Mapping[str, Any], dimension: DimensionReference) -> str:
    """Render one canonical dimension through its fixed registry renderer."""

    definition = dimension_definition(dimension)
    renderer = RENDERER_LOOKUP[definition.renderer_hints.renderer_id]
    return renderer(report, definition)


def dimension_label(dimension: DimensionReference, *, include_id: bool = True) -> str:
    """Return the canonical human title, optionally with its stable ID."""

    definition = dimension_definition(dimension)
    if include_id:
        return f"{definition.title} (`{definition.id}`)"
    return definition.title


def _markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def registry_markdown() -> str:
    """Render deterministic generated documentation for the registry."""

    measured = DEFAULT_DIMENSIONS[0]
    contextual = next(
        definition
        for definition in TRUST_DIMENSION_DEFINITIONS
        if definition.contextual
    )
    measured_statuses = ", ".join(measured.expected_statuses)
    lines = [
        "# Trust Dimension Registry",
        "",
        "This file is generated from the validated, versioned trust-dimension registry. Do not edit it by hand.",
        "",
        f"All measured dimensions currently support report schema `{measured.supported_report_versions[0]}`, use the `{measured.extractor_id}` extractor and `{measured.comparator_id}` comparator, expect statuses "
        f"`{measured_statuses.replace(', ', '`, `')}`, and use the `{measured.confidence_policy.policy_id}` confidence policy.",
        "",
        f"Contextual dimensions support report schema `{contextual.supported_report_versions[0]}`, remain disabled by default, have no fabricated evidence path, and return only the canonical `{contextual.expected_statuses[0]}` sentinel.",
        "",
        "## Dimensions",
        "",
        "| Stable ID | Title | Category | Evidence path | Materiality | Direction rule | Renderer | Matrix order |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for definition in TRUST_DIMENSION_DEFINITIONS:
        evidence_path = (
            definition.evidence_paths[0] if definition.evidence_paths else "—"
        )
        matrix_order = definition.renderer_hints.matrix_order
        lines.append(
            "| `{id}` | {title} | `{category}` | `{path}` | `{materiality}` | "
            "`{direction}` | `{renderer}` | {matrix} |".format(
                id=definition.id,
                title=_markdown_cell(definition.title),
                category=definition.category,
                path=evidence_path,
                materiality=definition.materiality_rule.value,
                direction=definition.direction_rule.policy_id,
                renderer=definition.renderer_hints.renderer_id,
                matrix=matrix_order if matrix_order is not None else "—",
            )
        )

    lines.extend(
        [
            "",
            "## Descriptions and interpretation",
            "",
            "| Stable ID | Description | Interpretation |",
            "|---|---|---|",
        ]
    )
    for definition in TRUST_DIMENSION_DEFINITIONS:
        lines.append(
            f"| `{definition.id}` | {_markdown_cell(definition.description)} | "
            f"{_markdown_cell(definition.interpretation)} |"
        )
    return "\n".join(lines) + "\n"
