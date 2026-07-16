"""Diff normalized Android Trust Lab reports."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .assessment import confidence_assessment, direction_assessment
from .canonical_json import framed_content_digest
from .comparison import classify_comparison
from .compatibility import (
    SchemaFamily,
    current_write_version,
    prepare_report_for_comparison,
)
from .dimension_registry import (
    DEFAULT_DIMENSIONS,
    TrustDimension,
    comparison_value,
    dimensions_equal,
    extract_dimension,
)
from .transitions import (
    classify_status_transition,
    confidence_impact,
    evidence_is_available,
    evidence_status,
    signal_direction,
    transition_interpretation,
)

VERIFIED_BOOT_DIMENSIONS = frozenset(
    definition.id
    for definition in DEFAULT_DIMENSIONS
    if definition.category == "boot_integrity"
)


def get_raw_path(obj: dict[str, Any], path: list[str]) -> Any:
    current: Any = obj
    for part in path:
        if not isinstance(current, dict):
            return "unknown"
        current = current.get(part, "unknown")
    return current


def get_path(obj: dict[str, Any], path: list[str]) -> Any:
    return comparison_value(get_raw_path(obj, path))


def _source_evidence(value: Any) -> list[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        evidence_refs = value.get("evidence_refs")
        if isinstance(evidence_refs, list):
            refs.update(ref for ref in evidence_refs if isinstance(ref, str))
        for nested in value.values():
            refs.update(_source_evidence(nested))
    elif isinstance(value, list):
        for nested in value:
            refs.update(_source_evidence(nested))
    return sorted(refs)


def _observed_value(value: Any, status: str) -> Any:
    if not evidence_is_available(status):
        return None
    if isinstance(value, dict) and value.get("status") == status:
        return comparison_value(value.get("value"))
    return comparison_value(value)


def _transition(
    before_status: str,
    after_status: str,
    *,
    comparison_axis: str,
) -> dict[str, str]:
    return {
        "before_status": before_status,
        "after_status": after_status,
        "classification": classify_status_transition(
            before_status,
            after_status,
            comparison_axis=comparison_axis,
        ),
        "confidence_impact": confidence_impact(before_status, after_status),
    }


def _signal_entry(
    dimension: str,
    before_raw: Any,
    after_raw: Any,
    transition: dict[str, str],
    assessment: dict[str, Any],
    evidence_path: str,
) -> dict[str, Any]:
    before_status = transition["before_status"]
    after_status = transition["after_status"]
    return {
        "dimension": dimension,
        **transition,
        "observed_values": {
            "before": _observed_value(before_raw, before_status),
            "after": _observed_value(after_raw, after_status),
        },
        "source_evidence": {
            "before": _source_evidence(before_raw),
            "after": _source_evidence(after_raw),
        },
        "interpretation": transition_interpretation(
            before_status,
            after_status,
            transition["classification"],
        ),
        "materiality": assessment["materiality"],
        "direction": assessment["direction"],
        "confidence": deepcopy(assessment["confidence"]),
        "rationale": list(assessment["rationale"]),
        "evidence_paths": [evidence_path],
    }


def _field_confidence(report: dict[str, Any], dimension: str) -> str:
    if dimension not in VERIFIED_BOOT_DIMENSIONS:
        return "not_available"
    confidence = report.get("verified_boot", {}).get("confidence", {})
    level = confidence.get("level") if isinstance(confidence, dict) else None
    return (
        str(level) if level in {"high", "medium", "low", "unassessed"} else "unassessed"
    )


def _corroborating_evidence_count(
    base: dict[str, Any],
    compare: dict[str, Any],
    dimension: str,
    before_raw: Any,
    after_raw: Any,
) -> int:
    count = len(set(_source_evidence(before_raw)) | set(_source_evidence(after_raw)))
    if dimension not in VERIFIED_BOOT_DIMENSIONS:
        return count
    for report in (base, compare):
        confidence = report.get("verified_boot", {}).get("confidence", {})
        if isinstance(confidence, dict):
            corroborating = confidence.get("corroborating_signal_count")
            if isinstance(corroborating, int) and not isinstance(corroborating, bool):
                count = max(count, corroborating)
    return count


def _dimension_assessment(
    definition: TrustDimension,
    before: Any,
    after: Any,
    before_raw: Any,
    after_raw: Any,
    transition: dict[str, str],
    *,
    base: dict[str, Any],
    compare: dict[str, Any],
    compatibility: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    direction, direction_rationale = direction_assessment(
        definition.direction_rule.policy_id,
        before,
        after,
        transition_class=transition["classification"],
    )
    migration_count = sum(
        len(compatibility["migrations"][side]) for side in ("base", "compare")
    )
    confidence = confidence_assessment(
        before_status=transition["before_status"],
        after_status=transition["after_status"],
        before_field_confidence=_field_confidence(base, definition.id),
        after_field_confidence=_field_confidence(compare, definition.id),
        corroborating_evidence_count=_corroborating_evidence_count(
            base, compare, definition.id, before_raw, after_raw
        ),
        migration_count=migration_count,
        comparability=comparison["comparability"],
        warning_count=len(comparison["warnings"]),
    )
    return {
        "materiality": definition.materiality_rule.value,
        "direction": direction,
        "confidence": confidence,
        "rationale": [
            "materiality_from_dimension_policy",
            direction_rationale,
            "confidence_from_explicit_factors",
        ],
    }


def make_diff(
    base: dict[str, Any],
    compare: dict[str, Any],
    *,
    allow_mixed: bool = False,
) -> dict[str, Any]:
    base, base_provenance, base_compatibility = prepare_report_for_comparison(
        base, side="base"
    )
    compare, compare_provenance, compare_compatibility = prepare_report_for_comparison(
        compare, side="compare"
    )
    common_version = base.get("schema_version")
    if compare.get("schema_version") != common_version:
        raise ValueError("report migration did not produce one common schema version")
    comparison = classify_comparison(base, compare, allow_mixed=allow_mixed)
    provenance = {
        "common_report_schema_version": common_version,
        "base": base_provenance,
        "compare": compare_provenance,
    }
    compatibility = {
        "input_schema_versions": {
            "base": base_compatibility["schema_version"],
            "compare": compare_compatibility["schema_version"],
        },
        "migrations": {
            "base": base_compatibility["migrations"],
            "compare": compare_compatibility["migrations"],
        },
        "warnings": [
            *base_compatibility["warnings"],
            *compare_compatibility["warnings"],
        ],
        "canonical_comparison_schema_version": common_version,
        "migration_mode": "temporary_in_memory",
    }
    changed = []
    unchanged = []
    new_signals: list[dict[str, Any]] = []
    missing_signals: list[dict[str, Any]] = []
    confidence_changes = []

    for definition in DEFAULT_DIMENSIONS:
        dimension = definition.id
        evidence_path = definition.evidence_paths[0]
        before_raw = extract_dimension(base, definition)
        after_raw = extract_dimension(compare, definition)
        before = comparison_value(before_raw)
        after = comparison_value(after_raw)
        if not dimensions_equal(definition, before_raw, after_raw):
            transition = _transition(
                evidence_status(before_raw),
                evidence_status(after_raw),
                comparison_axis=comparison["axis"],
            )
            assessment = _dimension_assessment(
                definition,
                before,
                after,
                before_raw,
                after_raw,
                transition,
                base=base,
                compare=compare,
                compatibility=compatibility,
                comparison=comparison,
            )
            changed.append(
                {
                    "dimension": dimension,
                    "before": before,
                    "after": after,
                    "transition": transition,
                    **assessment,
                    "interpretation": definition.interpretation,
                    "evidence_paths": [evidence_path],
                }
            )
            direction = signal_direction(
                transition["before_status"], transition["after_status"]
            )
            if direction is not None:
                entry = _signal_entry(
                    dimension,
                    before_raw,
                    after_raw,
                    transition,
                    assessment,
                    evidence_path,
                )
                (new_signals if direction == "new" else missing_signals).append(entry)
        else:
            unchanged.append(dimension)

    base_conf = get_path(base, ["verified_boot", "confidence"])
    compare_conf = get_path(compare, ["verified_boot", "confidence"])
    if base_conf != compare_conf:
        confidence_changes.append(
            {
                "path": "verified_boot.confidence",
                "before": base_conf,
                "after": compare_conf,
            }
        )

    summary = (
        f"{len(changed)} dimensions changed, {len(unchanged)} dimensions unchanged; "
        f"{len(new_signals)} signals became available, "
        f"{len(missing_signals)} signals became unavailable."
    )
    schema_version = current_write_version(SchemaFamily.DIFF)
    result = {
        "schema_version": schema_version,
        "base_report": {
            "report_id": base["report_id"],
            "content_digest": base["content_digest"],
            "schema_version": base["schema_version"],
        },
        "compare_report": {
            "report_id": compare["report_id"],
            "content_digest": compare["content_digest"],
            "schema_version": compare["schema_version"],
        },
        "changed_dimensions": changed,
        "unchanged_dimensions": unchanged,
        "new_signals": new_signals,
        "missing_signals": missing_signals,
        "confidence_changes": confidence_changes,
        "summary": summary,
        "compatibility": compatibility,
        "comparison": comparison,
        "provenance": provenance,
    }
    content_digest = framed_content_digest(
        family="diff",
        schema_version=schema_version,
        value=result,
    )
    return {
        "diff_id": f"atldiff-{content_digest[:32]}",
        "content_digest": content_digest,
        **result,
    }
