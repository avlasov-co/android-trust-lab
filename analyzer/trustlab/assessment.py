"""Materiality, direction, and factorized confidence for trust diffs."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .dimension_registry import TRUST_DIMENSION_DEFINITIONS
from .transitions import evidence_is_available

CONFIDENCE_LEVELS = ("low", "moderate", "high")
FIELD_CONFIDENCE_LEVELS = frozenset(
    {"high", "medium", "low", "unassessed", "not_available"}
)


def _direct_value(value: Any) -> Any:
    if isinstance(value, dict) and "status" in value:
        return value.get("value")
    return value


def _mount_integrity_rank(value: Any) -> int | None:
    if not isinstance(value, dict):
        return None
    overlay = _direct_value(value.get("overlay_detected"))
    writable = _direct_value(value.get("writable_sensitive_mounts"))
    if not isinstance(overlay, bool) or not isinstance(writable, list):
        return None
    return 0 if overlay or writable else 1


def _ordered_value_rank(value: Any, ordered_values: Mapping[str, int]) -> int | None:
    plain = _direct_value(value)
    if not isinstance(plain, str):
        return None
    return ordered_values.get(plain)


DirectionRanker = Callable[[Any], int | None]


def _indeterminate_rank(value: Any) -> int | None:
    del value
    return None


def _rank_bootloader_lock(value: Any) -> int | None:
    return _ordered_value_rank(value, {"0": 0, "1": 1})


def _rank_verified_boot(value: Any) -> int | None:
    return _ordered_value_rank(value, {"red": 0, "orange": 1, "yellow": 1, "green": 2})


def _rank_vbmeta_state(value: Any) -> int | None:
    return _ordered_value_rank(value, {"unlocked": 0, "locked": 1})


def _rank_verity_mode(value: Any) -> int | None:
    return _ordered_value_rank(
        value, {"disabled": 0, "logging": 1, "eio": 1, "enforcing": 2}
    )


def _rank_selinux_mode(value: Any) -> int | None:
    return _ordered_value_rank(value, {"disabled": 0, "permissive": 1, "enforcing": 2})


DIRECTION_RANKERS: Mapping[str, DirectionRanker] = {
    "indeterminate_v1": _indeterminate_rank,
    "ordered_bootloader_lock_v1": _rank_bootloader_lock,
    "ordered_verified_boot_v1": _rank_verified_boot,
    "ordered_vbmeta_state_v1": _rank_vbmeta_state,
    "ordered_verity_mode_v1": _rank_verity_mode,
    "ordered_selinux_mode_v1": _rank_selinux_mode,
    "ordered_mount_integrity_v1": _mount_integrity_rank,
    "context_only_v1": _indeterminate_rank,
}
if set(DIRECTION_RANKERS) != {
    definition.direction_rule.policy_id for definition in TRUST_DIMENSION_DEFINITIONS
}:
    raise RuntimeError("trust-dimension direction rules are not fully implemented")


def direction_assessment(
    direction_rule_id: str,
    before: Any,
    after: Any,
    *,
    transition_class: str,
) -> tuple[str, str]:
    """Return direction and a canonical rationale without a trust score."""

    if transition_class == "context_change":
        return "context_change", "observer_or_target_context_changed"
    if transition_class == "visibility_change":
        return "visibility_change", "evidence_visibility_changed"
    if transition_class == "collection_quality_change":
        return "indeterminate", "collection_quality_is_not_target_direction"
    try:
        ranker = DIRECTION_RANKERS[direction_rule_id]
    except KeyError as exc:
        raise ValueError(f"unknown direction rule: {direction_rule_id}") from exc
    before_rank = ranker(before)
    after_rank = ranker(after)
    if before_rank is None or after_rank is None or before_rank == after_rank:
        return "indeterminate", "no_justified_direction_rule"
    if after_rank > before_rank:
        return "improvement", "ordered_dimension_rule_applied"
    return "regression", "ordered_dimension_rule_applied"


def confidence_assessment(
    *,
    before_status: str,
    after_status: str,
    before_field_confidence: str,
    after_field_confidence: str,
    corroborating_evidence_count: int,
    migration_count: int,
    comparability: str,
    warning_count: int,
) -> dict[str, Any]:
    """Compute reviewable confidence from explicit factors, never target trust."""

    before_available = evidence_is_available(before_status)
    after_available = evidence_is_available(after_status)
    if before_available and after_available:
        rank = 3
        evidence_rationale = "both_sides_successfully_observed"
    elif before_available or after_available:
        rank = 2
        evidence_rationale = "one_side_successfully_observed"
    else:
        rank = 1
        evidence_rationale = "neither_side_successfully_observed"

    field_levels = [
        level
        for level in (before_field_confidence, after_field_confidence)
        if level != "not_available"
    ]
    if field_levels:
        field_rank = min(
            {"high": 3, "medium": 2, "low": 1, "unassessed": 1}[level]
            for level in field_levels
        )
        rank = min(rank, field_rank)
        field_rationale = "field_confidence_applied"
    else:
        field_rationale = "field_confidence_unavailable"

    if corroborating_evidence_count >= 2:
        corroboration_rationale = "corroborating_evidence_present"
    else:
        rank = min(rank, 2)
        corroboration_rationale = "corroborating_evidence_limited"

    if migration_count:
        rank = min(rank, 2)
        migration_rationale = "input_migration_reduces_confidence"
    else:
        migration_rationale = "inputs_compared_without_migration"

    if comparability == "incomparable":
        rank = 1
        comparison_rationale = "comparison_incomparable"
    elif comparability == "limited" or warning_count:
        rank = min(rank, 2)
        comparison_rationale = "comparison_warning_reduces_confidence"
    else:
        comparison_rationale = "comparison_fully_comparable"

    return {
        "level": CONFIDENCE_LEVELS[rank - 1],
        "factors": {
            "evidence_statuses": {
                "before": before_status,
                "after": after_status,
            },
            "field_confidence": {
                "before": before_field_confidence,
                "after": after_field_confidence,
            },
            "corroborating_evidence_count": corroborating_evidence_count,
            "migration_count": migration_count,
            "comparability": comparability,
            "comparability_warning_count": warning_count,
        },
        "rationale": [
            evidence_rationale,
            field_rationale,
            corroboration_rationale,
            migration_rationale,
            comparison_rationale,
        ],
    }
