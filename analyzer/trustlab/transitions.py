"""Status-aware evidence transition semantics for trust diffs."""

from __future__ import annotations

from typing import Any, Final

from .compatibility import EvidenceStatus

AVAILABLE_EVIDENCE_STATUSES: Final[frozenset[str]] = frozenset(
    {EvidenceStatus.OBSERVED, EvidenceStatus.OBSERVED_ABSENT}
)
EVIDENCE_STATUSES: Final[frozenset[str]] = frozenset(
    status.value for status in EvidenceStatus
)
TRANSITION_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "visibility_change",
        "collection_quality_change",
        "state_change",
        "context_change",
    }
)


def evidence_is_available(status: str) -> bool:
    """Return whether a status carries successful positive or negative evidence."""

    return status in AVAILABLE_EVIDENCE_STATUSES


def _nested_statuses(value: Any) -> list[str]:
    if isinstance(value, dict):
        status = value.get("status")
        if isinstance(status, str) and status in EVIDENCE_STATUSES:
            return [status]
        return [
            status for nested in value.values() for status in _nested_statuses(nested)
        ]
    if isinstance(value, list):
        return [status for nested in value for status in _nested_statuses(nested)]
    return []


def evidence_status(value: Any) -> str:
    """Return one explicit aggregate status for a diff dimension."""

    statuses = _nested_statuses(value)
    if not statuses:
        return EvidenceStatus.OBSERVED.value
    if len(set(statuses)) == 1:
        return statuses[0]
    if any(evidence_is_available(status) for status in statuses):
        return EvidenceStatus.OBSERVED.value
    for status in (
        EvidenceStatus.INACCESSIBLE,
        EvidenceStatus.COMMAND_ERROR,
        EvidenceStatus.UNSUPPORTED,
        EvidenceStatus.NOT_COLLECTED,
    ):
        if status in statuses:
            return status.value
    return EvidenceStatus.NOT_COLLECTED.value


def classify_status_transition(
    before_status: str,
    after_status: str,
    *,
    comparison_axis: str,
) -> str:
    """Classify a transition without conflating failures with observed absence."""

    if comparison_axis == "same_state_observer_change":
        return "context_change"
    if {before_status, after_status} <= AVAILABLE_EVIDENCE_STATUSES:
        if comparison_axis in {
            "different_target_context",
            "mixed_change",
            "incomparable",
        }:
            return "context_change"
        return "state_change"
    if EvidenceStatus.INACCESSIBLE in {before_status, after_status}:
        return "visibility_change"
    return "collection_quality_change"


def confidence_impact(before_status: str, after_status: str) -> str:
    """Describe only the evidence-confidence effect of a status transition."""

    before_available = evidence_is_available(before_status)
    after_available = evidence_is_available(after_status)
    if not before_available and after_available:
        return "increased"
    if before_available and not after_available:
        return "decreased"
    if before_available and after_available:
        return "unchanged"
    if before_status == after_status:
        return "unchanged"
    return "indeterminate"


def signal_direction(before_status: str, after_status: str) -> str | None:
    """Return the structured signal list that should contain this transition."""

    before_available = evidence_is_available(before_status)
    after_available = evidence_is_available(after_status)
    if not before_available and after_available:
        return "new"
    if before_available and not after_available:
        return "missing"
    return None


def transition_interpretation(
    before_status: str,
    after_status: str,
    transition_class: str,
) -> str:
    """Render a canonical status-specific interpretation."""

    if transition_class == "context_change":
        return (
            f"Evidence changed from {before_status} to {after_status} with the "
            "observer context; this is not classified as a target-state change."
        )
    if transition_class == "visibility_change":
        return (
            f"Evidence visibility changed from {before_status} to {after_status}; "
            "inaccessible is distinct from observed absence."
        )
    if transition_class == "collection_quality_change":
        return (
            f"Collection outcome changed from {before_status} to {after_status}; "
            "this alone does not establish a target-state change."
        )
    return (
        f"Observed evidence changed from {before_status} to {after_status}; both "
        "outcomes are explicit observations."
    )
