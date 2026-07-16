"""Comparison-context attachment and deterministic axis classification."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .exceptions import ComparisonAcknowledgementError, SchemaValidationError
from .identity import finalize_report_identity

COMPARISON_CONTEXT_EXTENSION = "org.androidtrustlab.comparison-context"
COMPARISON_AXES = frozenset(
    {
        "same_target_state_change",
        "same_state_observer_change",
        "repeat_measurement",
        "different_target_context",
        "mixed_change",
        "incomparable",
    }
)


def observer_protocol(observer_type: object) -> str:
    """Map a registered observer to its stable visibility protocol."""

    return {
        "adb_shell": "adb",
        "host": "host",
        "root_collector": "root",
        "unprivileged_app": "app",
    }.get(str(observer_type), "unknown")


def _plain_value(value: object) -> object:
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value


def _boolean_context_value(value: object) -> str:
    plain = _plain_value(value)
    return str(plain).lower() if isinstance(plain, bool) else "unknown"


def attach_comparison_context(
    report: dict[str, Any],
    *,
    target_pseudonym: str,
    state_id: str,
    environment_context: str,
) -> dict[str, Any]:
    """Return a report whose comparison metadata is content-identity bound."""

    attached = deepcopy(report)
    observer = attached.get("observer", {})
    target = attached.get("target", {})
    attached.setdefault("extensions", {})[COMPARISON_CONTEXT_EXTENSION] = {
        "target_pseudonym": target_pseudonym,
        "target_class": target.get("target_type", "unknown"),
        "state_id": state_id,
        "experiment_id": attached.get("experiment_id", "unknown"),
        "protocol": observer_protocol(observer.get("observer_type")),
        "observer": observer.get("observer_type", "unknown"),
        "observer_privilege": observer.get("privilege_level", "unknown"),
        "report_schema_version": attached.get("schema_version", "unknown"),
        "environment_context": environment_context,
        "measurement_id": attached.get("collection_event_id", "unknown"),
    }
    return finalize_report_identity(attached)


def comparison_context_from_report(report: dict[str, Any]) -> dict[str, str]:
    """Extract canonical comparison fields with explicit unknown fallbacks."""

    extensions = report.get("extensions", {})
    declared = (
        extensions.get(COMPARISON_CONTEXT_EXTENSION, {})
        if isinstance(extensions, dict)
        else {}
    )
    if not isinstance(declared, dict):
        raise SchemaValidationError("report comparison context must be an object")
    observer = report.get("observer", {})
    target = report.get("target", {})
    return {
        "target_pseudonym": str(declared.get("target_pseudonym", "unknown")),
        "target_class": str(target.get("target_type", "unknown")),
        "state_id": str(declared.get("state_id", "unknown")),
        "experiment_id": str(report.get("experiment_id", "unknown")),
        "protocol": observer_protocol(observer.get("observer_type")),
        "observer": str(observer.get("observer_type", "unknown")),
        "observer_privilege": str(observer.get("privilege_level", "unknown")),
        "report_schema_version": str(report.get("schema_version", "unknown")),
        "environment_context": str(declared.get("environment_context", "unknown")),
        "measurement_id": str(report.get("collection_event_id", "unknown")),
        "observer_effective_uid_is_root": _boolean_context_value(
            report.get("root_state", {}).get(
                "observer_effective_uid_is_root", "unknown"
            )
        ),
    }


def _relationship_reason(
    reasons: list[str],
    *,
    name: str,
    base: str,
    compare: str,
    required: bool = False,
) -> str:
    if base == "unknown" or compare == "unknown":
        reasons.append(f"{name}_missing")
        if required:
            return "missing"
        return "same" if base == compare else "different"
    if base == compare:
        reasons.append(f"{name}_matches")
        return "same"
    reasons.append(f"{name}_differs")
    return "different"


def classify_comparison(
    base_report: dict[str, Any],
    compare_report: dict[str, Any],
    *,
    allow_mixed: bool,
) -> dict[str, Any]:
    """Classify comparison axis and reject unacknowledged mixed changes."""

    base = comparison_context_from_report(base_report)
    compare = comparison_context_from_report(compare_report)
    return classify_comparison_contexts(base, compare, allow_mixed=allow_mixed)


def classify_comparison_contexts(
    base: dict[str, str],
    compare: dict[str, str],
    *,
    allow_mixed: bool,
) -> dict[str, Any]:
    """Classify two already-extracted contexts deterministically."""

    reasons: list[str] = []
    target_identity = _relationship_reason(
        reasons,
        name="target_identity",
        base=base["target_pseudonym"],
        compare=compare["target_pseudonym"],
        required=True,
    )
    target_class = _relationship_reason(
        reasons,
        name="target_class",
        base=base["target_class"],
        compare=compare["target_class"],
        required=True,
    )
    state = _relationship_reason(
        reasons,
        name="state_identity",
        base=base["state_id"],
        compare=compare["state_id"],
        required=True,
    )
    _relationship_reason(
        reasons,
        name="experiment",
        base=base["experiment_id"],
        compare=compare["experiment_id"],
    )
    protocol = _relationship_reason(
        reasons,
        name="protocol",
        base=base["protocol"],
        compare=compare["protocol"],
    )
    observer = _relationship_reason(
        reasons,
        name="observer",
        base=base["observer"],
        compare=compare["observer"],
        required=True,
    )
    observer_privilege = _relationship_reason(
        reasons,
        name="observer_privilege",
        base=base["observer_privilege"],
        compare=compare["observer_privilege"],
    )
    observer_effective_uid = _relationship_reason(
        reasons,
        name="observer_effective_uid",
        base=base["observer_effective_uid_is_root"],
        compare=compare["observer_effective_uid_is_root"],
    )
    _relationship_reason(
        reasons,
        name="report_schema",
        base=base["report_schema_version"],
        compare=compare["report_schema_version"],
        required=True,
    )
    environment = _relationship_reason(
        reasons,
        name="environment_context",
        base=base["environment_context"],
        compare=compare["environment_context"],
        required=True,
    )
    _relationship_reason(
        reasons,
        name="measurement",
        base=base["measurement_id"],
        compare=compare["measurement_id"],
    )

    observer_context_changed = "different" in {
        observer,
        observer_privilege,
        observer_effective_uid,
        protocol,
    }
    missing_required = "missing" in {
        target_identity,
        target_class,
        state,
        observer,
        environment,
    }
    warnings: list[str] = []
    acknowledgement = "not_required"
    if missing_required:
        axis = "incomparable"
        comparability = "incomparable"
        warnings.append("insufficient_metadata_for_comparison")
    elif (
        target_identity == "different"
        or target_class == "different"
        or environment == "different"
    ):
        axis = "different_target_context"
        comparability = "limited"
        warnings.append("different_target_context_limits_attribution")
    elif state == "different" and observer_context_changed:
        axis = "mixed_change"
        comparability = "limited"
        if not allow_mixed:
            raise ComparisonAcknowledgementError(
                "mixed state and observer changes require --allow-mixed"
            )
        acknowledgement = "allow_mixed"
        warnings.append("mixed_state_and_observer_change_acknowledged")
    elif state == "different":
        axis = "same_target_state_change"
        comparability = "comparable"
    elif observer_context_changed:
        axis = "same_state_observer_change"
        comparability = "comparable"
        warnings.append("observer_context_changed_visibility_may_differ")
    else:
        axis = "repeat_measurement"
        comparability = "comparable"

    return {
        "axis": axis,
        "comparability": comparability,
        "reasons": reasons,
        "warnings": warnings,
        "acknowledgement": acknowledgement,
        "visibility_context_changed": observer_context_changed,
        "context": {"base": base, "compare": compare},
    }
