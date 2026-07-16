"""Report writing helpers."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .bounded_io import read_bounded_regular_file
from .canonical_json import MAX_CANONICAL_BYTES
from .dimension_registry import TRUST_DIMENSIONS_BY_ID
from .dimension_rendering import dimension_label, render_dimension
from .exceptions import (
    InvalidJSONError,
    OutputWriteError,
    SchemaValidationError,
    safe_path_label,
)
from .privacy import validate_portable_diff, validate_portable_report

MAX_JSON_INPUT_BYTES = MAX_CANONICAL_BYTES


def _reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object member")
        value[key] = item
    return value


def write_json(data: dict[str, Any], path: str | Path) -> None:
    p = Path(path)
    try:
        payload = (
            json.dumps(
                data,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        )
    except (TypeError, ValueError) as exc:
        raise OutputWriteError("could not serialize JSON output") from exc

    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            dir=p.parent,
            prefix=f".{p.name}.",
            suffix=".tmp",
            text=True,
        )
    except OSError as exc:
        raise OutputWriteError(
            f"could not prepare output: {safe_path_label(p)}"
        ) from exc

    temporary_path = Path(temporary_name)
    descriptor_open = True
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            descriptor_open = False
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, p)
    except (OSError, UnicodeError) as exc:
        raise OutputWriteError(f"could not write output: {safe_path_label(p)}") from exc
    finally:
        if descriptor_open:
            os.close(fd)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # Preserve the original write failure; a later verification scan can
            # identify an undeletable temporary file.
            pass


def load_json(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    label = safe_path_label(p)
    try:
        payload = read_bounded_regular_file(
            p,
            limit=MAX_JSON_INPUT_BYTES,
            subject="JSON input",
        )
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidJSONError(f"invalid UTF-8 JSON: {label}") from exc

    try:
        data = json.loads(
            text,
            parse_constant=_reject_nonstandard_json_constant,
            object_pairs_hook=_reject_duplicate_members,
        )
    except json.JSONDecodeError as exc:
        raise InvalidJSONError(
            f"invalid JSON: {label} (line {exc.lineno}, column {exc.colno})"
        ) from exc
    except (RecursionError, ValueError) as exc:
        raise InvalidJSONError(f"invalid JSON: {label}") from exc
    if not isinstance(data, dict):
        raise SchemaValidationError("JSON document must be an object")
    return data


def _cell(value: Any) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value).replace("|", "\\|")


def _evidence_value(value: Any) -> Any:
    if isinstance(value, dict) and {"status", "value", "reason"} <= value.keys():
        if value["status"] in {"observed", "observed_absent"}:
            return value["value"]
        return value["status"]
    return value


def _registered_dimension_label(dimension: object, *, include_id: bool = True) -> str:
    if isinstance(dimension, str) and dimension in TRUST_DIMENSIONS_BY_ID:
        return dimension_label(dimension, include_id=include_id)
    return str(dimension)


def diff_to_markdown(diff: dict[str, Any]) -> str:
    validate_portable_diff(diff)
    compatibility = diff.get("compatibility", {})
    versions = compatibility.get("input_schema_versions", {})
    migrations = compatibility.get("migrations", {})
    base_migrations = (
        ", ".join(item["migration_id"] for item in migrations.get("base", [])) or "none"
    )
    compare_migrations = (
        ", ".join(item["migration_id"] for item in migrations.get("compare", []))
        or "none"
    )
    warnings = ", ".join(compatibility.get("warnings", [])) or "none"
    comparison = diff.get("comparison", {})
    comparison_reasons = ", ".join(comparison.get("reasons", [])) or "none"
    warning_messages = {
        "different_target_context_limits_attribution": (
            "Different target context limits causal attribution."
        ),
        "insufficient_metadata_for_comparison": (
            "Required comparison metadata is missing; inputs are incomparable."
        ),
        "mixed_state_and_observer_change_acknowledged": (
            "Target state and observer context both changed; attribution is confounded."
        ),
        "observer_context_changed_visibility_may_differ": (
            "Observer context changed; visibility differences are not target-state changes."
        ),
    }
    lines = [
        f"# Trust Diff {diff.get('diff_id', '')}",
        "",
        diff.get("summary", ""),
        "",
        "## Compatibility",
        "",
        f"- Input schemas: base `{versions.get('base', 'unknown')}`, compare `{versions.get('compare', 'unknown')}`",
        f"- Canonical comparison schema: `{compatibility.get('canonical_comparison_schema_version', 'unknown')}`",
        f"- Base migrations: {base_migrations}",
        f"- Compare migrations: {compare_migrations}",
        f"- Warnings: {warnings}",
        "",
        "## Comparison",
        "",
        f"- Axis: `{comparison.get('axis', 'unknown')}`",
        f"- Comparability: `{comparison.get('comparability', 'unknown')}`",
        f"- Reasons: {comparison_reasons}",
        "",
        *[
            f"> **Warning:** {warning_messages[warning]}"
            for warning in comparison.get("warnings", [])
        ],
        *([""] if comparison.get("warnings") else []),
        "| Dimension | Materiality | Direction | Confidence | Transition | Before | After | Rationale |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in diff.get("changed_dimensions", []):
        transition = item.get("transition", {})
        materiality = item.get(
            "materiality", f"legacy severity: {item.get('severity', 'unknown')}"
        )
        confidence = item.get("confidence", {}).get("level", "not recorded")
        rationale = ", ".join(item.get("rationale", [])) or "not recorded"
        lines.append(
            f"| {_registered_dimension_label(item['dimension'])} | {materiality} | "
            f"{item.get('direction', 'not recorded')} | {confidence} | "
            f"{transition.get('classification', 'unknown')} "
            f"({transition.get('before_status', 'unknown')} → "
            f"{transition.get('after_status', 'unknown')}) | "
            f"`{_cell(item['before'])}` | `{_cell(item['after'])}` | {rationale} |"
        )
    for title, field in (
        ("Signals Became Available", "new_signals"),
        ("Signals Became Unavailable", "missing_signals"),
    ):
        lines.extend(["", f"## {title}", ""])
        signals = diff.get(field, [])
        if not signals:
            lines.append("None.")
            continue
        lines.extend(
            [
                "| Dimension | Materiality | Direction | Confidence | Status transition | Classification | Confidence impact | Observed values | Source evidence | Evidence paths | Rationale | Interpretation |",
                "|---|---|---|---|---|---|---|---|---|---|---|---|",
            ]
        )
        for signal in signals:
            if isinstance(signal, str):
                lines.append(
                    f"| {_registered_dimension_label(signal)} | legacy | not recorded | not recorded | legacy | "
                    "legacy | indeterminate | `unknown` | `unknown` | `unknown` | "
                    "not recorded | Historical diff did not record structured status "
                    "transition metadata. |"
                )
                continue
            lines.append(
                f"| {_registered_dimension_label(signal['dimension'])} | "
                f"{signal.get('materiality', 'not recorded')} | "
                f"{signal.get('direction', 'not recorded')} | "
                f"{signal.get('confidence', {}).get('level', 'not recorded')} | "
                f"{signal['before_status']} → "
                f"{signal['after_status']} | {signal['classification']} | "
                f"{signal['confidence_impact']} | "
                f"`{_cell(signal['observed_values'])}` | "
                f"`{_cell(signal['source_evidence'])}` | "
                f"`{_cell(signal.get('evidence_paths', []))}` | "
                f"{', '.join(signal.get('rationale', [])) or 'not recorded'} | "
                f"{signal['interpretation']} |"
            )
    return "\n".join(lines) + "\n"


def _status(value: Any) -> str:
    if isinstance(value, dict):
        status = value.get("status")
        if isinstance(status, str):
            return status
    return "not_collected"


def _selected_process_summary(process_state: dict[str, Any]) -> str:
    summaries = []
    for item in process_state.get("selected_processes", []):
        if not isinstance(item, dict):
            continue
        name = item.get("name", "unknown")
        visibility = _status(item.get("visibility"))
        context = item.get("context")
        context_value = (
            "observed_absent"
            if _status(context) == "observed_absent"
            else _evidence_value(context)
        )
        summaries.append(f"{name}={visibility}/{context_value}")
    return ", ".join(summaries) or "not_collected"


def report_to_markdown(report: dict[str, Any]) -> str:
    validate_portable_report(report)
    selinux = report.get("selinux", {})
    process_state = report.get("process_state", {})
    root_state = report.get("root_state", {})
    magisk_state = report.get("magisk_state", {})
    confidence = report.get("verified_boot", {}).get("confidence", {})
    process_limitations = process_state.get("limitations", [])
    process_capture = _status(
        {"status": process_state.get("capture_status", "not_collected")}
    )
    lines = [
        f"# Trust Report {report.get('report_id', '')}",
        "",
        f"Experiment: `{report.get('experiment_id', 'unknown')}`",
        f"Target: `{report.get('target', {}).get('target_type', 'unknown')}`",
        f"Observer: `{report.get('observer', {}).get('observer_type', 'unknown')}`",
        "",
        "## Key dimensions",
        "",
        f"- {_registered_dimension_label('selinux_mode', include_id=False)}: `{render_dimension(report, 'selinux_mode')}`",
        f"- {_registered_dimension_label('selinux_current_context', include_id=False)}: `{render_dimension(report, 'selinux_current_context')}`",
        f"- {_registered_dimension_label('selinux_denial_collection', include_id=False)}: `{_status(selinux.get('denial_collection'))}`",
        f"- Process capture: `{process_capture}` (scope `{process_state.get('scope', 'unknown')}`, completeness `{process_state.get('completeness', 'unknown')}`)",
        f"- {_registered_dimension_label('selected_process_visibility', include_id=False)} (visibility/context): `{_selected_process_summary(process_state)}`",
        f"- Process limitations: `{', '.join(process_limitations) if process_limitations else 'none'}`",
        f"- Observer effective UID is root: `{_evidence_value(root_state.get('observer_effective_uid_is_root', 'not_collected'))}`",
        f"- {_registered_dimension_label('root_shell_availability', include_id=False)}: `{render_dimension(report, 'root_shell_availability')}`",
        f"- {_registered_dimension_label('su_binary_visibility', include_id=False)}: `{render_dimension(report, 'su_binary_visibility')}`",
        f"- {_registered_dimension_label('su_invocation_tested', include_id=False)}: `{render_dimension(report, 'su_invocation_tested')}`",
        f"- {_registered_dimension_label('su_invocation_result', include_id=False)}: `{render_dimension(report, 'su_invocation_result')}`",
        f"- {_registered_dimension_label('root_management_artifact', include_id=False)}: `{render_dimension(report, 'root_management_artifact')}`",
        f"- {_registered_dimension_label('magisk_binary_visibility', include_id=False)}: `{render_dimension(report, 'magisk_binary_visibility')}`",
        f"- {_registered_dimension_label('magisk_daemon_visibility', include_id=False)}: `{render_dimension(report, 'magisk_daemon_visibility')}`",
        f"- {_registered_dimension_label('magisk_process_visibility', include_id=False)}: `{render_dimension(report, 'magisk_process_visibility')}`",
        f"- {_registered_dimension_label('zygisk_visibility', include_id=False)}: `{render_dimension(report, 'zygisk_visibility')}`",
        f"- {_registered_dimension_label('magisk_version_name', include_id=False)}: `{render_dimension(report, 'magisk_version_name')}`; {_registered_dimension_label('magisk_version_code', include_id=False)}: `{render_dimension(report, 'magisk_version_code')}`",
        f"- {_registered_dimension_label('magisk_module_context', include_id=False)}: `{render_dimension(report, 'magisk_module_context')}`",
        f"- {_registered_dimension_label('magisk_command_status', include_id=False)}: `{_status(magisk_state.get('command_status'))}`",
        f"- Verified-boot confidence: `{confidence.get('level', 'unassessed')}` (source `{confidence.get('source_quality', 'unavailable')}`, command `{confidence.get('command_success', 'not_collected')}`, observer `{confidence.get('observer_capability', 'unspecified')}`)",
        f"- {_registered_dimension_label('emulator_state', include_id=False)}: `{render_dimension(report, 'emulator_state')}`",
    ]
    return "\n".join(lines) + "\n"
