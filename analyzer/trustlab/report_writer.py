"""Report writing helpers."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .bounded_io import read_bounded_regular_file
from .canonical_json import MAX_CANONICAL_BYTES
from .exceptions import (
    InvalidJSONError,
    OutputWriteError,
    SchemaValidationError,
    safe_path_label,
)

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


def diff_to_markdown(diff: dict[str, Any]) -> str:
    lines = [
        f"# Trust Diff {diff.get('diff_id', '')}",
        "",
        diff.get("summary", ""),
        "",
        "| Dimension | Severity | Before | After |",
        "|---|---|---|---|",
    ]
    for item in diff.get("changed_dimensions", []):
        lines.append(
            f"| {item['dimension']} | {item['severity']} | `{_cell(item['before'])}` | `{_cell(item['after'])}` |"
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
    selinux = report.get("selinux", {})
    process_state = report.get("process_state", {})
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
        f"- SELinux mode: `{_evidence_value(selinux.get('policy_mode', selinux.get('mode', 'not_collected')))}`",
        f"- SELinux current context: `{_evidence_value(selinux.get('current_context', 'not_collected'))}`",
        f"- SELinux denial collection: `{_status(selinux.get('denial_collection'))}`",
        f"- Process capture: `{process_capture}` (scope `{process_state.get('scope', 'unknown')}`, completeness `{process_state.get('completeness', 'unknown')}`)",
        f"- Selected processes (visibility/context): `{_selected_process_summary(process_state)}`",
        f"- Process limitations: `{', '.join(process_limitations) if process_limitations else 'none'}`",
        f"- Root present: `{_evidence_value(report.get('root_state', {}).get('su_present', 'not_collected'))}`",
        f"- Magisk present: `{_evidence_value(report.get('magisk_state', {}).get('magisk_binary_present', 'not_collected'))}`",
        f"- Emulator: `{_evidence_value(report.get('emulator_state', {}).get('is_emulator', 'not_collected'))}`",
    ]
    return "\n".join(lines) + "\n"
