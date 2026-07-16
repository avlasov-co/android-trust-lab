"""Report writing helpers."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict

from .exceptions import (
    CollectionError,
    InvalidJSONError,
    MissingFileError,
    OutputWriteError,
    SchemaValidationError,
    safe_path_label,
)


def _reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def write_json(data: Dict[str, Any], path: str | Path) -> None:
    p = Path(path)
    try:
        payload = json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        ) + "\n"
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


def load_json(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    label = safe_path_label(p)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise MissingFileError(f"input file not found: {label}") from exc
    except UnicodeDecodeError as exc:
        raise InvalidJSONError(f"invalid UTF-8 JSON: {label}") from exc
    except OSError as exc:
        raise CollectionError(f"could not read input: {label}") from exc

    try:
        data = json.loads(text, parse_constant=_reject_nonstandard_json_constant)
    except json.JSONDecodeError as exc:
        raise InvalidJSONError(
            f"invalid JSON: {label} (line {exc.lineno}, column {exc.colno})"
        ) from exc
    except ValueError as exc:
        raise InvalidJSONError(f"invalid JSON: {label}") from exc
    if not isinstance(data, dict):
        raise SchemaValidationError("JSON document must be an object")
    return data


def _cell(value: Any) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value).replace("|", "\\|")


def diff_to_markdown(diff: Dict[str, Any]) -> str:
    lines = [f"# Trust Diff {diff.get('diff_id', '')}", "", diff.get("summary", ""), "", "| Dimension | Severity | Before | After |", "|---|---|---|---|"]
    for item in diff.get("changed_dimensions", []):
        lines.append(f"| {item['dimension']} | {item['severity']} | `{_cell(item['before'])}` | `{_cell(item['after'])}` |")
    return "\n".join(lines) + "\n"


def report_to_markdown(report: Dict[str, Any]) -> str:
    lines = [
        f"# Trust Report {report.get('report_id', '')}",
        "",
        f"Experiment: `{report.get('experiment_id', 'unknown')}`",
        f"Target: `{report.get('target', {}).get('target_type', 'unknown')}`",
        f"Observer: `{report.get('observer', {}).get('observer_type', 'unknown')}`",
        "",
        "## Key dimensions",
        "",
        f"- SELinux: `{report.get('selinux', {}).get('mode', 'unknown')}`",
        f"- Root present: `{report.get('root_state', {}).get('su_present', 'unknown')}`",
        f"- Magisk present: `{report.get('magisk_state', {}).get('magisk_binary_present', 'unknown')}`",
        f"- Emulator: `{report.get('emulator_state', {}).get('is_emulator', 'unknown')}`",
    ]
    return "\n".join(lines) + "\n"
