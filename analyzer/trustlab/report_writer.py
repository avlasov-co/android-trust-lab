"""Report writing helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def write_json(data: Dict[str, Any], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_json(path: str | Path) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


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
