#!/usr/bin/env python3
"""Validate project schemas and every checked-in report/diff that claims them."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from trustlab.report_writer import load_json  # noqa: E402
from trustlab.validators import validate_diff, validate_report  # noqa: E402


def load_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"expected a JSON object: {path.relative_to(ROOT)}")
    return data


def main() -> int:
    schema_paths = sorted((ROOT / "collector" / "schema").glob("*.schema.json"))
    if not schema_paths:
        raise FileNotFoundError("no project schemas found")

    for path in schema_paths:
        Draft202012Validator.check_schema(load_object(path))

    manifest = load_object(ROOT / "datasets" / "manifest.json")
    report_paths = [ROOT / sample["report_path"] for sample in manifest.get("samples", [])]
    report_paths.append(ROOT / "tests" / "fixtures" / "sample_normalized_report.json")
    for path in report_paths:
        validate_report(load_json(path))

    diff_paths = [ROOT / "tests" / "fixtures" / "sample_diff.json"]
    diff_paths.extend(sorted((ROOT / "results" / "diffs").glob("*.json")))
    for path in diff_paths:
        validate_diff(load_json(path))

    print(
        f"validated {len(schema_paths)} schemas, "
        f"{len(report_paths)} reports, and {len(diff_paths)} diffs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
