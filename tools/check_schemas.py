#!/usr/bin/env python3
"""Validate project schemas and checked-in report, diff, and manifest artifacts."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from trustlab.report_writer import load_json  # noqa: E402
from trustlab.validators import (  # noqa: E402
    check_project_schemas,
    validate_collection_manifest,
    validate_diff,
    validate_report,
)


def load_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"expected a JSON object: {path.relative_to(ROOT)}")
    return data


def main() -> int:
    schema_names = check_project_schemas()

    manifest = load_object(ROOT / "datasets" / "manifest.json")
    report_paths = [
        ROOT / sample["report_path"] for sample in manifest.get("samples", [])
    ]
    report_paths.append(ROOT / "tests" / "fixtures" / "sample_normalized_report.json")
    report_paths.append(ROOT / "tests" / "fixtures" / "report_v1_historical.json")
    for path in report_paths:
        validate_report(load_json(path))

    diff_paths = [ROOT / "tests" / "fixtures" / "sample_diff.json"]
    diff_paths.extend(sorted((ROOT / "results" / "diffs").glob("*.json")))
    for path in diff_paths:
        validate_diff(load_json(path))

    collection_manifest_paths = [
        ROOT
        / "datasets"
        / "samples"
        / "magisk_collector"
        / "collector_manifest_sample.json"
    ]
    for path in collection_manifest_paths:
        validate_collection_manifest(load_json(path))

    print(
        f"validated {len(schema_names)} schemas, "
        f"{len(report_paths)} reports, {len(diff_paths)} diffs, and "
        f"{len(collection_manifest_paths)} collection manifest"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
