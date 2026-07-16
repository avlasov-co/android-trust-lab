#!/usr/bin/env python3
"""Validate project schemas and checked-in report, diff, and manifest artifacts."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from trustlab.dataset_manifest import verify_dataset_manifest  # noqa: E402
from trustlab.report_writer import load_json  # noqa: E402
from trustlab.validators import (  # noqa: E402
    check_project_schemas,
    validate_collection_manifest,
    validate_dataset_manifest,
    validate_dataset_source,
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
    validate_dataset_manifest(manifest)
    verify_dataset_manifest(ROOT / "datasets" / "manifest.json")
    source = load_object(ROOT / "datasets" / "source.json")
    validate_dataset_source(source)
    legacy_manifest = load_object(
        ROOT / "tests" / "fixtures" / "dataset_manifest_v1_historical.json"
    )
    validate_dataset_manifest(legacy_manifest)

    artifact_paths = {
        artifact["artifact_id"]: ROOT / "datasets" / artifact["relative_path"]
        for artifact in manifest["artifacts"]
    }
    report_paths = [
        artifact_paths[sample["normalized_report_artifact_id"]]
        for sample in manifest["samples"]
    ]
    report_paths.append(ROOT / "tests" / "fixtures" / "sample_normalized_report.json")
    report_paths.append(ROOT / "tests" / "fixtures" / "report_v1_historical.json")
    for path in report_paths:
        validate_report(load_json(path))

    diff_paths = [ROOT / "tests" / "fixtures" / "sample_diff.json"]
    diff_paths.extend(
        artifact_paths[derivation["artifact_id"]]
        for derivation in manifest["derived_diffs"]
    )
    for path in diff_paths:
        validate_diff(load_json(path))

    collection_manifest_paths = [
        ROOT / "datasets" / artifact["relative_path"]
        for artifact in manifest["artifacts"]
        if artifact["role"] == "collection_manifest"
    ]
    for path in collection_manifest_paths:
        validate_collection_manifest(load_json(path))

    print(
        f"validated {len(schema_names)} schemas, "
        f"{len(report_paths)} reports, {len(diff_paths)} diffs, and "
        f"{len(collection_manifest_paths)} collection manifest, 2 dataset manifests, "
        "and 1 dataset source"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
