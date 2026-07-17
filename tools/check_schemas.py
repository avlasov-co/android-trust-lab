#!/usr/bin/env python3
"""Validate project schemas and checked-in report, diff, and manifest artifacts."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from trustlab.dataset_manifest import verify_dataset_manifest  # noqa: E402
from trustlab.dimension_registry import (  # noqa: E402
    TRUST_DIMENSION_DEFINITIONS,
)
from trustlab.report_writer import load_json  # noqa: E402
from trustlab.validators import (  # noqa: E402
    check_project_schemas,
    validate_collection_manifest,
    validate_dataset_manifest,
    validate_dataset_source,
    validate_diff,
    validate_report,
)


def main() -> int:
    schema_names = check_project_schemas()

    manifest = load_json(ROOT / "datasets" / "manifest.json")
    validate_dataset_manifest(manifest)
    verify_dataset_manifest(ROOT / "datasets" / "manifest.json")
    source = load_json(ROOT / "datasets" / "source.json")
    validate_dataset_source(source)
    historical_manifest_paths = [
        ROOT / "tests" / "fixtures" / "dataset_manifest_v1_historical.json",
        ROOT / "tests" / "fixtures" / "dataset_manifest_v2_historical.json",
    ]
    for path in historical_manifest_paths:
        validate_dataset_manifest(load_json(path))

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
    report_paths.append(ROOT / "tests" / "fixtures" / "report_v2_historical.json")
    cross_observer_root = ROOT / "tests" / "fixtures" / "cross_observer_bundle"
    report_paths.extend(
        sorted((cross_observer_root / "generated" / "reports").glob("*.json"))
    )
    for path in report_paths:
        validate_report(load_json(path))

    diff_paths = [ROOT / "tests" / "fixtures" / "sample_diff.json"]
    diff_paths.append(ROOT / "tests" / "fixtures" / "diff_v1_historical.json")
    diff_paths.extend(
        artifact_paths[derivation["artifact_id"]]
        for derivation in manifest["derived_diffs"]
    )
    diff_paths.extend(
        sorted((cross_observer_root / "generated" / "diffs").glob("*.json"))
    )
    for path in diff_paths:
        validate_diff(load_json(path))

    collection_manifest_paths = [
        ROOT / "datasets" / artifact["relative_path"]
        for artifact in manifest["artifacts"]
        if artifact["role"] == "collection_manifest"
    ]
    collection_manifest_paths.extend(
        sorted(cross_observer_root.glob("*/collection_manifest.json"))
    )
    for path in collection_manifest_paths:
        validate_collection_manifest(load_json(path))

    print(
        f"validated {len(schema_names)} schemas, "
        f"{len(TRUST_DIMENSION_DEFINITIONS)} dimensions in 1 registry, "
        f"{len(report_paths)} reports, {len(diff_paths)} diffs, and "
        f"{len(collection_manifest_paths)} collection manifests, "
        f"{len(historical_manifest_paths) + 1} dataset manifests, "
        "and 1 dataset source"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
