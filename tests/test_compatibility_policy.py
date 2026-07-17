from __future__ import annotations

import copy
import re
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any, cast

import pytest

import trustlab.validators as validators_module
from trustlab.compatibility import (
    REPORT_MIGRATION_REGISTRY,
    SCHEMA_RESOURCE_REGISTRY,
    SCHEMA_SUPPORT,
    EvidenceStatus,
    SchemaFamily,
    SchemaSupport,
    current_write_version,
    report_migration_path,
    require_supported_schema_version,
    schema_resource_name,
    supported_schema_versions,
)
from trustlab.diff import make_diff
from trustlab.exceptions import SchemaValidationError, UnsupportedSchemaVersionError
from trustlab.normalizer import normalize_raw_file
from trustlab.report_writer import load_json
from trustlab.validators import (
    validate_dataset_manifest,
    validate_dataset_source,
    validate_diff,
    validate_report,
)

SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
ROOT = Path(__file__).resolve().parents[1]


def test_supported_version_table_is_complete_and_exact():
    assert dict(SCHEMA_SUPPORT) == {
        SchemaFamily.REPORT: SchemaSupport(
            current_write_version="6.0.0",
            readable_versions=frozenset(
                {"1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0"}
            ),
        ),
        SchemaFamily.DIFF: SchemaSupport(
            current_write_version="2.8.0",
            readable_versions=frozenset(
                {
                    "1.0.0",
                    "2.0.0",
                    "2.1.0",
                    "2.2.0",
                    "2.3.0",
                    "2.4.0",
                    "2.5.0",
                    "2.6.0",
                    "2.7.0",
                    "2.8.0",
                }
            ),
        ),
        SchemaFamily.DATASET_MANIFEST: SchemaSupport(
            current_write_version="2.0.0",
            readable_versions=frozenset({"1.0.0", "2.0.0"}),
        ),
        SchemaFamily.COLLECTION_MANIFEST: SchemaSupport(
            current_write_version="1.0.0",
            readable_versions=frozenset({"1.0.0"}),
        ),
        SchemaFamily.APP_PROBE: SchemaSupport(
            current_write_version="2.0.0",
            readable_versions=frozenset({"1.0.0", "2.0.0"}),
        ),
        SchemaFamily.EXPERIMENT_SPEC: SchemaSupport(
            current_write_version=None,
            readable_versions=frozenset(),
            planned_version="1.0.0",
        ),
    }
    for support in SCHEMA_SUPPORT.values():
        versions = set(support.readable_versions)
        versions.update(
            version
            for version in (support.current_write_version, support.planned_version)
            if version is not None
        )
        assert all(SEMVER.fullmatch(version) for version in versions)


def test_schema_resource_registry_is_exact_and_fail_closed():
    assert dict(SCHEMA_RESOURCE_REGISTRY) == {
        (SchemaFamily.REPORT, "1.0.0"): "trust_report_v1_0_0.schema.json",
        (SchemaFamily.REPORT, "2.0.0"): "trust_report_v2_0_0.schema.json",
        (SchemaFamily.REPORT, "3.0.0"): "trust_report_v3_0_0.schema.json",
        (SchemaFamily.REPORT, "4.0.0"): "trust_report_v4_0_0.schema.json",
        (SchemaFamily.REPORT, "5.0.0"): "trust_report_v5_0_0.schema.json",
        (SchemaFamily.REPORT, "6.0.0"): "trust_report_v6_0_0.schema.json",
        (SchemaFamily.DIFF, "1.0.0"): "trust_diff.schema.json",
        (SchemaFamily.DIFF, "2.0.0"): "trust_diff_v2_0_0.schema.json",
        (SchemaFamily.DIFF, "2.1.0"): "trust_diff_v2_1_0.schema.json",
        (SchemaFamily.DIFF, "2.2.0"): "trust_diff_v2_2_0.schema.json",
        (SchemaFamily.DIFF, "2.3.0"): "trust_diff_v2_3_0.schema.json",
        (SchemaFamily.DIFF, "2.4.0"): "trust_diff_v2_4_0.schema.json",
        (SchemaFamily.DIFF, "2.5.0"): "trust_diff_v2_5_0.schema.json",
        (SchemaFamily.DIFF, "2.6.0"): "trust_diff_v2_6_0.schema.json",
        (SchemaFamily.DIFF, "2.7.0"): "trust_diff_v2_7_0.schema.json",
        (SchemaFamily.DIFF, "2.8.0"): "trust_diff_v2_8_0.schema.json",
        (SchemaFamily.DATASET_MANIFEST, "1.0.0"): (
            "dataset_manifest_v1_0_0.schema.json"
        ),
        (SchemaFamily.DATASET_MANIFEST, "2.0.0"): (
            "dataset_manifest_v2_0_0.schema.json"
        ),
        (SchemaFamily.COLLECTION_MANIFEST, "1.0.0"): (
            "collection_manifest_v1_0_0.schema.json"
        ),
        (SchemaFamily.APP_PROBE, "1.0.0"): "app_probe_v1_0_0.schema.json",
        (SchemaFamily.APP_PROBE, "2.0.0"): "app_probe_v2_0_0.schema.json",
    }
    assert (
        schema_resource_name(SchemaFamily.REPORT, "1.0.0")
        == "trust_report_v1_0_0.schema.json"
    )
    with pytest.raises(UnsupportedSchemaVersionError):
        schema_resource_name(SchemaFamily.REPORT, "7.0.0")
    assert schema_resource_name(SchemaFamily.DATASET_MANIFEST, "2.0.0") == (
        "dataset_manifest_v2_0_0.schema.json"
    )


def test_schema_registries_and_support_records_are_immutable():
    report_support = SCHEMA_SUPPORT[SchemaFamily.REPORT]
    with pytest.raises(TypeError):
        cast(Any, SCHEMA_SUPPORT)[SchemaFamily.REPORT] = report_support
    with pytest.raises(TypeError):
        cast(Any, SCHEMA_RESOURCE_REGISTRY)[SchemaFamily.REPORT, "3.0.0"] = (
            "other.schema.json"
        )
    with pytest.raises(FrozenInstanceError):
        cast(Any, report_support).current_write_version = "3.0.0"
    with pytest.raises(AttributeError):
        cast(Any, report_support.readable_versions).add("3.0.0")
    assert current_write_version(SchemaFamily.REPORT) == "6.0.0"


def test_report_migrations_resolve_only_through_the_registered_chain():
    assert list(REPORT_MIGRATION_REGISTRY) == [
        "1.0.0",
        "2.0.0",
        "3.0.0",
        "4.0.0",
        "5.0.0",
    ]
    assert [step.migration_id for step in report_migration_path("1.0.0")] == [
        "report-v1-to-v2",
        "report-v2-to-v3",
        "report-v3-to-v4",
        "report-v4-to-v5",
        "report-v5-to-v6",
    ]
    assert report_migration_path("6.0.0") == ()
    assert require_supported_schema_version(SchemaFamily.REPORT, "2.0.0") == ("2.0.0")
    with pytest.raises(SchemaValidationError, match="semantic version"):
        require_supported_schema_version(SchemaFamily.REPORT, "v2")
    with pytest.raises(SchemaValidationError, match="semantic version"):
        require_supported_schema_version(SchemaFamily.REPORT, None)
    with pytest.raises(UnsupportedSchemaVersionError, match="unsupported"):
        report_migration_path("7.0.0")
    with pytest.raises(UnsupportedSchemaVersionError, match="downgrade"):
        report_migration_path("6.0.0", target_version="5.0.0")


def test_supported_schema_versions_do_not_imply_planned_support():
    assert supported_schema_versions(SchemaFamily.REPORT) == frozenset(
        {"1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0"}
    )
    assert supported_schema_versions(SchemaFamily.COLLECTION_MANIFEST) == frozenset(
        {"1.0.0"}
    )
    assert supported_schema_versions(SchemaFamily.APP_PROBE) == frozenset(
        {"1.0.0", "2.0.0"}
    )
    assert supported_schema_versions(SchemaFamily.EXPERIMENT_SPEC) == frozenset()
    assert current_write_version(SchemaFamily.REPORT) == "6.0.0"
    assert current_write_version(SchemaFamily.COLLECTION_MANIFEST) == "1.0.0"
    assert current_write_version(SchemaFamily.APP_PROBE) == "2.0.0"


def test_writers_emit_literal_versions_declared_by_the_support_table():
    report = normalize_raw_file(
        ROOT / "tests/fixtures/sample_raw_report.txt",
        collection_timestamp="2026-04-25T15:06:21Z",
    )
    diff = make_diff(report, report)
    dataset_manifest = load_json(ROOT / "datasets/manifest.json")

    assert {
        "report": report["schema_version"],
        "diff": diff["schema_version"],
        "dataset_manifest": dataset_manifest["schema_version"],
    } == {
        "report": "6.0.0",
        "diff": "2.8.0",
        "dataset_manifest": "2.0.0",
    }
    assert report["schema_version"] == current_write_version(SchemaFamily.REPORT)
    assert diff["schema_version"] == current_write_version(SchemaFamily.DIFF)
    assert dataset_manifest["schema_version"] == current_write_version(
        SchemaFamily.DATASET_MANIFEST
    )


@pytest.mark.parametrize(
    ("validator", "fixture", "expected_resource"),
    [
        (
            validate_report,
            "tests/fixtures/sample_normalized_report.json",
            "trust_report_v6_0_0.schema.json",
        ),
        (
            validate_report,
            "tests/fixtures/report_v1_historical.json",
            "trust_report_v1_0_0.schema.json",
        ),
        (
            validate_report,
            "tests/fixtures/report_v2_historical.json",
            "trust_report_v2_0_0.schema.json",
        ),
        (
            validate_diff,
            "tests/fixtures/sample_diff.json",
            "trust_diff_v2_8_0.schema.json",
        ),
        (
            validate_diff,
            "tests/fixtures/diff_v1_historical.json",
            "trust_diff.schema.json",
        ),
        (
            validate_dataset_manifest,
            "tests/fixtures/dataset_manifest_v1_historical.json",
            "dataset_manifest_v1_0_0.schema.json",
        ),
        (
            validate_dataset_manifest,
            "datasets/manifest.json",
            "dataset_manifest_v2_0_0.schema.json",
        ),
        (
            validate_dataset_source,
            "datasets/source.json",
            "dataset_source_v1_0_0.schema.json",
        ),
    ],
)
def test_validators_dispatch_exact_versions_and_reject_unknown_ones(
    monkeypatch, validator, fixture, expected_resource
):
    loaded_resources: list[str] = []
    original_load_schema = validators_module.load_schema

    def tracking_load_schema(name: str) -> dict[str, Any]:
        loaded_resources.append(name)
        return original_load_schema(name)

    monkeypatch.setattr(validators_module, "load_schema", tracking_load_schema)
    document = load_json(ROOT / fixture)
    validator(document)
    assert loaded_resources == [expected_resource]

    unsupported = copy.deepcopy(document)
    unsupported["schema_version"] = "9.9.9"
    with pytest.raises(UnsupportedSchemaVersionError):
        validator(unsupported)
    assert loaded_resources == [expected_resource]


def test_evidence_statuses_are_distinct_and_canonical():
    assert {status.value for status in EvidenceStatus} == {
        "observed",
        "observed_absent",
        "inaccessible",
        "not_collected",
        "command_error",
        "unsupported",
    }
