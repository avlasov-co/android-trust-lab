import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyzer"))

import pytest
from jsonschema import Draft202012Validator

import trustlab.validators as validators
from trustlab.exceptions import SchemaValidationError
from trustlab.report_writer import load_json
from trustlab.validators import (
    check_project_schemas,
    load_schema,
    validate_collection_manifest,
    validate_dataset_manifest,
    validate_dataset_source,
    validate_diff,
    validate_report,
)

ROOT = Path(__file__).resolve().parents[1]


def test_project_schemas_are_valid_draft_2020_12():
    for path in (ROOT / "collector" / "schema").glob("*.schema.json"):
        Draft202012Validator.check_schema(load_json(path))


def test_packaged_project_schema_registry_is_meta_schema_valid():
    assert check_project_schemas() == (
        "app_probe_v1_0_0.schema.json",
        "artifact_collection_manifest_v1_0_0.schema.json",
        "collection_manifest_v1_0_0.schema.json",
        "dataset_manifest_v1_0_0.schema.json",
        "dataset_manifest_v2_0_0.schema.json",
        "dataset_source_v1_0_0.schema.json",
        "trust_diff.schema.json",
        "trust_diff_v2_0_0.schema.json",
        "trust_diff_v2_1_0.schema.json",
        "trust_diff_v2_2_0.schema.json",
        "trust_diff_v2_3_0.schema.json",
        "trust_diff_v2_4_0.schema.json",
        "trust_diff_v2_5_0.schema.json",
        "trust_diff_v2_6_0.schema.json",
        "trust_report_v1_0_0.schema.json",
        "trust_report_v2_0_0.schema.json",
        "trust_report_v3_0_0.schema.json",
        "trust_report_v4_0_0.schema.json",
        "trust_report_v5_0_0.schema.json",
        "trust_report_v6_0_0.schema.json",
    )


def test_current_report_and_diff_schemas_are_closed_and_required_complete():
    for name in (
        "trust_report_v6_0_0.schema.json",
        "trust_diff_v2_6_0.schema.json",
    ):
        schema = load_schema(name)
        assert set(schema["required"]) == set(schema["properties"])
        assert schema["additionalProperties"] is False


def test_current_identity_documents_reject_excessive_nesting_before_schema_walk():
    nested: object = None
    for _ in range(70):
        nested = {"value": nested}

    report = load_json(ROOT / "tests/fixtures/sample_normalized_report.json")
    report["extensions"] = {"org.example.nested": {"value": nested}}
    with pytest.raises(SchemaValidationError, match="bounded canonical JSON model"):
        validate_report(report)

    diff = load_json(ROOT / "tests/fixtures/sample_diff.json")
    diff["changed_dimensions"][0]["before"] = nested
    with pytest.raises(SchemaValidationError, match="bounded canonical JSON model"):
        validate_diff(diff)


def test_v3_rejects_canonical_invalid_surrogate_in_excluded_provenance():
    report = load_json(ROOT / "tests/fixtures/sample_normalized_report.json")
    report["extensions"] = {"org.example.invalid": {"value": "\ud800"}}

    with pytest.raises(SchemaValidationError, match="bounded canonical JSON model"):
        validate_report(report)


def test_v2_schema_declares_required_defs_and_closes_structured_objects():
    schema = load_schema("trust_report_v2_0_0.schema.json")
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["additionalProperties"] is False
    definitions = schema["$defs"]
    assert {
        "reportId",
        "experimentId",
        "semver",
        "timestamp",
        "observerMetadata",
        "targetMetadata",
        "evidenceStatus",
        "confidence",
        "provenance",
        "mountObservation",
        "commandResult",
        "limitations",
    } <= set(definitions)

    strict_objects = {
        "evidenceString",
        "evidenceBoolean",
        "evidenceStringList",
        "evidenceStringMap",
        "evidenceInteger",
        "observerMetadata",
        "targetMetadata",
        "bootState",
        "verifiedBoot",
        "selinuxState",
        "mountObservation",
        "mountState",
        "propertyState",
        "rootState",
        "magiskState",
        "processState",
        "emulatorState",
        "commandResult",
        "migrationRecord",
        "provenance",
        "limitations",
    }
    for name in strict_objects:
        definition = definitions[name]
        assert definition["type"] == "object"
        assert definition["additionalProperties"] is False
        assert set(definition["required"]) == set(definition["properties"])


def test_v4_mount_schema_closes_every_structured_mount_object():
    definitions = load_schema("trust_report_v4_0_0.schema.json")["$defs"]
    strict_mount_objects = {
        "mountSourceAttempt",
        "mountObservationSet",
        "mountPropagation",
        "mountRecord",
        "systemMountResolution",
        "dynamicPartitionState",
        "apexMountSet",
        "mountIntegrityContext",
        "mountState",
    }

    for name in strict_mount_objects:
        definition = definitions[name]
        assert definition["type"] == "object"
        assert definition["additionalProperties"] is False
        assert set(definition["required"]) == set(definition["properties"])


def test_invalid_date_time_format_is_rejected():
    report = load_json(ROOT / "tests/fixtures/sample_normalized_report.json")
    report["collection_timestamp"] = "not-a-date"
    with pytest.raises(
        SchemaValidationError,
        match=r"/collection_timestamp: expected format date-time",
    ):
        validate_report(report)


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-04-25T15:06:21Z",
        "2026-04-25t15:06:21z",
        "2016-12-31T23:59:60Z",
        "2016-12-31T15:59:60-08:00",
        "2017-01-01T05:29:60+05:30",
        "2026-04-25T15:06:21.123456+23:59",
        "2026-04-25T15:06:21-00:00",
        "0000-02-29T00:00:00Z",
    ],
)
def test_rfc3339_date_time_boundary_values_are_accepted(timestamp):
    assert validators._is_rfc3339_date_time(timestamp) is True


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-02-30T15:06:21Z",
        "2026-04-25T24:00:00Z",
        "2026-04-25T15:60:00Z",
        "2026-04-25T15:58:60Z",
        "2026-04-25T15:59:60Z",
        "2026-04-25T15:06:61Z",
        "2026-04-25T15:06:21+01:60",
        "2026-04-25T15:06:21+24:00",
        "2026-04-25 15:06:21Z",
        "2026-04-25T15:06:21",
        "2026-04-25T١٥:٠٦:٢١Z",
        "0000-02-30T00:00:00Z",
        "0001-01-01T00:00:60+23:59",
        "9999-12-31T23:59:60-23:59",
    ],
)
def test_non_rfc3339_date_time_boundary_values_are_rejected(timestamp):
    assert validators._is_rfc3339_date_time(timestamp) is False


def test_multiple_validation_errors_are_complete_and_deterministic():
    report = load_json(ROOT / "tests/fixtures/sample_normalized_report.json")
    report.pop("target")
    report["collection_timestamp"] = "not-a-date"
    report["observer"]["privilege_level"] = "superuser"
    messages = []
    issue_snapshots = []
    for _ in range(2):
        with pytest.raises(SchemaValidationError) as caught:
            validate_report(copy.deepcopy(report))
        messages.append(str(caught.value))
        issue_snapshots.append(caught.value.issues)
    assert messages[0] == messages[1]
    assert "(3 errors)" in messages[0]
    assert messages[0].index("/: missing required property: target") < messages[
        0
    ].index("/collection_timestamp")
    assert messages[0].index("/collection_timestamp") < messages[0].index(
        "/observer/privilege_level"
    )
    assert issue_snapshots[0] == issue_snapshots[1]
    assert [issue.instance_path for issue in issue_snapshots[0]] == [
        "/",
        "/collection_timestamp",
        "/observer/privilege_level",
    ]
    assert [issue.validator for issue in issue_snapshots[0]] == [
        "required",
        "format",
        "enum",
    ]
    assert all(issue.schema_path.startswith("/") for issue in issue_snapshots[0])
    assert caught.value.__cause__ is not None


def test_missing_schema_version_collects_all_structured_schema_issues():
    with pytest.raises(SchemaValidationError) as caught:
        validate_report({})

    assert len(caught.value.issues) > 2
    messages = [issue.message for issue in caught.value.issues]
    assert "missing required property: schema_version" in messages
    assert "missing required property: target" in messages
    assert caught.value.__cause__ is not None
    assert "<missing or invalid>" in str(caught.value)


@pytest.mark.parametrize("validator", [validate_report, validate_diff])
@pytest.mark.parametrize("document", [None, [], "not-an-object"])
def test_non_object_documents_keep_the_schema_error_contract(validator, document):
    with pytest.raises(SchemaValidationError, match="must be a JSON object"):
        validator(document)


def test_invalid_schema_version_type_does_not_leak_through_native_cause():
    report = load_json(ROOT / "tests/fixtures/sample_normalized_report.json")
    sensitive_value = "sensitive-device-value"
    report["schema_version"] = {"private": sensitive_value}

    with pytest.raises(SchemaValidationError) as caught:
        validate_report(report)

    assert [issue.instance_path for issue in caught.value.issues] == ["/schema_version"]
    assert sensitive_value not in str(caught.value)
    assert caught.value.__cause__ is not None
    assert sensitive_value not in str(caught.value.__cause__)


def test_malformed_packaged_schema_fails_explicitly(monkeypatch):
    malformed = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": 7,
    }
    monkeypatch.setattr(validators, "load_schema", lambda _name: malformed)
    with pytest.raises(SchemaValidationError, match="project schema is invalid"):
        validate_report(
            load_json(ROOT / "tests/fixtures/sample_normalized_report.json")
        )


def test_missing_packaged_schema_fails_explicitly():
    with pytest.raises(SchemaValidationError, match="schema resource is missing"):
        load_schema("not-packaged.schema.json")


def test_sample_report_schema():
    report = load_json(
        ROOT
        / "datasets"
        / "samples"
        / "stock_avd"
        / "E01_stock_avd__observer-adb__sample.json"
    )
    validate_report(report)


def test_sample_diff_schema():
    diff = load_json(ROOT / "tests" / "fixtures" / "sample_diff.json")
    validate_diff(diff)


def test_sample_collection_manifest_schema():
    manifest = load_json(
        ROOT / "datasets/samples/magisk_collector/collector_manifest_sample.json"
    )
    validate_collection_manifest(manifest)


def test_all_manifest_reports_validate():
    manifest = load_json(ROOT / "datasets" / "manifest.json")
    validate_dataset_manifest(manifest)
    validate_dataset_source(load_json(ROOT / "datasets" / "source.json"))
    artifacts = {
        artifact["artifact_id"]: artifact for artifact in manifest["artifacts"]
    }
    for sample in manifest["samples"]:
        artifact = artifacts[sample["normalized_report_artifact_id"]]
        validate_report(load_json(ROOT / "datasets" / artifact["relative_path"]))


def test_result_diffs_validate():
    for path in (ROOT / "datasets" / "derived" / "diffs").glob("*.json"):
        validate_diff(load_json(path))
