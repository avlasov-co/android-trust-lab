from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import trustlab.compatibility as compatibility_module
import trustlab.report_v4 as report_v4_module
import trustlab.report_v5 as report_v5_module
from trustlab import cli
from trustlab.exceptions import SchemaValidationError, UnsupportedSchemaVersionError
from trustlab.identity import finalize_report_identity
from trustlab.migration_codec import encode_legacy_report, legacy_report_digest
from trustlab.migrations import (
    migrate_report_to_current,
    migrate_report_v1_to_v2,
    migrate_report_v2_to_v3,
    migrate_report_v3_to_v4,
    migrate_report_v4_to_v5,
)
from trustlab.normalizer import normalize_raw_file
from trustlab.report_writer import load_json, write_json
from trustlab.validators import validate_report

ROOT = Path(__file__).resolve().parents[1]
V1_REPORT = ROOT / "tests/fixtures/report_v1_historical.json"
V2_REPORT = ROOT / "tests/fixtures/report_v2_historical.json"
GOLDEN = ROOT / "tests/golden/report_v1_to_v2_expectations.json"


def canonical_json(document: object) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def current_report() -> dict[str, object]:
    return normalize_raw_file(
        ROOT / "tests/fixtures/sample_raw_report.txt",
        experiment_id="E01_stock_avd",
        target_type="avd",
        observer_type="adb_shell",
        collection_timestamp="2026-04-25T15:06:21Z",
        raw_artifact_ref="tests/fixtures/sample_raw_report.txt",
    )


def test_golden_v1_to_v2_migration_is_exact_and_preserves_source():
    source_bytes = V1_REPORT.read_bytes()
    source = load_json(V1_REPORT)
    original = copy.deepcopy(source)
    golden = load_json(GOLDEN)

    migrated = migrate_report_v1_to_v2(source)
    assert source == original
    assert hashlib.sha256(source_bytes).hexdigest() == golden["source_file_sha256"]
    assert (
        hashlib.sha256(canonical_json(migrated)).hexdigest()
        == golden["migrated_canonical_sha256"]
    )
    record = migrated["provenance"]["migration_history"][0]
    observed = {
        "schema_version": migrated["schema_version"],
        "source_schema_version": migrated["provenance"]["source_schema_version"],
        "migration_id": record["migration_id"],
        "target_schema_version": record["target_schema_version"],
        "build_fingerprint_status": migrated["target"]["build_fingerprint"]["status"],
        "crypto_properties_status": migrated["properties"]["crypto"]["status"],
        "denials_collected_status": migrated["selinux"]["denials_collected"]["status"],
        "root_presence_status": migrated["root_state"]["su_present"]["status"],
    }
    assert observed == golden["expected"]
    preserved = migrated["extensions"]["org.androidtrustlab.migration"]
    assert preserved["encoding"] == "canonical-json-text-v1"
    assert json.loads(preserved["source_report_json"]) == source
    validate_report(source)
    validate_report(migrated)


def test_migration_is_deterministic_and_round_trip_stable(tmp_path):
    source = load_json(V1_REPORT)
    first = migrate_report_v1_to_v2(source)
    second = migrate_report_v1_to_v2(copy.deepcopy(source))
    assert first == second

    output = tmp_path / "migrated.json"
    write_json(first, output)
    loaded = load_json(output)
    assert loaded == first
    validate_report(loaded)


def test_migration_rejects_non_v1_source():
    with pytest.raises(UnsupportedSchemaVersionError, match="requires schema version"):
        migrate_report_v1_to_v2(current_report())


def test_valid_but_loose_v1_values_migrate_without_inventing_evidence():
    source = load_json(V1_REPORT)
    source["report_id"] = "legacy report id"
    source["experiment_id"] = "Legacy Experiment"
    source["observer"]["collection_method"] = "RAW"
    source["target"]["model"] = "x" * 5000
    source["properties"] = {"security": {"legacy": [1.5]}}
    source["process_state"] = {"legacy_freeform": [1.5]}
    source["raw_artifacts"] = ["", "x" * 1025]
    validate_report(source)

    migrated = migrate_report_v1_to_v2(source)
    validate_report(migrated)
    assert migrated["report_id"].startswith("atl-")
    assert migrated["experiment_id"] == "unknown"
    assert migrated["observer"]["collection_method"] == "legacy_migration"
    assert migrated["target"]["model"]["status"] == "not_collected"
    assert migrated["properties"]["security"]["status"] == "not_collected"
    assert migrated["process_state"]["process_contexts_available"]["status"] == (
        "not_collected"
    )
    assert migrated["raw_artifacts"] == []
    preserved = migrated["extensions"]["org.androidtrustlab.migration"]
    assert json.loads(preserved["source_report_json"]) == source


def test_only_documented_v1_inaccessible_sentinel_becomes_access_denial():
    source = load_json(V1_REPORT)
    source["target"]["model"] = "inaccessible"
    source["selinux"]["mode"] = "inaccessible"

    migrated = migrate_report_v1_to_v2(source)

    assert migrated["target"]["model"] == {
        "status": "observed",
        "value": "inaccessible",
        "reason": None,
    }
    assert migrated["selinux"]["mode"]["status"] == "inaccessible"


def test_valid_v1_values_outside_v2_bounds_are_preserved_without_blocking_migration():
    source = load_json(V1_REPORT)
    source["properties"]["all_count"] = 9_007_199_254_740_992
    source["process_state"]["raw_line_count"] = 9_007_199_254_740_992
    source["limitations"]["collection_errors"] = [
        "x" * 1025,
        *[f"error-{index}" for index in range(300)],
    ]
    validate_report(source)

    migrated = migrate_report_v1_to_v2(source)

    validate_report(migrated)
    assert migrated["properties"]["all_count"]["status"] == "not_collected"
    assert migrated["process_state"]["raw_line_count"]["status"] == "not_collected"
    assert len(migrated["limitations"]["collection_errors"]) == 256
    assert all(
        len(error) <= 1024 for error in migrated["limitations"]["collection_errors"]
    )
    assert (
        json.loads(
            migrated["extensions"]["org.androidtrustlab.migration"][
                "source_report_json"
            ]
        )
        == source
    )


def test_v1_to_v2_target_is_pinned_independently_of_current_writer(monkeypatch):
    monkeypatch.setattr(
        compatibility_module,
        "current_write_version",
        lambda _family: "3.0.0",
    )

    assert migrate_report_v1_to_v2(load_json(V1_REPORT))["schema_version"] == "2.0.0"


def test_migration_provenance_is_fail_closed_and_source_bound():
    migrated = migrate_report_v1_to_v2(load_json(V1_REPORT))
    forged_history = copy.deepcopy(migrated)
    forged_history["provenance"]["migration_history"][0]["migration_id"] = "forged"
    with pytest.raises(SchemaValidationError, match="migration provenance"):
        validate_report(forged_history)

    forged_source = copy.deepcopy(migrated)
    preserved = forged_source["extensions"]["org.androidtrustlab.migration"]
    preserved["source_report_json"] = encode_legacy_report({"schema_version": "1.0.0"})
    with pytest.raises(SchemaValidationError, match="digest does not match"):
        validate_report(forged_source)

    malformed_digest = copy.deepcopy(migrated)
    malformed_digest["extensions"]["org.androidtrustlab.migration"]["source_sha256"] = (
        "é" * 64
    )
    with pytest.raises(SchemaValidationError, match="digest is invalid"):
        validate_report(malformed_digest)

    invalid_source = copy.deepcopy(migrated)
    preserved = invalid_source["extensions"]["org.androidtrustlab.migration"]
    preserved["source_report_json"] = encode_legacy_report({"schema_version": "1.0.0"})
    preserved["source_sha256"] = legacy_report_digest(preserved["source_report_json"])
    with pytest.raises(SchemaValidationError, match="preserved source report"):
        validate_report(invalid_source)

    missing_source = migrate_report_to_current(load_json(V1_REPORT))
    del missing_source["extensions"]["org.androidtrustlab.migration-v4"]
    with pytest.raises(SchemaValidationError, match="deterministic migration"):
        validate_report(missing_source)


def test_v2_extensions_reject_noncanonical_float_values():
    report = current_report()
    report["extensions"]["org.example.test"] = {"value": 1.5}

    with pytest.raises(SchemaValidationError):
        validate_report(report)


def test_v2_canonical_invalid_string_fails_validation_and_migration_cleanly():
    report = load_json(V2_REPORT)
    report["extensions"]["org.example.invalid"] = {"value": "\ud800"}

    with pytest.raises(SchemaValidationError, match="bounded canonical JSON model"):
        validate_report(report)
    with pytest.raises(SchemaValidationError, match="bounded canonical JSON model"):
        migrate_report_v2_to_v3(report)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report.update({"undeclared": True}),
        lambda report: report["root_state"]["su_present"].update({"status": "unknown"}),
        lambda report: report["mounts"].update({"overlay_detected": True}),
        lambda report: report["process_state"].update({"raw_processes": []}),
        lambda report: report["extensions"].update({"not_namespaced": {}}),
        lambda report: report["emulator_state"]["indicators"].update(
            {"status": "observed", "value": ["qemu", "qemu"], "reason": None}
        ),
        lambda report: report["provenance"]["command_results"].append(
            {"command_id": "getprop"}
        ),
    ],
)
def test_strict_v2_rejects_undeclared_or_malformed_data(mutation):
    report = current_report()
    mutation(report)
    with pytest.raises(SchemaValidationError):
        validate_report(report)


def test_migrate_report_cli_publishes_separate_current_output(tmp_path):
    source = tmp_path / "v1.json"
    source.write_bytes(V1_REPORT.read_bytes())
    before = source.read_bytes()
    output = tmp_path / "v5.json"

    assert (
        cli.main(
            [
                "migrate-report",
                "--input",
                str(source),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert source.read_bytes() == before
    migrated = load_json(output)
    assert migrated["schema_version"] == "5.0.0"
    assert [
        record["migration_id"] for record in migrated["provenance"]["migration_history"]
    ] == [
        "report-v1-to-v2",
        "report-v2-to-v3",
        "report-v3-to-v4",
        "report-v4-to-v5",
    ]
    validate_report(migrated)


def test_explicit_v2_to_v3_migration_is_deterministic_and_source_bound():
    v2 = load_json(V2_REPORT)

    first = migrate_report_v2_to_v3(v2)
    second = migrate_report_v2_to_v3(copy.deepcopy(v2))

    assert first == second
    assert first["schema_version"] == "3.0.0"
    assert first["raw_artifacts"][0]["media_type"] == "application/json"
    assert (
        first["raw_artifacts"][0]["sha256"]
        == first["extensions"]["org.androidtrustlab.migration-v3"]["source_sha256"]
    )
    validate_report(first)


def test_explicit_v3_to_v4_migration_is_deterministic_without_invented_mounts():
    v3 = migrate_report_v2_to_v3(load_json(V2_REPORT))

    first = migrate_report_v3_to_v4(v3)
    second = migrate_report_v3_to_v4(copy.deepcopy(v3))

    assert first == second
    assert first["schema_version"] == "4.0.0"
    assert first["mounts"]["records"] == []
    assert first["mounts"]["system_resolution"]["state"] == "unresolved"
    assert first["mounts"]["observation"]["parse_status"] == "not_parsed"
    assert first["provenance"]["migration_history"][-1]["migration_id"] == (
        "report-v3-to-v4"
    )
    validate_report(first)


def test_explicit_v4_to_v5_migration_is_deterministic_without_invented_processes():
    v4 = migrate_report_v3_to_v4(migrate_report_v2_to_v3(load_json(V2_REPORT)))

    first = migrate_report_v4_to_v5(v4)
    second = migrate_report_v4_to_v5(copy.deepcopy(v4))

    assert first == second
    assert first["schema_version"] == "5.0.0"
    assert first["process_state"]["capture_status"] == "not_collected"
    assert all(
        item["visibility"]["status"] == "not_collected"
        for item in first["process_state"]["selected_processes"]
    )
    assert first["provenance"]["migration_history"][-1]["migration_id"] == (
        "report-v4-to-v5"
    )
    validate_report(first)


def test_persisted_v4_migration_remains_valid_after_analyzer_version_changes(
    monkeypatch,
):
    migrated = migrate_report_v3_to_v4(migrate_report_v2_to_v3(load_json(V2_REPORT)))
    declared_version = migrated["provenance"]["migration_history"][-1][
        "implementation"
    ]["version"]

    monkeypatch.setattr(report_v4_module, "__version__", "99.0.0")

    validate_report(migrated)
    assert (
        migrated["provenance"]["migration_history"][-1]["implementation"]["version"]
        == declared_version
    )


def test_persisted_v5_migration_remains_valid_after_analyzer_version_changes(
    monkeypatch,
):
    v4 = migrate_report_v3_to_v4(migrate_report_v2_to_v3(load_json(V2_REPORT)))
    migrated = migrate_report_v4_to_v5(v4)
    declared_version = migrated["provenance"]["migration_history"][-1][
        "implementation"
    ]["version"]

    monkeypatch.setattr(report_v5_module, "__version__", "99.0.0")

    validate_report(migrated)
    assert (
        migrated["provenance"]["migration_history"][-1]["implementation"]["version"]
        == declared_version
    )


def test_v3_to_v4_migration_rejects_reserved_extension_collision():
    v2 = load_json(V2_REPORT)
    v2["extensions"]["org.androidtrustlab.migration-v4"] = {"caller": "must survive"}
    validate_report(v2)
    v3 = migrate_report_v2_to_v3(v2)
    validate_report(v3)

    with pytest.raises(SchemaValidationError, match="reserved v4 extension key"):
        migrate_report_v3_to_v4(v3)


def test_v4_to_v5_migration_rejects_reserved_extension_collision():
    v2 = load_json(V2_REPORT)
    v2["extensions"]["org.androidtrustlab.migration-v5"] = {"caller": "must survive"}
    validate_report(v2)
    v3 = migrate_report_v2_to_v3(v2)
    v4 = migrate_report_v3_to_v4(v3)
    validate_report(v4)

    with pytest.raises(SchemaValidationError, match="reserved v5 extension key"):
        migrate_report_v4_to_v5(v4)


def test_v2_to_v3_validation_binds_migrated_evidence_and_structured_source():
    migrated = migrate_report_v2_to_v3(load_json(V2_REPORT))

    forged_evidence = copy.deepcopy(migrated)
    forged_evidence["properties"]["security"]["value"]["ro.secure"] = "0"
    forged_evidence = finalize_report_identity(forged_evidence)
    with pytest.raises(SchemaValidationError, match="evidence does not match"):
        validate_report(forged_evidence)

    forged_reference = copy.deepcopy(migrated)
    forged_reference["raw_artifacts"][0]["collector_version"] = "9.9.9"
    with pytest.raises(SchemaValidationError, match="source reference does not match"):
        validate_report(forged_reference)


@pytest.mark.parametrize(
    "reference",
    [
        "/Users/alice/private/raw.txt",
        "C:\\Users\\alice\\private\\raw.txt",
        "\\\\server\\share\\raw.txt",
        "../private/raw.txt",
    ],
)
def test_v2_to_v3_migration_rejects_nonportable_legacy_raw_paths(reference):
    v2 = load_json(V2_REPORT)
    v2["raw_artifacts"] = [reference]
    validate_report(v2)

    with pytest.raises(SchemaValidationError, match="nonportable raw artifact"):
        migrate_report_v2_to_v3(v2)


def test_v1_to_current_migration_rejects_nested_absolute_raw_path():
    v1 = load_json(V1_REPORT)
    v1["raw_artifacts"] = ["/home/alice/private/raw.txt"]
    validate_report(v1)

    with pytest.raises(SchemaValidationError, match="nonportable raw artifact"):
        migrate_report_to_current(v1)


@pytest.mark.parametrize(
    "host_path",
    [
        "/Users/alice/private/raw.txt",
        "/home/alice/private/raw.txt",
        "/tmp/alice/raw.txt",
        "/opt/workspace/raw.txt",
        "C:\\Users\\alice\\private\\raw.txt",
        "\\\\server\\share\\raw.txt",
    ],
)
def test_v2_to_v3_migration_rejects_host_paths_in_carried_free_text(host_path):
    v2 = load_json(V2_REPORT)
    v2["limitations"]["collection_errors"].append(
        f"input failed while reading {host_path}"
    )
    validate_report(v2)

    with pytest.raises(SchemaValidationError, match="host absolute path"):
        migrate_report_v2_to_v3(v2)


@pytest.mark.parametrize(
    "reserved_key",
    ["org.androidtrustlab.collection", "org.androidtrustlab.migration-v3"],
)
def test_v2_to_v3_migration_rejects_reserved_extension_collision(reserved_key):
    v2 = load_json(V2_REPORT)
    v2["extensions"][reserved_key] = {"fake": "provenance"}
    validate_report(v2)

    with pytest.raises(SchemaValidationError, match="reserved v3 extension key"):
        migrate_report_v2_to_v3(v2)


@pytest.mark.parametrize(
    "reserved_key",
    ["org.androidtrustlab.migration", "org.androidtrustlab.migration-v3"],
)
def test_raw_v3_rejects_reserved_migration_extensions(reserved_key):
    report = current_report()
    report["extensions"][reserved_key] = {"fake": "provenance"}

    with pytest.raises(SchemaValidationError, match="migration provenance"):
        validate_report(report)


def test_v1_surrogate_remains_readable_but_current_migration_fails_closed():
    v1 = load_json(V1_REPORT)
    v1["target"]["model"] = "\ud800"
    validate_report(v1)

    with pytest.raises(SchemaValidationError, match="bounded canonical JSON model"):
        migrate_report_to_current(v1)


def test_migrated_v3_output_contains_no_absolute_source_path():
    migrated = migrate_report_v2_to_v3(load_json(V2_REPORT))

    encoded = json.dumps(migrated, sort_keys=True)
    assert "/Users/" not in encoded
    assert "C:\\Users\\" not in encoded


def test_v2_migration_identity_excludes_wrapper_timestamp_and_raw_path():
    source = load_json(V2_REPORT)
    baseline = migrate_report_v2_to_v3(source)

    timestamp_only = copy.deepcopy(source)
    timestamp_only["collection_timestamp"] = "2026-04-25T15:06:22Z"
    validate_report(timestamp_only)
    timestamp_migrated = migrate_report_v2_to_v3(timestamp_only)
    assert timestamp_migrated["content_digest"] == baseline["content_digest"]
    assert timestamp_migrated["collection_event_id"] != baseline["collection_event_id"]
    assert timestamp_migrated["report_id"] != baseline["report_id"]

    path_only = copy.deepcopy(source)
    path_only["raw_artifacts"] = ["moved/same-raw.txt"]
    validate_report(path_only)
    path_migrated = migrate_report_v2_to_v3(path_only)
    assert path_migrated["content_digest"] == baseline["content_digest"]
    assert path_migrated["collection_event_id"] == baseline["collection_event_id"]
    assert path_migrated["report_id"] == baseline["report_id"]
    assert (
        path_migrated["raw_artifacts"][0]["sha256"]
        != baseline["raw_artifacts"][0]["sha256"]
    )


def test_migrate_report_cli_refuses_to_replace_source(tmp_path, capsys):
    source = tmp_path / "v1.json"
    source.write_bytes(V1_REPORT.read_bytes())
    before = source.read_bytes()

    assert (
        cli.main(
            [
                "migrate-report",
                "--input",
                str(source),
                "--output",
                str(source),
            ]
        )
        == cli.EXIT_OUTPUT_WRITE_FAILURE
    )
    assert source.read_bytes() == before
    assert "output must not replace" in capsys.readouterr().err
