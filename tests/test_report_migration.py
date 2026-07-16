from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import trustlab.compatibility as compatibility_module
from trustlab import cli
from trustlab.exceptions import SchemaValidationError, UnsupportedSchemaVersionError
from trustlab.migration_codec import encode_legacy_report, legacy_report_digest
from trustlab.migrations import migrate_report_v1_to_v2
from trustlab.normalizer import normalize_raw_file
from trustlab.report_writer import load_json, write_json
from trustlab.validators import validate_report

ROOT = Path(__file__).resolve().parents[1]
V1_REPORT = ROOT / "tests/fixtures/report_v1_historical.json"
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

    missing_source = current_report()
    missing_source["provenance"]["source_schema_version"] = "1.0.0"
    missing_source["provenance"]["migration_history"] = [
        {
            "migration_id": "report-v1-to-v2",
            "source_schema_version": "1.0.0",
            "target_schema_version": "2.0.0",
        }
    ]
    with pytest.raises(SchemaValidationError, match="preserved-source extension"):
        validate_report(missing_source)


def test_v2_extensions_reject_noncanonical_float_values():
    report = current_report()
    report["extensions"]["org.example.test"] = {"value": 1.5}

    with pytest.raises(SchemaValidationError):
        validate_report(report)


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


def test_migrate_report_cli_publishes_separate_valid_output(tmp_path):
    source = tmp_path / "v1.json"
    source.write_bytes(V1_REPORT.read_bytes())
    before = source.read_bytes()
    output = tmp_path / "v2.json"

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
    assert load_json(output)["schema_version"] == "2.0.0"
    validate_report(load_json(output))


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
