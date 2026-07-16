from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustlab.exceptions import NormalizationError, SchemaValidationError
from trustlab.identity import finalize_report_identity
from trustlab.normalizer import normalize_collection_manifest, normalize_raw_file
from trustlab.privacy import (
    contains_sensitive_identifier,
    deterministic_pseudonym,
    sanitize_boot_reason,
    sanitize_collection_id,
    sanitize_metadata_value,
    sanitize_mount_model,
    sanitize_raw_artifact_references,
    semantic_capture_ref,
    validate_portable_collection_manifest,
    validate_portable_diff,
    validate_portable_historical_report,
    validate_portable_report,
)
from trustlab.validators import validate_report

ROOT = Path(__file__).resolve().parents[1]
MAGISK_FIXTURE = ROOT / "tests/fixtures/adapters/magisk_manifest.json"


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_uid_zero_does_not_manufacture_su_or_root_shell(tmp_path):
    source = _write(
        tmp_path,
        "uid-zero.txt",
        "=== ID ===\nuid=0(root) gid=0(root) groups=0(root)\n=== SU_PATHS ===\n",
    )

    report = normalize_raw_file(source, collection_timestamp="2026-07-16T10:00:00Z")

    assert report["root_state"]["observer_effective_uid_is_root"]["value"] is True
    assert report["root_state"]["root_shell_available"]["status"] == "not_collected"
    assert report["root_state"]["su_binary_observed"]["status"] == ("observed_absent")
    assert report["root_state"]["su_binary_observed"]["value"] is False
    assert report["root_state"]["su_invocation_tested"]["status"] == ("not_collected")
    validate_report(report)


def test_root_probe_keeps_su_invocation_result_independent(tmp_path):
    document = json.loads(MAGISK_FIXTURE.read_text(encoding="utf-8"))
    root_probe = next(
        capture for capture in document["captures"] if capture["name"] == "root_probe"
    )
    root_probe["stdout"] = root_probe["stdout"].replace(
        "su_invocation_tested=observed_absent\nsu_invocation_result=not_tested",
        "su_invocation_tested=observed\nsu_invocation_result=succeeded",
    )
    source = _write(tmp_path, "root-probe.json", json.dumps(document))

    report = normalize_raw_file(source)

    assert report["root_state"]["su_binary_observed"]["value"] is False
    assert report["root_state"]["su_invocation_tested"]["value"] is True
    assert report["root_state"]["su_invocation_result"]["value"] == "succeeded"
    validate_report(report)


@pytest.mark.parametrize(
    ("tested", "result"),
    [("observed_absent", "succeeded"), ("observed", "not_tested")],
)
def test_root_probe_rejects_contradictory_su_result(tmp_path, tested, result):
    document = json.loads(MAGISK_FIXTURE.read_text(encoding="utf-8"))
    root_probe = next(
        capture for capture in document["captures"] if capture["name"] == "root_probe"
    )
    root_probe["stdout"] = root_probe["stdout"].replace(
        "su_invocation_tested=observed_absent\nsu_invocation_result=not_tested",
        f"su_invocation_tested={tested}\nsu_invocation_result={result}",
    )
    source = _write(tmp_path, "contradictory-root-probe.json", json.dumps(document))

    with pytest.raises(NormalizationError, match="malformed observed output"):
        normalize_raw_file(source)


def test_magisk_version_name_and_code_are_distinct():
    report = normalize_raw_file(MAGISK_FIXTURE)

    assert report["magisk_state"]["version_name"]["value"] == "synthetic-28.1"
    assert report["magisk_state"]["version_code"]["value"] == "28100"
    assert report["magisk_state"]["version_name"]["evidence_refs"] == [
        "captures/magisk.txt"
    ]
    assert report["magisk_state"]["version_code"]["evidence_refs"] == [
        "captures/magisk.txt"
    ]


def test_inaccessible_magisk_command_stays_inaccessible(tmp_path):
    document = json.loads(MAGISK_FIXTURE.read_text(encoding="utf-8"))
    magisk = next(
        capture for capture in document["captures"] if capture["name"] == "magisk"
    )
    magisk.update(
        {
            "status": "inaccessible",
            "exit_code": 1,
            "stdout": "",
            "stderr": "permission denied for private-device-serial",
        }
    )
    source = _write(tmp_path, "magisk-inaccessible.json", json.dumps(document))

    report = normalize_raw_file(source)

    assert report["magisk_state"]["binary_visibility"]["status"] == "inaccessible"
    assert report["magisk_state"]["version_name"]["status"] == "inaccessible"
    assert report["magisk_state"]["command_status"]["status"] == "inaccessible"
    assert "private-device-serial" not in json.dumps(report)
    validate_report(report)


def test_magisk_substrings_and_ambiguous_versions_do_not_create_evidence(tmp_path):
    source = _write(
        tmp_path,
        "false-positive.txt",
        "=== MAGISK ===\nnotmagisk_version=28.1\nversion: forged\n",
    )

    report = normalize_raw_file(source, collection_timestamp="2026-07-16T10:00:00Z")

    assert report["magisk_state"]["binary_visibility"]["status"] == "not_collected"
    assert report["magisk_state"]["version_name"]["status"] == "not_collected"
    assert report["magisk_state"]["version_code"]["status"] == "not_collected"
    validate_report(report)


@pytest.mark.parametrize(
    "sensitive_value",
    [
        "alice@example.com",
        "10.0.0.7",
        "aa:bb:cc:dd:ee:ff",
        "aa-bb-cc-dd-ee-ff",
        "2001:db8::1",
        "emulator-5554",
        "9774d56d682e549c",
        "ZX1G22BQQ7",
        "ghp_PRIVATEVALUE12345678",
        "alice",
        "/Users/alice/private/device.txt",
        "serialno=R58M1234ABCDE",
        "password=hunter2",
    ],
)
def test_allowlisted_property_values_are_sanitized(tmp_path, sensitive_value):
    source = _write(
        tmp_path,
        "sensitive-props.txt",
        "=== GETPROP ===\n"
        f"[ro.product.model]: [{sensitive_value}]\n"
        "[ro.boot.verifiedbootstate]: [green]\n",
    )

    report = normalize_raw_file(source, collection_timestamp="2026-07-16T10:00:00Z")
    encoded = json.dumps(report, sort_keys=True)

    assert sensitive_value not in encoded
    assert report["target"]["model"]["value"].startswith("redacted-")
    assert set(report["properties"]["product"]["value"]) == {"ro.product.model"}
    validate_report(report)


def test_mount_credentials_and_paths_are_withheld(tmp_path):
    source = _write(
        tmp_path,
        "mount-secret.txt",
        "=== MOUNT ===\n"
        "//10.0.0.7/private on /system type cifs "
        "(rw,username=alice,password=hunter2,addr=10.0.0.7)\n",
    )

    report = normalize_raw_file(source, collection_timestamp="2026-07-16T10:00:00Z")
    encoded = json.dumps(report, sort_keys=True)

    for marker in ("10.0.0.7", "username=alice", "password=hunter2", "//"):
        assert marker not in encoded
    record = report["mounts"]["records"][0]
    assert record["raw"] == "<withheld>"
    assert record["mount_options"] == ["rw"]
    assert record["source"] == "redacted-mount-source"
    validate_report(report)


def test_mount_filesystem_and_apex_labels_are_redacted(tmp_path):
    source = _write(
        tmp_path,
        "apex-secret.txt",
        "=== MOUNT ===\n"
        "/dev/block/dm-0 /apex/com.alice.private ghp_PRIVATEVALUE12345678 rw 0 0\n",
    )

    report = normalize_raw_file(source, collection_timestamp="2026-07-16T10:00:00Z")
    encoded = json.dumps(report, sort_keys=True)
    record = report["mounts"]["records"][0]

    assert "alice" not in encoded
    assert "ghp_PRIVATEVALUE" not in encoded
    assert record["mount_point"] == "/apex/redacted-apex-package-001"
    assert record["fs_type"] == "redacted-fs-type"
    assert report["mounts"]["apex_set"]["packages"] == ["redacted-apex-package-001"]
    validate_report(report)


def test_capture_references_are_semantic_not_caller_controlled(tmp_path):
    document = json.loads(MAGISK_FIXTURE.read_text(encoding="utf-8"))
    for capture in document["captures"]:
        capture["source_ref"] = "captures/R58M1234ABCDE-alice-10.0.0.7.txt"
    source = _write(tmp_path, "typed.json", json.dumps(document))

    report = normalize_raw_file(source)
    encoded = json.dumps(report, sort_keys=True)

    assert "R58M1234ABCDE" not in encoded
    assert "10.0.0.7" not in encoded
    assert {
        capture["source_ref"]
        for capture in report["extensions"]["org.androidtrustlab.adapter"]["captures"]
    } == {
        "captures/identity.txt",
        "captures/root_probe.txt",
        "captures/magisk.txt",
    }


def test_pseudonyms_are_deterministic_and_not_candidate_testable():
    first = deterministic_pseudonym(
        "R58M1234ABCDE", category="serial", scope="collection-a"
    )
    second = deterministic_pseudonym(
        "R58M1234ABCDE", category="serial", scope="collection-a"
    )
    other_scope = deterministic_pseudonym(
        "R58M1234ABCDE", category="serial", scope="collection-b"
    )

    assert first == second
    assert first == other_scope == "redacted-serial"
    assert "R58M1234ABCDE" not in first


def test_privacy_primitives_cover_fail_closed_edge_branches():
    assert contains_sensitive_identifier("deadbeef") is False
    assert contains_sensitive_identifier("abc:def") is False
    assert deterministic_pseudonym("value", category="---", scope="scope") == (
        "redacted-value"
    )
    assert semantic_capture_ref("---") == "captures/unknown.txt"
    assert (
        sanitize_collection_id("atlcol-" + "a" * 32, scope="scope")
        == "atlcol-" + "a" * 32
    )
    assert sanitize_collection_id("caller-label", scope="scope") == (
        "collection-redacted"
    )
    assert sanitize_metadata_value("unknown", category="property", scope="scope") == (
        "unknown"
    )
    assert (
        sanitize_metadata_value(
            "private-module", category="module-context", scope="scope"
        )
        == "redacted-module-context"
    )
    assert sanitize_metadata_value(
        "safe-token", category="property", scope="scope"
    ) == ("safe-token")
    assert (
        sanitize_metadata_value("../private", category="property", scope="scope")
        == "redacted-property"
    )
    assert sanitize_boot_reason("unknown", scope="scope") == "unknown"
    assert sanitize_boot_reason("watchdog", scope="scope") == "watchdog"
    assert sanitize_boot_reason("alice", scope="scope") == "redacted-boot-reason"
    assert validate_portable_diff(None) is None
    assert validate_portable_collection_manifest(None) is None


def test_mount_and_raw_artifact_sanitizers_withhold_unstructured_values():
    mounts = {
        "records": [
            {
                "record_index": 0,
                "root": 17,
                "mount_point": "/apex/com.example.private@42",
                "mount_options": "rw,context=secret",
                "optional_fields": ["shared:7"],
                "source": "/dev/block/mapper/system_a",
                "fs_type": "privatefs",
                "super_options": None,
                "raw": "private mount row",
            }
        ],
        "system_mount": {
            "mount_point": "/apex/com.example.private@42",
            "options": "rw,context=secret",
            "fs_type": "privatefs",
            "raw": "private summary",
        },
        "observation": {"selected_source": None, "attempts": []},
        "dynamic_partitions": {"record_indices": [0]},
        "apex_set": {"packages": ["com.example.private"]},
    }

    sanitized_mounts = sanitize_mount_model(mounts, scope="scope")
    sanitized_artifacts = sanitize_raw_artifact_references(
        [
            {
                "media_type": "application/json",
                "collector_name": "private-collector",
                "collector_version": "1.2.3-private",
            }
        ],
        scope="scope",
    )

    assert sanitized_mounts["system_mount"] == {
        "mount_point": "/apex/redacted-package",
        "options": [],
        "fs_type": "redacted-fs-type",
        "raw": "<withheld>",
    }
    assert sanitized_mounts["records"][0]["mount_point"] == (
        "/apex/redacted-apex-package-001"
    )
    assert sanitized_mounts["records"][0]["source"] == ("/dev/block/mapper/redacted")
    assert sanitized_mounts["records"][0]["root"] is None
    assert sanitized_artifacts[0]["collector_name"] == "redacted-collector"
    assert sanitized_artifacts[0]["collector_version"] == "unknown"
    assert sanitized_artifacts[0]["relative_path"] == "artifacts/raw-artifact-001.json"


def test_portable_report_validator_accepts_absent_optional_structures():
    assert validate_portable_report(None) is None
    assert validate_portable_historical_report(None) is None
    assert (
        validate_portable_report(
            {
                "schema_version": "6.0.0",
                "target": None,
                "properties": None,
                "verified_boot": {},
                "mounts": None,
                "magisk_state": None,
                "provenance": None,
            }
        )
        is None
    )


@pytest.mark.parametrize(
    "properties",
    [
        {"product": {"value": {"ro.product.model": "nonsense"}}},
        {"build": {"value": {"ro.private.example": "nonsense"}}},
        {"build": {"value": {"ro.build.version.release": "nonnumeric"}}},
    ],
)
def test_portable_report_validator_rejects_unportable_property_shapes(properties):
    with pytest.raises(SchemaValidationError, match="property"):
        validate_portable_report({"properties": properties})


@pytest.mark.parametrize(
    "report",
    [
        {"experiment_id": "nonsense"},
        {"target": {"android_version": "nonnumeric"}},
        {"target": {"sdk": "nonnumeric"}},
        {"observer": {"collection_method": "nonsense"}},
        {"boot": {"boot_reason": "nonsense"}},
        {"boot": {"slot_suffix": "nonsense"}},
        {"magisk_state": {"version_name": {"value": "not valid"}}},
        {"magisk_state": {"version_code": {"value": "nonnumeric"}}},
        {"magisk_state": {"module_context": {"value": "nonsense"}}},
    ],
)
def test_portable_report_validator_rejects_unportable_metadata(report):
    with pytest.raises(SchemaValidationError, match="portable|semantic|unsafe"):
        validate_portable_report(report)


def test_confidence_is_unassessed_without_evidence_and_medium_for_complete_probe(
    tmp_path,
):
    empty = _write(tmp_path, "empty.txt", "")
    empty_report = normalize_raw_file(
        empty, collection_timestamp="2026-07-16T10:00:00Z", target_type="physical"
    )
    assert empty_report["verified_boot"]["confidence"]["level"] == "unassessed"

    document = {
        "artifact_kind": "adb_collection_manifest",
        "schema_version": "1.0.0",
        "collector_version": "0.3.0",
        "observer": {
            "observer_type": "adb_shell",
            "collection_method": "synthetic_confidence_probe",
        },
        "collection": {
            "experiment_id": "E16_adapter_contract",
            "target_type": "avd",
            "timestamp": "2026-07-16T10:00:00Z",
        },
        "captures": [
            {
                "name": "getprop_selected",
                "status": "observed",
                "exit_code": 0,
                "timed_out": False,
                "stdout": "\n".join(
                    (
                        "[ro.boot.verifiedbootstate]: [green]",
                        "[ro.boot.flash.locked]: [1]",
                        "[ro.boot.vbmeta.device_state]: [locked]",
                        "[ro.boot.veritymode]: [enforcing]",
                    )
                ),
                "stderr": "",
                "source_ref": "captures/getprop-private-serial.txt",
            }
        ],
        "warnings": [],
    }
    source = _write(tmp_path, "confidence.json", json.dumps(document))
    report = normalize_raw_file(source)
    confidence = report["verified_boot"]["confidence"]

    assert confidence["level"] == "medium"
    assert confidence["source_quality"] == "structured_capture"
    assert confidence["command_success"] == "complete"
    assert confidence["corroborating_signal_count"] == 4
    assert confidence["target_limitations"] == [
        "hardware_attestation_not_collected",
        "virtual_target_not_hardware_backed",
    ]
    validate_report(report)


def test_validator_rejects_confidence_detached_from_evidence(tmp_path):
    source = _write(tmp_path, "empty.txt", "")
    report = normalize_raw_file(source)
    report["verified_boot"]["confidence"] = {
        "level": "medium",
        "source_quality": "structured_capture",
        "command_success": "complete",
        "observer_capability": "root",
        "corroborating_signal_count": 4,
        "target_limitations": ["hardware_attestation_not_collected"],
        "evidence_refs": [],
    }
    report = finalize_report_identity(report)

    with pytest.raises(
        SchemaValidationError,
        match="confidence does not match its evidence and provenance",
    ):
        validate_report(report)


@pytest.mark.parametrize("field", ["target", "property", "mount", "extension"])
def test_final_portability_gate_rejects_forged_sensitive_report(field):
    report = normalize_raw_file(
        ROOT / "datasets/samples/stock_avd/raw_sample.txt",
        collection_timestamp="2026-07-16T10:00:00Z",
    )
    if field == "target":
        report["target"]["model"]["value"] = "alice@example.com"
    elif field == "property":
        report["properties"]["security"]["value"]["ro.debuggable"] = (
            "password=DIFF_SECRET"
        )
    elif field == "mount":
        report["mounts"]["records"][0]["raw"] = (
            "//10.0.0.7/private username=alice,password=hunter2"
        )
    else:
        report["extensions"]["org.example.private"] = {
            "path": "/data/local/tmp/alice/PRIVATE_KEY"
        }
    report = finalize_report_identity(report)

    with pytest.raises(SchemaValidationError, match="portable|privacy"):
        validate_report(report)


def test_manifest_wrapped_legacy_capture_keeps_inferred_confidence():
    report = normalize_collection_manifest(
        ROOT / "datasets/samples/magisk_collector/collector_manifest_sample.json"
    )
    confidence = report["verified_boot"]["confidence"]

    assert confidence["level"] == "low"
    assert confidence["source_quality"] == "legacy_inferred"
    assert "legacy_capture_status_inferred" in confidence["target_limitations"]


def test_modern_magisk_grammar_rejects_path_and_combined_version(tmp_path):
    document = json.loads(MAGISK_FIXTURE.read_text(encoding="utf-8"))
    magisk = next(
        capture for capture in document["captures"] if capture["name"] == "magisk"
    )
    magisk["stdout"] = "magisk_path=/data/adb/magisk\nmagisk_version=28.1"
    source = _write(tmp_path, "invalid-magisk.json", json.dumps(document))

    with pytest.raises(NormalizationError, match="malformed observed output"):
        normalize_raw_file(source)


def test_semantic_metadata_does_not_carry_account_names(tmp_path):
    document = json.loads(MAGISK_FIXTURE.read_text(encoding="utf-8"))
    document["collection"]["experiment_id"] = "E01_alice_private"
    document["observer"]["collection_method"] = "alice_probe"
    source = _write(tmp_path, "metadata.json", json.dumps(document))

    report = normalize_raw_file(source)
    encoded = json.dumps(report, sort_keys=True)

    assert "alice" not in encoded
    assert report["experiment_id"] == "unknown"
    assert report["observer"]["collection_method"] == "legacy_migration"
    validate_report(report)


def test_magisk_version_name_uses_numeric_release_grammar(tmp_path):
    document = json.loads(MAGISK_FIXTURE.read_text(encoding="utf-8"))
    magisk = next(
        capture for capture in document["captures"] if capture["name"] == "magisk"
    )
    magisk["stdout"] = magisk["stdout"].replace("synthetic-28.1", "alice2026")
    source = _write(tmp_path, "magisk-account.json", json.dumps(document))

    report = normalize_raw_file(source)

    assert report["magisk_state"]["version_name"]["value"] == (
        "redacted-magisk-version-name"
    )
    assert "alice2026" not in json.dumps(report, sort_keys=True)
    validate_report(report)


@pytest.mark.parametrize(
    "field",
    [
        "collector_version",
        "collection_command_detail",
        "provenance_command_detail",
        "provenance_command_id",
        "provenance_generator",
        "provenance_normalizer",
    ],
)
def test_final_gate_rejects_account_bearing_structured_metadata(field):
    if field == "collector_version":
        report = normalize_raw_file(MAGISK_FIXTURE)
        report["extensions"]["org.androidtrustlab.adapter"]["collector_version"] = (
            "1.2.3-alice"
        )
    elif field == "collection_command_detail":
        report = normalize_collection_manifest(
            ROOT / "datasets/samples/magisk_collector/collector_manifest_sample.json"
        )
        report["extensions"]["org.androidtrustlab.collection"]["portable_binding"][
            "artifact_results"
        ][0]["detail"] = "alice"
    else:
        report = normalize_raw_file(MAGISK_FIXTURE)
        if field == "provenance_command_detail":
            report["provenance"]["command_results"][0]["detail"] = "alice"
        elif field == "provenance_command_id":
            report["provenance"]["command_results"][0]["command_id"] = "alice"
        elif field == "provenance_generator":
            report["provenance"]["generator"]["name"] = "alice"
        else:
            report["provenance"]["normalizer"]["name"] = "alice"
    report = finalize_report_identity(report)

    with pytest.raises(SchemaValidationError, match="portable|semantic"):
        validate_report(report)


@pytest.mark.parametrize(
    ("property_name", "group"),
    [
        ("ro.build.version.release", "build"),
        ("ro.crypto.volume.filenames_mode", "crypto"),
    ],
)
def test_account_text_is_redacted_from_grammar_bound_properties(
    tmp_path, property_name, group
):
    source = _write(
        tmp_path,
        "account-property.txt",
        f"=== GETPROP ===\n[{property_name}]: [alice]\n",
    )

    report = normalize_raw_file(source, collection_timestamp="2026-07-16T10:00:00Z")
    encoded = json.dumps(report, sort_keys=True)

    assert "alice" not in encoded
    assert report["properties"][group]["value"][property_name] == "redacted-property"
    if property_name == "ro.build.version.release":
        assert report["target"]["android_version"]["value"] == "redacted-property"
    validate_report(report)
