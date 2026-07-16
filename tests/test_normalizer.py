import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyzer"))

from trustlab.normalizer import normalize_properties, normalize_raw_file
from trustlab.validators import validate_report


def test_normalize_fixture():
    report = normalize_raw_file(
        Path(__file__).parent / "fixtures" / "sample_raw_report.txt",
        experiment_id="E01_stock_avd",
        target_type="avd",
        observer_type="adb_shell",
    )
    assert report["target"]["target_type"] == "avd"
    assert report["selinux"]["policy_mode"]["value"] == "enforcing"
    assert report["root_state"]["su_present"]["status"] == "observed_absent"
    assert report["mounts"]["system_mount"]["classification"] == "read-only"
    assert report["emulator_state"]["is_emulator"]["value"] is True


def test_normalize_magisk_sample():
    report = normalize_raw_file(
        Path(__file__).resolve().parents[1]
        / "datasets"
        / "samples"
        / "magisk_collector"
        / "raw_sample.txt",
        experiment_id="E05_magisk_collector",
        target_type="avd",
        observer_type="root_collector",
        collection_method="magisk_module_manual",
        collection_timestamp="2026-04-25T15:50:00Z",
        raw_artifact_ref="datasets/samples/magisk_collector/raw_sample.txt",
    )
    assert report["root_state"]["su_present"]["value"] is True
    assert report["magisk_state"]["magisk_binary_present"]["value"] is True
    assert report["observer"]["collection_method"] == "magisk_module_manual"


def test_normalize_writable_system_sample():
    report = normalize_raw_file(
        Path(__file__).resolve().parents[1]
        / "datasets"
        / "samples"
        / "writable_system_avd"
        / "raw_sample.txt",
        experiment_id="E03_writable_system_avd",
        target_type="avd",
        observer_type="adb_shell",
        collection_method="synthetic_writable_system_snapshot",
        collection_timestamp="2026-04-25T15:08:21Z",
        raw_artifact_ref="datasets/samples/writable_system_avd/raw_sample.txt",
    )
    integrity = report["mounts"]["integrity_summary"]
    assert integrity["overlay_detected"]["value"] is True
    assert "/system" in integrity["writable_sensitive_mounts"]["value"]


def test_current_normalized_snapshot_is_generator_owned():
    # This snapshot is regenerated from the same raw fixture by the canonical
    # sample generator; independent behavior expectations remain in goldens.
    import json

    fixture_dir = Path(__file__).parent / "fixtures"
    report = normalize_raw_file(
        fixture_dir / "sample_raw_report.txt",
        experiment_id="E01_stock_avd",
        target_type="avd",
        observer_type="adb_shell",
        collection_method="raw_artifact",
        collection_timestamp="2026-04-25T15:06:21Z",
        raw_artifact_ref="tests/fixtures/sample_raw_report.txt",
        raw_artifact_id="fixture-sample-raw-report",
        collector_name="trustlab-fixture-authors",
        collector_version="1.0.0",
        redaction_state="not_required",
    )
    expected = json.loads(
        (fixture_dir / "sample_normalized_report.json").read_text(encoding="utf-8")
    )
    assert report == expected


def test_default_raw_artifact_reference_does_not_embed_host_path(tmp_path):
    raw = tmp_path / "private-host-path" / "raw.txt"
    raw.parent.mkdir()
    raw.write_text(
        (Path(__file__).parent / "fixtures/sample_raw_report.txt").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    report = normalize_raw_file(raw, collection_timestamp="2026-04-25T15:06:21Z")
    assert report["raw_artifacts"][0]["relative_path"] == "raw.txt"
    assert str(tmp_path) not in str(report)


def test_missing_probes_do_not_become_affirmative_absence(tmp_path):
    raw = tmp_path / "empty.raw"
    raw.write_text("", encoding="utf-8")

    report = normalize_raw_file(
        raw,
        collection_timestamp="2026-04-25T15:06:21Z",
        raw_artifact_ref="empty.raw",
    )

    evidence = (
        report["boot_state"]["kernel_cmdline_present"],
        report["mounts"]["integrity_summary"]["overlay_detected"],
        report["mounts"]["integrity_summary"]["writable_sensitive_mounts"],
        report["properties"]["security"],
        report["root_state"]["su_present"],
        report["magisk_state"]["magisk_binary_present"],
        report["process_state"]["selected_processes"][0]["visibility"],
        report["process_state"]["selected_processes"][0]["context"],
        report["emulator_state"]["is_emulator"],
    )
    assert {item["status"] for item in evidence} == {"not_collected"}
    assert report["properties"]["all_count"]["status"] == "not_collected"
    validate_report(report)


def test_default_provenance_distinguishes_same_named_artifacts(tmp_path):
    source = (Path(__file__).parent / "fixtures/sample_raw_report.txt").read_text(
        encoding="utf-8"
    )
    first = tmp_path / "first" / "raw.txt"
    second = tmp_path / "second" / "raw.txt"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_text(source, encoding="utf-8")
    second.write_text(
        source.replace("[ro.secure]: [1]", "[ro.secure]: [0]"), encoding="utf-8"
    )

    first_report = normalize_raw_file(
        first, collection_timestamp="2026-04-25T15:06:21Z"
    )
    second_report = normalize_raw_file(
        second, collection_timestamp="2026-04-25T15:06:21Z"
    )

    assert {
        first_report["raw_artifacts"][0]["relative_path"],
        second_report["raw_artifacts"][0]["relative_path"],
    } == {"raw.txt"}
    assert (
        first_report["raw_artifacts"][0]["sha256"]
        != second_report["raw_artifacts"][0]["sha256"]
    )
    assert first_report["content_digest"] != second_report["content_digest"]
    assert first_report["report_id"] != second_report["report_id"]
    assert str(tmp_path) not in str(first_report)
    assert str(tmp_path) not in str(second_report)


@pytest.mark.parametrize(
    "sensitive_key",
    [
        "ro.boot.serialno",
        "ro.serialno",
        "ro.boot.device_serial",
        "ro.boot.wifimacaddr",
        "ro.boot.btmacaddr",
        "ro.boot.ip_address",
        "ro.boot.device_address",
        "ro.product.imei",
        "ro.product.account_email",
        "ro.build.user",
        "ro.build.host",
        "ro.product.username",
        "ro.product.owner",
        "ro.boot.host_name",
        "ro.boot.wifi_mac",
    ],
)
def test_sensitive_identifier_properties_are_not_copied_to_report_groups(
    sensitive_key,
):
    normalized = normalize_properties(
        {
            sensitive_key: "sensitive-identifier",
            "ro.boot.verifiedbootstate": "green",
        }
    )
    assert all(
        sensitive_key not in properties
        for properties in normalized.values()
        if isinstance(properties, dict)
    )
    assert normalized["boot"]["ro.boot.verifiedbootstate"] == "green"


def test_unknown_property_is_private_by_default():
    normalized = normalize_properties({"ro.boot.future_signal": "not-reviewed"})
    assert "ro.boot.future_signal" not in normalized["boot"]
    assert normalized["all_count"] == 1
