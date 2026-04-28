from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyzer"))

from trustlab.normalizer import normalize_raw_file


def test_normalize_fixture():
    report = normalize_raw_file(
        Path(__file__).parent / "fixtures" / "sample_raw_report.txt",
        experiment_id="E01_stock_avd",
        target_type="avd",
        observer_type="adb_shell",
    )
    assert report["target"]["target_type"] == "avd"
    assert report["selinux"]["mode"] == "enforcing"
    assert report["root_state"]["su_present"] is False
    assert report["mounts"]["system_mount"]["classification"] == "read-only"
    assert report["emulator_state"]["is_emulator"] is True



def test_normalize_magisk_sample():
    report = normalize_raw_file(
        Path(__file__).resolve().parents[1] / "datasets" / "samples" / "magisk_collector" / "raw_sample.txt",
        experiment_id="E05_magisk_collector",
        target_type="avd",
        observer_type="root_collector",
        collection_method="magisk_module_manual",
        collection_timestamp="2026-04-25T15:50:00Z",
        raw_artifact_ref="datasets/samples/magisk_collector/raw_sample.txt",
    )
    assert report["root_state"]["su_present"] is True
    assert report["magisk_state"]["magisk_binary_present"] is True
    assert report["observer"]["collection_method"] == "magisk_module_manual"


def test_normalize_writable_system_sample():
    report = normalize_raw_file(
        Path(__file__).resolve().parents[1] / "datasets" / "samples" / "writable_system_avd" / "raw_sample.txt",
        experiment_id="E03_writable_system_avd",
        target_type="avd",
        observer_type="adb_shell",
        collection_method="synthetic_writable_system_snapshot",
        collection_timestamp="2026-04-25T15:08:21Z",
        raw_artifact_ref="datasets/samples/writable_system_avd/raw_sample.txt",
    )
    assert report["mounts"]["overlay_detected"] is True
    assert "/system" in report["mounts"]["writable_sensitive_mounts"]


def test_fixture_normalized_report_matches_current_normalizer():
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
    )
    expected = json.loads((fixture_dir / "sample_normalized_report.json").read_text(encoding="utf-8"))
    assert report == expected
