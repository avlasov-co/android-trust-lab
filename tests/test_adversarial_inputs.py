from __future__ import annotations

from pathlib import Path

import pytest

import trustlab.bounded_io as bounded_io_module
from trustlab.exceptions import CollectionError, NormalizationError
from trustlab.normalizer import normalize_raw_file
from trustlab.parser import (
    classify_mount,
    parse_getenforce,
    parse_id,
    parse_mount_line,
    parse_paths,
    parse_processes,
    parse_raw_report,
    parse_raw_text,
)
from trustlab.validators import validate_report

ROOT = Path(__file__).resolve().parents[1]
ADVERSARIAL = ROOT / "tests/fixtures/adversarial_raw_report.txt"


def test_checked_in_adversarial_fixture_preserves_evidence_semantics():
    parsed = parse_raw_report(ADVERSARIAL)

    assert parsed["sections"]["GETPROP"].count("ro.secure") == 1
    assert parsed["sections"]["GETPROP"].count("ro.debuggable") == 2
    assert "sys.boot_completed" in parsed["sections"]["GETPROP"]
    assert parsed["properties"]["ro.secure"] == "unknown"
    # Duplicate sections are concatenated in capture order; the later repeated
    # property deterministically wins while a literal "unknown" remains data.
    assert parsed["properties"]["ro.debuggable"] == "0"
    assert parsed["properties"]["sys.boot_completed"] == "1"
    assert parsed["selinux_mode"] == "inaccessible"
    assert [mount["classification"] for mount in parsed["mounts"]] == [
        "read-only",
        "unknown",
        "overlay",
        "tmpfs",
        "bind mount",
    ]

    report = normalize_raw_file(
        ADVERSARIAL,
        experiment_id="E10_adversarial",
        target_type="avd",
        collection_timestamp="2026-01-02T03:04:05Z",
        raw_artifact_ref="tests/fixtures/adversarial_raw_report.txt",
    )
    validate_report(report)
    assert report["properties"]["security"]["value"]["ro.secure"] == "unknown"
    assert report["properties"]["all_count"]["value"] == 4
    assert report["mounts"]["system_mount"]["classification"] == "overlay"
    assert report["mounts"]["vendor_mount"]["classification"] == "tmpfs"
    assert report["mounts"]["product_mount"]["classification"] == "other"
    assert report["mounts"]["product_mount"]["raw"].endswith("rw,bind")
    assert report["limitations"]["collection_errors"] == []


def test_truncated_and_variant_parser_inputs_degrade_explicitly():
    assert parse_mount_line("")["classification"] == "unknown"
    assert parse_mount_line("truncated command")["mount_point"] == "unknown"
    assert classify_mount("overlay", ["rw"]) == "overlay"
    assert classify_mount("tmpfs", ["rw"]) == "tmpfs"
    assert classify_mount("ext4", ["rbind"]) == "bind mount"
    assert classify_mount("ext4", ["rw"]) == "read-write"
    assert classify_mount("ext4", ["ro"]) == "read-only"
    assert classify_mount("ext4", []) == "unknown"
    assert parse_id("uid output was truncated")["uid"] == "unknown"
    assert parse_getenforce("Permissive") == "permissive"
    assert parse_getenforce("unexpected output") == "unknown"
    assert parse_paths("not found\n/system/xbin/su") == ["/system/xbin/su"]
    processes = parse_processes(
        "u:r:init:s0 init\nadbd\nzygote64\nsystem_server\nmagiskd"
    )
    assert processes == {
        "raw_line_count": 5,
        "init_visible": True,
        "adbd_visible": True,
        "zygote_visible": True,
        "system_server_visible": True,
        "magisk_processes_visible": True,
        "process_contexts_available": True,
    }


def test_enormous_property_line_is_rejected_without_truncation():
    value = "x" * 1_000_000
    with pytest.raises(NormalizationError, match="line byte limit"):
        parse_raw_text(f"=== GETPROP ===\n[ro.product.model]: [{value}]")


def test_invalid_utf8_policy_rejects_raw_artifact(tmp_path):
    invalid = tmp_path / "invalid.raw"
    invalid.write_bytes(bytes((0xFF, 0xFE, 0x80)))
    with pytest.raises(CollectionError, match="input artifact is not valid UTF-8"):
        normalize_raw_file(invalid)


def test_permission_failure_is_a_collection_error(tmp_path, monkeypatch):
    private = tmp_path / "private.raw"
    private.write_text("unreachable", encoding="utf-8")

    def deny_open(*args, **kwargs):
        raise PermissionError("injected permission failure")

    monkeypatch.setattr(bounded_io_module.os, "open", deny_open)
    with pytest.raises(CollectionError, match="could not open raw input artifact"):
        normalize_raw_file(private)
