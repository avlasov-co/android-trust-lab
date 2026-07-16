from __future__ import annotations

import copy
from pathlib import Path

import pytest

from trustlab.exceptions import SchemaValidationError
from trustlab.identity import finalize_report_identity
from trustlab.normalizer import normalize_raw_file
from trustlab.validators import validate_report

MOUNT_FIXTURES = Path(__file__).parent / "fixtures" / "mounts"


def normalize_mountinfo(tmp_path: Path, *fixture_names: str) -> dict:
    mountinfo = "".join(
        (MOUNT_FIXTURES / name).read_text(encoding="utf-8") for name in fixture_names
    )
    raw = tmp_path / "modern-mounts.txt"
    raw.write_text(
        """=== GETPROP ===
[ro.product.device]: [synthetic]
[ro.build.version.release]: [16]
[ro.build.version.sdk]: [36]
=== MOUNTINFO ===
"""
        + mountinfo
        + """=== ID ===
uid=2000(shell) gid=2000(shell) groups=2000(shell)
=== GETENFORCE ===
Enforcing
""",
        encoding="utf-8",
    )
    report = normalize_raw_file(
        raw,
        experiment_id="E18_modern_mounts",
        target_type="avd",
        observer_type="adb_shell",
        collection_method="raw_artifact",
        collection_timestamp="2026-07-16T12:00:00Z",
        raw_artifact_ref="fixtures/modern-mounts.txt",
    )
    validate_report(report)
    return report


def test_system_as_root_is_resolved_without_fabricating_system_mount(
    tmp_path: Path,
) -> None:
    report = normalize_mountinfo(tmp_path, "system_as_root_mountinfo.txt")
    mounts = report["mounts"]

    assert report["schema_version"] == "5.0.0"
    assert mounts["system_resolution"] == {
        "state": "system_as_root",
        "system_root": "/",
        "record_indices": [0],
        "reason": "no /system mount was observed; one root mount is the system root",
    }
    assert all(record["mount_point"] != "/system" for record in mounts["records"])
    assert mounts["system_mount"]["status"] != "observed"
    assert mounts["observation"]["selected_source"] == "mountinfo"
    assert mounts["observation"]["selected_format"] == "mountinfo"


def test_dynamic_partitions_and_apex_set_are_deterministic(tmp_path: Path) -> None:
    report = normalize_mountinfo(
        tmp_path,
        "dynamic_partitions_mountinfo.txt",
        "apex_set_mountinfo.txt",
    )
    mounts = report["mounts"]

    assert mounts["dynamic_partitions"] == {
        "state": "detected",
        "record_indices": [0, 1, 2],
        "sources": [
            "/dev/block/dm-0",
            "/dev/block/mapper/product_a",
            "/dev/block/mapper/vendor_a",
        ],
    }
    assert mounts["apex_set"] == {
        "packages": ["com.android.art", "com.android.runtime"],
        "record_indices": [3, 4, 5],
        "mount_count": 3,
        "package_count": 2,
        "read_only_count": 3,
        "writable_count": 0,
        "unknown_access_count": 0,
        "overlay_count": 0,
        "bind_count": 0,
    }


def test_overlay_does_not_create_a_writable_integrity_verdict(tmp_path: Path) -> None:
    mountinfo = tmp_path / "modern-mounts.txt"
    mountinfo.write_text(
        """=== GETPROP ===
[ro.product.device]: [synthetic]
=== MOUNTINFO ===
60 35 0:45 / /system ro,seclabel - overlay overlay rw,lowerdir=/system
=== ID ===
uid=2000(shell) gid=2000(shell)
=== GETENFORCE ===
Enforcing
""",
        encoding="utf-8",
    )
    report = normalize_raw_file(
        mountinfo,
        experiment_id="E18_overlay_context",
        target_type="avd",
        collection_timestamp="2026-07-16T12:00:00Z",
        raw_artifact_ref="fixtures/modern-mounts.txt",
    )
    validate_report(report)
    mounts = report["mounts"]

    assert mounts["records"][0]["overlay_state"] == "detected"
    assert mounts["records"][0]["access"] == "read_only"
    assert mounts["integrity_summary"]["writable_sensitive_mounts"]["value"] == []
    assert mounts["integrity_context"]["assessment"] == "not_assessed"
    assert "not an integrity verdict" in mounts["integrity_context"]["reason"]


def test_nested_system_path_is_not_selected_as_the_system_mount(tmp_path: Path) -> None:
    mountinfo = tmp_path / "nested.txt"
    mountinfo.write_text(
        """=== GETPROP ===
[ro.product.device]: [synthetic]
=== MOUNTINFO ===
61 35 0:46 / /system/bin ro - tmpfs tmpfs ro
=== ID ===
uid=2000(shell) gid=2000(shell)
=== GETENFORCE ===
Enforcing
""",
        encoding="utf-8",
    )
    report = normalize_raw_file(
        mountinfo,
        experiment_id="E18_nested_mount",
        target_type="avd",
        collection_timestamp="2026-07-16T12:00:00Z",
        raw_artifact_ref="fixtures/nested.txt",
    )

    assert report["mounts"]["system_resolution"]["state"] == "unresolved"
    assert report["mounts"]["system_mount"]["status"] != "observed"


def test_partial_mountinfo_keeps_absence_based_layout_claims_unknown(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "partial-mountinfo.txt"
    raw.write_text(
        """=== GETPROP ===
[ro.product.device]: [synthetic]
=== MOUNTINFO ===
35 24 8:1 / / ro - ext4 /dev/block/sda1 ro
malformed mountinfo line
=== ID ===
uid=2000(shell) gid=2000(shell)
=== GETENFORCE ===
Enforcing
""",
        encoding="utf-8",
    )

    report = normalize_raw_file(
        raw,
        experiment_id="E18_partial_mounts",
        target_type="avd",
        collection_timestamp="2026-07-16T12:00:00Z",
        raw_artifact_ref="fixtures/partial-mountinfo.txt",
    )
    validate_report(report)
    mounts = report["mounts"]

    assert mounts["observation"]["parse_status"] == "partial"
    assert mounts["system_resolution"] == {
        "state": "unresolved",
        "system_root": None,
        "record_indices": [0],
        "reason": "partial evidence cannot establish that /system is absent",
    }
    assert mounts["dynamic_partitions"]["state"] == "unknown"


def test_partial_generic_mount_fallback_keeps_layout_claims_unknown(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "partial-generic-mount.txt"
    raw.write_text(
        """=== GETPROP ===
[ro.product.device]: [synthetic]
=== MOUNT ===
/dev/block/root on / type ext4
=== ID ===
uid=2000(shell) gid=2000(shell)
=== GETENFORCE ===
Enforcing
""",
        encoding="utf-8",
    )

    report = normalize_raw_file(
        raw,
        experiment_id="E18_partial_generic_mount",
        target_type="avd",
        collection_timestamp="2026-07-16T12:00:00Z",
        raw_artifact_ref="fixtures/partial-generic-mount.txt",
    )
    validate_report(report)
    mounts = report["mounts"]

    assert mounts["observation"]["selected_source"] == "mounts"
    assert mounts["observation"]["parse_status"] == "partial"
    assert mounts["records"][0]["parse_status"] == "partial"
    assert mounts["system_resolution"]["state"] == "unresolved"
    assert mounts["dynamic_partitions"]["state"] == "unknown"


def test_mount_records_are_bound_into_report_content_identity(tmp_path: Path) -> None:
    report = normalize_mountinfo(tmp_path, "system_as_root_mountinfo.txt")
    changed = copy.deepcopy(report)
    changed["mounts"]["records"][0]["raw"] += " "
    changed = finalize_report_identity(changed)

    assert changed["content_digest"] != report["content_digest"]
    assert changed["report_id"] != report["report_id"]
    validate_report(changed)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda mounts: mounts["records"][0].update(record_index=7),
        lambda mounts: mounts["observation"].update(evidence_paths=[]),
        lambda mounts: mounts["observation"]["attempts"][0].update(record_count=1),
        lambda mounts: mounts["records"][0].update(format="proc_mounts"),
        lambda mounts: mounts["system_resolution"].update(state="unresolved"),
        lambda mounts: mounts["dynamic_partitions"].update(state="unknown"),
        lambda mounts: mounts["apex_set"].update(package_count=99),
    ],
)
def test_v4_mount_semantics_reject_internally_inconsistent_aggregates(
    tmp_path: Path, mutation
) -> None:
    report = normalize_mountinfo(
        tmp_path,
        "dynamic_partitions_mountinfo.txt",
        "apex_set_mountinfo.txt",
    )
    mutation(report["mounts"])
    report = finalize_report_identity(report)

    with pytest.raises(SchemaValidationError, match="report mount validation failed"):
        validate_report(report)


def test_v4_mount_semantics_reject_fallback_selected_over_usable_mountinfo(
    tmp_path: Path,
) -> None:
    report = normalize_mountinfo(tmp_path, "system_as_root_mountinfo.txt")
    mounts = report["mounts"]
    fallback = next(
        attempt
        for attempt in mounts["observation"]["attempts"]
        if attempt["name"] == "proc_mounts"
    )
    fallback.update(
        format="proc_mounts",
        capture_status="observed",
        parse_status="complete",
        source_ref="legacy-sections/PROC_MOUNTS",
        record_count=len(mounts["records"]),
        malformed_line_count=0,
        warnings=[],
    )
    mounts["observation"].update(
        selected_source="proc_mounts",
        selected_format="proc_mounts",
    )
    for record in mounts["records"]:
        record["format"] = "proc_mounts"
    report = finalize_report_identity(report)

    with pytest.raises(
        SchemaValidationError,
        match="first usable fixed-priority attempt",
    ):
        validate_report(report)


def test_v4_mount_semantics_reject_source_name_format_mismatch(
    tmp_path: Path,
) -> None:
    report = normalize_mountinfo(tmp_path, "system_as_root_mountinfo.txt")
    mounts = report["mounts"]
    mounts["observation"]["attempts"][0]["format"] = "mount"
    mounts["observation"]["selected_format"] = "mount"
    for record in mounts["records"]:
        record["format"] = "mount"
    report = finalize_report_identity(report)

    with pytest.raises(SchemaValidationError, match="does not match its format"):
        validate_report(report)


def test_v4_mount_semantics_reject_selected_inaccessible_attempt(
    tmp_path: Path,
) -> None:
    report = normalize_mountinfo(tmp_path, "system_as_root_mountinfo.txt")
    report["mounts"]["observation"]["attempts"][0]["capture_status"] = "inaccessible"
    report = finalize_report_identity(report)

    with pytest.raises(SchemaValidationError, match="cannot claim parsed records"):
        validate_report(report)
