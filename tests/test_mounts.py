from __future__ import annotations

from pathlib import Path

import pytest

from trustlab.mounts import decode_mount_field, parse_mounts_with_diagnostics

FIXTURES = Path(__file__).parent / "fixtures" / "mounts"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("name", "input_format", "expected_count"),
    [
        ("legacy_proc_mounts.txt", "proc_mounts", 3),
        ("dynamic_partitions_mountinfo.txt", "mountinfo", 3),
        ("system_as_root_mountinfo.txt", "mountinfo", 2),
        ("apex_set_mountinfo.txt", "mountinfo", 3),
        ("bind_mount.txt", "mount", 1),
        ("overlay_mountinfo.txt", "mountinfo", 1),
        ("namespaced_mountinfo.txt", "mountinfo", 2),
    ],
)
def test_requested_mount_layout_fixtures_parse(
    name: str, input_format: str, expected_count: int
) -> None:
    result = parse_mounts_with_diagnostics(
        fixture(name),
        input_format=input_format,  # type: ignore[arg-type]
        evidence_path=f"captures/{name}",
    )

    assert result["parse_status"] == "complete"
    assert len(result["records"]) == expected_count
    assert result["malformed_line_count"] == 0
    assert all(record["root"] is None for record in result["records"]) == (
        input_format != "mountinfo"
    )


def test_mountinfo_preserves_topology_propagation_and_per_mount_access() -> None:
    result = parse_mounts_with_diagnostics(
        fixture("namespaced_mountinfo.txt"),
        input_format="mountinfo",
        evidence_path="captures/mountinfo",
    )
    shared, unbindable = result["records"]

    assert shared["mount_id"] == 70
    assert shared["parent_id"] == 35
    assert shared["major_minor"] == "253:0"
    assert shared["propagation"] == {
        "kind": "shared_slave",
        "shared_id": 12,
        "master_id": 4,
        "propagate_from_id": 3,
        "unbindable": False,
    }
    assert unbindable["propagation"]["kind"] == "unbindable"
    assert shared["access"] == "read_only"
    assert shared["mount_options"] == ["ro"]
    assert shared["super_options"] == ["rw"]
    assert shared["evidence_path"] == "captures/mountinfo#L1"


def test_overlay_and_bind_are_orthogonal_to_access() -> None:
    overlay = parse_mounts_with_diagnostics(
        fixture("overlay_mountinfo.txt"), input_format="mountinfo"
    )["records"][0]
    bind = parse_mounts_with_diagnostics(
        fixture("bind_mount.txt"), input_format="mount"
    )["records"][0]

    assert overlay["overlay_state"] == "detected"
    assert overlay["bind_state"] == "unknown"
    assert overlay["access"] == "writable"
    assert bind["overlay_state"] == "not_detected"
    assert bind["bind_state"] == "detected"
    assert bind["access"] == "writable"


def test_mountinfo_root_does_not_imply_bind_mount() -> None:
    result = parse_mounts_with_diagnostics(
        "90 35 253:0 /system /mnt/system ro - ext4 /dev/block/dm-0 rw\n",
        input_format="mountinfo",
    )

    assert result["records"][0]["bind_state"] == "unknown"
    assert result["records"][0]["bind"] is False


def test_mount_escape_decoding_is_explicit_and_single_pass() -> None:
    assert decode_mount_field(r"space\040tab\011line\012slash\134") == (
        "space tab\tline\nslash\\"
    )
    with pytest.raises(ValueError, match="non-standard"):
        decode_mount_field(r"unexpected\141escape")
    with pytest.raises(ValueError, match="invalid"):
        decode_mount_field(r"literal\backslash")


def test_partial_and_inaccessible_captures_preserve_uncertainty() -> None:
    partial = parse_mounts_with_diagnostics(
        fixture("malformed_mountinfo.txt"),
        input_format="mountinfo",
        evidence_path="captures/mountinfo",
    )
    inaccessible = parse_mounts_with_diagnostics(
        fixture("inaccessible_mountinfo.txt"),
        input_format="mountinfo",
        evidence_path="captures/mountinfo",
    )

    assert partial["parse_status"] == "partial"
    assert partial["malformed_line_count"] == 1
    assert len(partial["records"]) == 1
    assert partial["warnings"] == ["mount mountinfo line 2 parsed as malformed"]
    assert inaccessible["parse_status"] == "malformed"
    assert inaccessible["records"] == []
    assert inaccessible["malformed_line_count"] == 1


def test_empty_capture_is_distinct_from_malformed_capture() -> None:
    result = parse_mounts_with_diagnostics("\n", input_format="mountinfo")

    assert result["parse_status"] == "empty"
    assert result["records"] == []


def test_mount_parser_warnings_are_bounded_for_adversarial_input() -> None:
    text = "35 24 253:0 / / ro - ext4 /dev/block/dm-0 ro\n" + "\n".join(
        f"malformed mount line {index}" for index in range(300)
    )

    result = parse_mounts_with_diagnostics(text, input_format="mountinfo")

    assert result["parse_status"] == "partial"
    assert result["malformed_line_count"] == 300
    assert len(result["warnings"]) == 256
    assert result["warnings"][-1] == (
        "additional mount parser warnings omitted after limit"
    )
