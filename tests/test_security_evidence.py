from __future__ import annotations

from pathlib import Path

import pytest

from trustlab.security_evidence import (
    parse_processes,
    parse_selinux_context,
    sanitize_selinux_context,
)

FIXTURES = Path(__file__).parent / "fixtures" / "processes"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("name", "expected_format", "expected_names"),
    [
        ("toybox_ps.txt", "toybox", ["init", "zygote64", "magiskd"]),
        ("toolbox_ps.txt", "toolbox", ["init", "adbd", "system_server"]),
        ("reordered_ps.txt", "toybox", ["init", "zygote"]),
    ],
)
def test_supported_ps_headers_use_exact_selected_names(
    name: str, expected_format: str, expected_names: list[str]
) -> None:
    result = parse_processes(
        fixture(name),
        scope="complete",
        evidence_path=f"captures/{name}",
    )

    assert result["format"] == expected_format
    assert result["parse_status"] == "complete"
    assert [item["name"] for item in result["observations"]] == expected_names


def test_selected_list_rejects_similar_names_and_does_not_infer_absence() -> None:
    result = parse_processes(
        fixture("selected_ps.txt"),
        scope="selected",
        evidence_path="captures/ps-selected.txt",
    )

    assert result["scope"] == "selected"
    assert result["parse_status"] == "partial"
    assert [item["name"] for item in result["observations"]] == [
        "init",
        "zygote",
        "magisk",
    ]
    assert "zygote-helper" not in str(result)


def test_truncated_or_short_rows_make_complete_table_partial() -> None:
    result = parse_processes(
        fixture("truncated_ps.txt"),
        scope="complete",
        evidence_path="captures/ps.txt",
    )

    assert result["parse_status"] == "partial"
    assert result["malformed_line_count"] == 1
    assert [item["name"] for item in result["observations"]] == ["init"]


def test_headerless_complete_table_is_unsupported() -> None:
    result = parse_processes(
        "root 1 0 init\n",
        scope="complete",
        evidence_path="captures/ps.txt",
    )

    assert result["parse_status"] == "unsupported"
    assert result["observations"] == []


@pytest.mark.parametrize(
    "text",
    [
        "PID NAME USER\n1 init root\n",
        "PID NAME NAME\n1 init init\n",
    ],
)
def test_ambiguous_or_command_bearing_headers_are_unsupported(text: str) -> None:
    result = parse_processes(
        text,
        scope="complete",
        evidence_path="captures/ps.txt",
    )

    assert result["parse_status"] == "unsupported"
    assert result["observations"] == []


def test_repeated_header_and_nonnumeric_pid_make_table_partial() -> None:
    result = parse_processes(
        "USER PID NAME\nroot 1 init\nUSER PID NAME\nroot nope adbd\n",
        scope="complete",
        evidence_path="captures/ps.txt",
    )

    assert result["parse_status"] == "partial"
    assert result["malformed_line_count"] == 2
    assert [item["name"] for item in result["observations"]] == ["init"]


@pytest.mark.parametrize("truncated_name", ["magis+", "zygote...", "ad…"])
def test_truncated_terminal_name_makes_table_partial(truncated_name: str) -> None:
    result = parse_processes(
        f"USER PID NAME\nroot 1 init\nroot 2 {truncated_name}\n",
        scope="complete",
        evidence_path="captures/ps.txt",
    )

    assert result["parse_status"] == "partial"
    assert result["malformed_line_count"] == 1
    assert [item["name"] for item in result["observations"]] == ["init"]


def test_selinux_context_is_sanitized_and_filesystem_rows_are_ignored() -> None:
    result = parse_selinux_context(
        "u:r:untrusted_app:s0:c123,c456\nu:object_r:system_file:s0 /system\n"
    )

    assert result == {
        "parse_status": "parsed",
        "value": "u:r:untrusted_app:s0",
        "evidence_refs": ["unknown#L1"],
        "warnings": ["ignored non-process SELinux context rows"],
    }
    assert sanitize_selinux_context("u:r:init:s0") == "u:r:init:s0"


@pytest.mark.parametrize(
    "value",
    [
        "u:object_r:system_file:s0",
        "u:r:init:s0 /system",
        "u:r:init:s0 secret",
        "not-a-context",
        "u:r:init:s0:c",
        "u:r:init:s0:---",
        "u:r:init:s0:..",
        "u:r:init:s0:c1,,c2",
    ],
)
def test_malformed_or_nonprocess_context_is_rejected(value: str) -> None:
    assert sanitize_selinux_context(value) is None
