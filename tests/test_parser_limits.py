from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import trustlab.artifacts as artifacts_module
import trustlab.normalizer as normalizer_module
import trustlab.parser as parser_module
from trustlab.artifacts import ADAPTERS, CaptureStatus, InputKind, parse_artifact_text
from trustlab.exceptions import CollectionError, InvalidJSONError, NormalizationError
from trustlab.normalizer import (
    normalize_collection_manifest_with_inputs,
    normalize_raw_file,
)
from trustlab.parser import parse_paths, parse_raw_report, parse_raw_text
from trustlab.validators import validate_report

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_FIXTURE = ROOT / "tests/fixtures/adapters/adb_manifest.json"
COLLECTION_MANIFEST = (
    ROOT / "datasets/samples/magisk_collector/collector_manifest_sample.json"
)


@pytest.mark.parametrize("character", ["\x00", "\x01", "\x7f", "\x85"])
def test_control_characters_are_rejected_with_location(character):
    with pytest.raises(NormalizationError, match=r"line 2, column 1"):
        parse_raw_text(f"=== ID ===\n{character}uid=2000(shell)")


def test_crlf_is_accepted_with_an_explicit_warning():
    parsed = parse_raw_text(
        "=== GETPROP ===\r\n[ro.secure]: [unknown]\r\n=== ID ===\r\n"
    )

    assert parsed["properties"] == {"ro.secure": "unknown"}
    assert parsed["warnings"] == ["CR/CRLF line endings normalized during parsing"]


def test_total_byte_limit_is_enforced_before_section_parsing(monkeypatch):
    monkeypatch.setattr(parser_module, "MAX_RAW_TEXT_BYTES", 16)

    with pytest.raises(NormalizationError, match="total byte limit"):
        parse_raw_text("=== ID ===\nuid=0(root)")


def test_line_byte_limit_counts_encoded_bytes(monkeypatch):
    monkeypatch.setattr(parser_module, "MAX_LINE_BYTES", 8)

    with pytest.raises(NormalizationError, match=r"line 1"):
        parse_raw_text("ééééé")


def test_section_and_entry_limits_fail_closed(monkeypatch):
    monkeypatch.setattr(parser_module, "MAX_SECTION_COUNT", 2)
    with pytest.raises(NormalizationError, match="section count limit"):
        parse_raw_text("=== ID ===\n=== ID ===\n=== ID ===")

    monkeypatch.setattr(parser_module, "MAX_ENTRIES_PER_SECTION", 2)
    with pytest.raises(NormalizationError, match="entry count limit"):
        parse_raw_text("=== ID ===\none\ntwo\nthree")

    with pytest.raises(NormalizationError, match=r"malformed section header at line 2"):
        parse_raw_text("=== GETPROP ===\n=== truncated header")
    with pytest.raises(NormalizationError, match=r"empty section header at line 1"):
        parse_raw_text("===    ===")
    with pytest.raises(NormalizationError, match=r"malformed section header at line 1"):
        parse_raw_text("=== KEY ===")


def test_warning_limit_ends_with_an_explicit_omission_notice(monkeypatch):
    monkeypatch.setattr(parser_module, "MAX_PARSER_WARNINGS", 3)
    parsed = parse_raw_text(
        "=== FUTURE_A ===\na\n"
        "=== FUTURE_B ===\nb\n"
        "=== FUTURE_C ===\nc\n"
        "=== FUTURE_D ===\nd\n"
    )

    assert len(parsed["warnings"]) == 3
    assert parsed["warnings"][-1] == parser_module.PARSER_WARNING_LIMIT_MESSAGE


def test_repeated_sections_and_duplicate_keys_are_deterministic_and_value_safe():
    text = """=== GETPROP ===
[ro.secure]: [unknown]
[ro.debuggable]: [super-secret-a]
[ro.debuggable]: [super-secret-a]
=== GETPROP ===
[ro.debuggable]: [super-secret-b]
[truncated]: [missing
=== BOOT_STATE ===
verified=unknown
verified=unknown
verified=green
truncated
"""

    first = parse_raw_text(text)
    second = parse_raw_text(text)

    assert first == second
    assert first["section_occurrences"]["GETPROP"] == 2
    assert first["properties"]["ro.secure"] == "unknown"
    assert first["properties"]["ro.debuggable"] == "super-secret-b"
    assert first["boot_state_raw"]["verified"] == "green"
    assert any("duplicate section" in warning for warning in first["warnings"])
    assert any("duplicate GETPROP key" in warning for warning in first["warnings"])
    assert any("conflicting GETPROP key" in warning for warning in first["warnings"])
    assert any("malformed GETPROP" in warning for warning in first["warnings"])
    assert any("duplicate BOOT_STATE key" in warning for warning in first["warnings"])
    assert any("conflicting BOOT_STATE key" in warning for warning in first["warnings"])
    assert any("malformed BOOT_STATE" in warning for warning in first["warnings"])
    assert all("super-secret" not in warning for warning in first["warnings"])


def test_semantic_section_aliases_have_explicit_deterministic_precedence():
    parsed = parse_raw_text(
        """=== GETPROP ===
[ro.secure]: [1]
=== PROPS ===
[ro.secure]: [0]
=== MOUNT ===
/dev/a on /system type ext4 (ro)
=== MOUNTS ===
/dev/b on /vendor type ext4 (rw)
=== GETENFORCE ===
Enforcing
=== SELINUX ===
Permissive
=== PS ===
root 1 init
=== PROCESSES ===
root 2 magiskd
"""
    )

    assert parsed["properties"]["ro.secure"] == "1"
    assert parsed["mounts"][0]["mount_point"] == "/system"
    assert parsed["selinux_mode"] == "enforcing"
    assert parsed["processes"]["init_visible"] is True
    assert parsed["processes"]["magisk_processes_visible"] is False
    assert sum("conflicting aliases" in item for item in parsed["warnings"]) == 4


def test_shell_diagnostics_never_become_path_evidence(tmp_path):
    assert parse_paths(
        """/system/xbin/su
/data/local/tmp/timeout
/data/inaccessible
/system/bin/sh: su: not found
/data/local/tmp/su: Permission denied
error: capture failed
sh: command not found
su: not found
unstructured output
"""
    ) == ["/system/xbin/su", "/data/local/tmp/timeout", "/data/inaccessible"]

    source = tmp_path / "failed-su-capture.txt"
    source.write_text(
        "=== SU_PATHS ===\n/system/bin/sh: su: Permission denied\n",
        encoding="utf-8",
    )
    report = normalize_raw_file(
        source,
        experiment_id="E17_parser_limits",
        target_type="avd",
        collection_timestamp="2026-07-16T12:00:00Z",
    )

    assert report["root_state"]["root_paths"]["status"] == "not_collected"
    assert report["root_state"]["su_present"]["status"] == "not_collected"
    assert any(
        "inferred inaccessible" in warning
        for warning in report["extensions"]["org.androidtrustlab.adapter"]["warnings"]
    )


def test_genuinely_empty_success_remains_distinct_from_command_failure():
    document = json.loads(ADAPTER_FIXTURE.read_text(encoding="utf-8"))
    capture = document["captures"][0]
    capture.update(
        name="su_paths",
        status="empty",
        exit_code=0,
        timed_out=False,
        stdout="",
        stderr="",
        source_ref="captures/su-paths.txt",
    )
    document["captures"] = [capture]

    result = ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
        json.dumps(document), source_ref="fixture"
    )

    assert result.captures[0].status is CaptureStatus.EMPTY
    assert result.fragments.su_paths == ()
    assert result.errors == ()
    assert result.parsed_capture_names == frozenset({"su_paths"})


@pytest.mark.parametrize(
    ("diagnostic", "expected_status", "timed_out"),
    [
        ("ps: command not found", CaptureStatus.COMMAND_ERROR, False),
        ("process capture timed out", CaptureStatus.TIMEOUT, True),
    ],
)
def test_legacy_command_failures_receive_inferred_command_status(
    diagnostic, expected_status, timed_out
):
    result = ADAPTERS[InputKind.LEGACY_SECTIONED_TEXT].parse(
        f"=== PS ===\n{diagnostic}\n", source_ref="legacy.txt"
    )
    capture = next(item for item in result.captures if item.name == "processes")

    assert capture.status is expected_status
    assert capture.timed_out is timed_out
    assert capture.stdout == ""
    assert capture.stderr == (
        f"legacy {expected_status.value} inferred from diagnostic output"
    )
    assert result.fragments.processes["raw_line_count"] == 0
    assert result.errors == (f"capture processes ended with {expected_status.value}",)


def test_historical_negative_sentinel_remains_observed_absence():
    result = ADAPTERS[InputKind.LEGACY_SECTIONED_TEXT].parse(
        "=== MAGISK ===\nmagisk: not found in PATH\n", source_ref="legacy.txt"
    )
    capture = next(item for item in result.captures if item.name == "magisk")

    assert capture.status is CaptureStatus.OBSERVED
    assert result.fragments.magisk_text == "magisk: not found in PATH"
    assert result.errors == ()


def test_diagnostic_words_inside_structured_evidence_remain_literal_values():
    result = ADAPTERS[InputKind.LEGACY_SECTIONED_TEXT].parse(
        "=== GETPROP ===\n"
        "[ro.product.model]: [Not Found Edition]\n"
        "[ro.product.device]: [inaccessible_lab]\n",
        source_ref="legacy.txt",
    )
    capture = next(item for item in result.captures if item.name == "properties")

    assert capture.status is CaptureStatus.OBSERVED
    assert result.fragments.properties == {
        "ro.product.model": "Not Found Edition",
        "ro.product.device": "inaccessible_lab",
    }


def test_unrecognized_sections_are_hashed_for_provenance_only(tmp_path):
    source = tmp_path / "unknown-section.txt"
    content = "opaque payload that must not become evidence"
    source.write_text(
        f"=== future_probe ===\n{content}\n=== FUTURE_EMPTY ===\n=== ID ===\n"
        "uid=2000(shell) gid=2000(shell)\n",
        encoding="utf-8",
    )

    report = normalize_raw_file(
        source,
        experiment_id="E17_parser_limits",
        target_type="avd",
        collection_timestamp="2026-07-16T12:00:00Z",
    )
    validate_report(report)
    provenance = report["extensions"]["org.androidtrustlab.adapter"][
        "unrecognized_sections"
    ]

    assert provenance == [
        {
            "name": "FUTURE_EMPTY",
            "occurrence_count": 1,
            "byte_size": 0,
            "sha256": hashlib.sha256(b"").hexdigest(),
        },
        {
            "name": "FUTURE_PROBE",
            "occurrence_count": 1,
            "byte_size": len(content.encode()),
            "sha256": hashlib.sha256(content.encode()).hexdigest(),
        },
    ]
    assert content not in json.dumps(report)


def test_collection_manifest_rejects_oversized_raw_before_verification(tmp_path):
    document = json.loads(COLLECTION_MANIFEST.read_text(encoding="utf-8"))
    raw_entry = next(
        item for item in document["artifacts"] if item["logical_name"] == "raw_report"
    )
    raw_entry["byte_size"] = normalizer_module.MAX_RAW_ARTIFACT_BYTES + 1
    manifest = tmp_path / "oversized-manifest.json"
    manifest.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CollectionError, match="raw_report exceeds the byte limit"):
        normalize_collection_manifest_with_inputs(manifest)


def test_invalid_utf8_reports_the_failing_byte_offset(tmp_path):
    source = tmp_path / "invalid.raw"
    source.write_bytes(b"=== ID ===\n\xff")

    with pytest.raises(CollectionError, match=r"UTF-8 at byte 11: invalid\.raw"):
        parse_raw_report(source)


def test_json_depth_and_node_limits_fail_as_domain_errors(monkeypatch):
    document = json.loads(ADAPTER_FIXTURE.read_text(encoding="utf-8"))
    nested: object = "leaf"
    for _ in range(artifacts_module.MAX_JSON_NESTING_DEPTH + 1):
        nested = [nested]
    document["warnings"] = nested
    with pytest.raises(NormalizationError, match="nesting depth limit"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )

    monkeypatch.setattr(artifacts_module, "MAX_JSON_NODES", 10)
    with pytest.raises(NormalizationError, match="node count limit"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            ADAPTER_FIXTURE.read_text(encoding="utf-8"), source_ref="fixture"
        )


def test_schema_validation_stops_after_the_first_error(monkeypatch):
    yielded = 0

    def many_errors(self, instance):
        nonlocal yielded
        for _ in range(10_000):
            yielded += 1
            yield object()

    monkeypatch.setattr(
        artifacts_module.Draft202012Validator,
        "iter_errors",
        many_errors,
    )
    with pytest.raises(NormalizationError, match="does not match"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            ADAPTER_FIXTURE.read_text(encoding="utf-8"), source_ref="fixture"
        )

    assert yielded == 1


def test_decoder_recursion_is_converted_to_a_stable_domain_error(monkeypatch):
    def recurse(*args, **kwargs):
        raise RecursionError("injected decoder recursion")

    monkeypatch.setattr(artifacts_module.json, "loads", recurse)
    with pytest.raises(InvalidJSONError, match="decoder nesting limit"):
        parse_artifact_text("{}", source_ref="hostile.json")


def test_json_crlf_warning_is_retained_by_typed_adapter():
    text = ADAPTER_FIXTURE.read_text(encoding="utf-8").replace("\n", "\r\n")

    result = parse_artifact_text(text, source_ref="fixture")

    assert "CR/CRLF line endings normalized during parsing" in result.warnings


def test_escaped_json_controls_are_checked_after_decoding():
    document = json.loads(ADAPTER_FIXTURE.read_text(encoding="utf-8"))
    document["captures"][0]["stdout"] = "\x00"

    with pytest.raises(NormalizationError, match="contains NUL"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )


def test_decoded_json_crlf_is_diagnosed():
    document = json.loads(ADAPTER_FIXTURE.read_text(encoding="utf-8"))
    document["warnings"] = ["collector warning\r\ncontinued"]

    result = ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
        json.dumps(document), source_ref="fixture"
    )

    assert "decoded JSON string: CR/CRLF line endings normalized during parsing" in (
        result.warnings
    )
