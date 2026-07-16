from __future__ import annotations

import copy
from pathlib import Path

import pytest

import trustlab.canonical_json as canonical_json_module
import trustlab.normalizer as normalizer_module
from trustlab.canonical_json import (
    CanonicalJSONError,
    canonical_json_bytes,
    canonicalize_json,
    framed_content_digest,
)
from trustlab.diff import make_diff
from trustlab.exceptions import CollectionError, SchemaValidationError
from trustlab.identity import (
    REPORT_EVIDENCE_FIELDS,
    calculate_report_id,
    finalize_report_identity,
)
from trustlab.normalizer import normalize_raw_bytes
from trustlab.validators import validate_diff, validate_report

ROOT = Path(__file__).resolve().parents[1]
RAW = (ROOT / "tests/fixtures/sample_raw_report.txt").read_bytes()


def normalized(
    payload: bytes = RAW,
    *,
    timestamp: str = "2026-01-02T03:04:05Z",
    relative_path: str = "observations/raw.txt",
) -> dict[str, object]:
    return normalize_raw_bytes(
        payload,
        label="raw.txt",
        experiment_id="E10_identity",
        target_type="avd",
        observer_type="adb_shell",
        collection_method="identity_fixture",
        collection_timestamp=timestamp,
        raw_artifact_ref=relative_path,
        raw_artifact_id="identity-raw-report",
        collector_name="trustlab-fixtures",
        collector_version="1.0.0",
        collection_id=None,
        redaction_state="not_required",
    )


def test_atl_canonical_json_has_a_frozen_ordering_and_digest_vector():
    value = {"z": [3, 2, 1], "a": "é", "n": None}

    assert canonical_json_bytes(value) == b'{"a":"\xc3\xa9","n":null,"z":[3,2,1]}'
    assert canonicalize_json(b'{ "z": [3,2,1], "n": null, "a": "\xc3\xa9" }') == (
        canonical_json_bytes(value)
    )
    assert (
        framed_content_digest(family="report", schema_version="3.0.0", value=value)
        == "e00db47777fa869d80ff3f2a484b0d2946fa3f02b1a46c9bc691674cc0ce3ef0"
    )


@pytest.mark.parametrize(
    "payload",
    [
        b'{"duplicate":1,"duplicate":2}',
        b'{"float":1.5}',
        b'{"constant":NaN}',
        b'\xef\xbb\xbf{"bom":true}',
        b'{"integer":9007199254740992}',
        b'"\xed\xa0\x80"',
    ],
)
def test_atl_canonical_json_rejects_ambiguous_or_nonportable_values(payload):
    with pytest.raises(CanonicalJSONError):
        canonicalize_json(payload)


def test_atl_canonical_json_enforces_exact_nesting_and_node_boundaries():
    at_depth_limit: object = None
    for _ in range(64):
        at_depth_limit = [at_depth_limit]
    canonical_json_bytes(at_depth_limit)

    nested = [at_depth_limit]
    with pytest.raises(CanonicalJSONError, match="nesting limit"):
        canonical_json_bytes(nested)

    canonical_json_bytes([None] * 99_999)
    with pytest.raises(CanonicalJSONError, match="node limit"):
        canonical_json_bytes([None] * 100_000)

    hostile_json = b"[" * 1_100 + b"null" + b"]" * 1_100
    with pytest.raises(CanonicalJSONError, match="nesting limit|not valid JSON"):
        canonicalize_json(hostile_json)


def test_atl_canonical_json_enforces_exact_byte_boundary(monkeypatch):
    monkeypatch.setattr(canonical_json_module, "MAX_CANONICAL_BYTES", 16)
    at_limit = b'"' + (b"x" * 14) + b'"'
    over_limit = b'"' + (b"x" * 15) + b'"'

    assert canonicalize_json(at_limit) == at_limit
    assert canonical_json_bytes("x" * 14) == at_limit
    with pytest.raises(CanonicalJSONError, match="byte limit"):
        canonicalize_json(over_limit)
    with pytest.raises(CanonicalJSONError, match="byte limit"):
        canonical_json_bytes("x" * 15)


def test_changed_source_bytes_change_content_and_report_identities():
    first = normalized()
    changed = normalized(RAW.replace(b"[ro.secure]: [1]", b"[ro.secure]: [0]"))

    assert first["raw_artifacts"][0]["sha256"] != changed["raw_artifacts"][0]["sha256"]
    assert first["content_digest"] != changed["content_digest"]
    assert first["report_id"] != changed["report_id"]


def test_byte_only_change_alters_identity_when_interpretation_is_unchanged():
    first = normalized()
    whitespace_only = normalized(RAW + b"\n")

    assert all(
        first[field] == whitespace_only[field] for field in REPORT_EVIDENCE_FIELDS
    )
    assert (
        first["raw_artifacts"][0]["sha256"]
        != whitespace_only["raw_artifacts"][0]["sha256"]
    )
    assert first["content_digest"] != whitespace_only["content_digest"]


def test_raw_source_references_require_observed_bytes():
    with pytest.raises(CollectionError, match="require observed source bytes"):
        normalize_raw_bytes(
            RAW,
            label="raw.txt",
            experiment_id="E10_identity",
            target_type="avd",
            observer_type="adb_shell",
            collection_method="identity_fixture",
            collection_timestamp="2026-01-02T03:04:05Z",
            raw_artifact_ref="observations/raw.txt",
            raw_status="not_collected",
        )

    forged = normalized()
    forged["raw_artifacts"][0]["status"] = "not_collected"
    forged = finalize_report_identity(forged)
    with pytest.raises(SchemaValidationError, match="schema validation failed"):
        validate_report(forged)


def test_multi_source_content_identity_is_permutation_stable_but_order_is_canonical():
    ordered = normalized()
    second = copy.deepcopy(ordered["raw_artifacts"][0])
    second["logical_id"] = "second-raw-report"
    second["relative_path"] = "observations/second.txt"
    ordered["raw_artifacts"].append(second)
    ordered = finalize_report_identity(ordered)
    validate_report(ordered)

    permuted = copy.deepcopy(ordered)
    permuted["raw_artifacts"].reverse()
    permuted = finalize_report_identity(permuted)
    assert permuted["content_digest"] == ordered["content_digest"]
    with pytest.raises(SchemaValidationError, match="canonical logical ID"):
        validate_report(permuted)


def test_moving_identical_bytes_does_not_change_content_or_event_identity():
    first = normalized(relative_path="first/raw.txt")
    moved = normalized(relative_path="moved/raw.txt")

    assert (
        first["raw_artifacts"][0]["relative_path"]
        != moved["raw_artifacts"][0]["relative_path"]
    )
    assert first["content_digest"] == moved["content_digest"]
    assert first["collection_event_id"] == moved["collection_event_id"]
    assert first["report_id"] == moved["report_id"]
    assert str(ROOT) not in str(first)
    assert str(ROOT) not in str(moved)
    validate_report(first)
    validate_report(moved)


def test_timestamp_only_change_separates_event_and_content_identity():
    first = normalized(timestamp="2026-01-02T03:04:05Z")
    later = normalized(timestamp="2026-01-02T03:04:06Z")

    assert first["content_digest"] == later["content_digest"]
    assert first["collection_event_id"] != later["collection_event_id"]
    assert first["report_id"] != later["report_id"]


def test_expected_source_binding_is_checked_before_normalization(monkeypatch):
    def unexpected_parse(_text: str):
        raise AssertionError("parser must not run before source verification")

    monkeypatch.setattr(normalizer_module, "parse_raw_text", unexpected_parse)
    with pytest.raises(CollectionError, match="digest does not match provenance"):
        normalize_raw_bytes(
            RAW,
            label="raw.txt",
            experiment_id="E10_identity",
            target_type="avd",
            observer_type="adb_shell",
            collection_method="identity_fixture",
            collection_timestamp="2026-01-02T03:04:05Z",
            raw_artifact_ref="raw.txt",
            expected_sha256="0" * 64,
        )


def test_expected_source_size_is_tamper_evident():
    with pytest.raises(CollectionError, match="byte size does not match provenance"):
        normalize_raw_bytes(
            RAW,
            label="raw.txt",
            experiment_id="E10_identity",
            target_type="avd",
            observer_type="adb_shell",
            collection_method="identity_fixture",
            collection_timestamp="2026-01-02T03:04:05Z",
            raw_artifact_ref="raw.txt",
            expected_byte_size=len(RAW) + 1,
        )


def test_report_validation_recomputes_content_and_event_binding():
    report = normalized()
    tampered_content = copy.deepcopy(report)
    tampered_content["properties"]["security"]["value"]["ro.secure"] = "0"
    with pytest.raises(SchemaValidationError, match="content digest does not match"):
        validate_report(tampered_content)

    tampered_report_id = copy.deepcopy(report)
    tampered_report_id["report_id"] = "atlrep-" + "0" * 32
    with pytest.raises(SchemaValidationError, match="does not bind"):
        validate_report(tampered_report_id)


def test_report_validation_recomputes_raw_collection_event_identity():
    report = normalized()
    forged_event = copy.deepcopy(report)
    forged_event["collection_event_id"] = "atlevent-" + "f" * 32
    forged_event["report_id"] = calculate_report_id(
        collection_event_id=forged_event["collection_event_id"],
        content_digest=forged_event["content_digest"],
    )
    with pytest.raises(SchemaValidationError, match="event identity does not match"):
        validate_report(forged_event)

    forged_collection = copy.deepcopy(report)
    forged_collection["raw_artifacts"][0]["collection_id"] = "atlcol-forged"
    with pytest.raises(SchemaValidationError, match="event identity does not match"):
        validate_report(forged_collection)


def test_identity_finalization_is_independent_of_dictionary_insertion_order():
    report = normalized()
    reordered = {key: report[key] for key in reversed(report)}

    assert finalize_report_identity(reordered) == report


def test_diff_identity_binds_exact_report_and_content_identities():
    base = normalized(timestamp="2026-01-02T03:04:05Z")
    compare = normalized(timestamp="2026-01-02T03:04:06Z")

    event_diff = make_diff(base, compare)
    same_input_diff = make_diff(base, base)

    assert event_diff["changed_dimensions"] == []
    assert event_diff["base_report"] == {
        "report_id": base["report_id"],
        "content_digest": base["content_digest"],
        "schema_version": "3.0.0",
    }
    assert event_diff["compare_report"] == {
        "report_id": compare["report_id"],
        "content_digest": compare["content_digest"],
        "schema_version": "3.0.0",
    }
    assert event_diff["diff_id"] != same_input_diff["diff_id"]
    validate_diff(event_diff)


def test_diff_validation_rejects_rehashed_provenance_misbinding():
    base = normalized(timestamp="2026-01-02T03:04:05Z")
    compare = normalized(timestamp="2026-01-02T03:04:06Z")
    tampered = make_diff(base, compare)
    tampered["provenance"]["base"]["common_report"] = copy.deepcopy(
        tampered["compare_report"]
    )
    projection = {
        key: value
        for key, value in tampered.items()
        if key not in {"diff_id", "content_digest"}
    }
    digest = framed_content_digest(
        family="diff", schema_version="2.0.0", value=projection
    )
    tampered["content_digest"] = digest
    tampered["diff_id"] = f"atldiff-{digest[:32]}"

    with pytest.raises(SchemaValidationError, match="exact common report identities"):
        validate_diff(tampered)
