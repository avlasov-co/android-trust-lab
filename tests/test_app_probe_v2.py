from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from trustlab.artifacts import ADAPTERS, CaptureStatus, InputKind, parse_artifact
from trustlab.diff import make_diff
from trustlab.dimension_registry import extract_dimension
from trustlab.exceptions import NormalizationError, SchemaValidationError
from trustlab.normalizer import normalize_collection_manifest, normalize_raw_file
from trustlab.privacy import validate_portable_report
from trustlab.validators import (
    load_schema,
    validate_collection_manifest,
    validate_report,
)

ROOT = Path(__file__).resolve().parents[1]
V2_FIXTURE = ROOT / "tests/fixtures/adapters/app_probe_v2.json"
V1_FIXTURE = ROOT / "tests/fixtures/adapters/app_probe.json"
BUNDLE = ROOT / "tests/fixtures/app_probe_v2_bundle/manifest.json"
PROBE_IDS = (
    "build_version",
    "app_identity",
    "install_source",
    "selinux_self_context",
    "file_system_shell",
    "file_system_su",
    "file_system_xbin_su",
    "file_vendor_bin_su",
    "file_sbin_su",
    "proc_self_status",
    "proc_self_mountinfo",
    "emulator_indicators",
)


def fixture_document() -> dict[str, object]:
    value = json.loads(V2_FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def write_artifact(document: dict[str, object], path: Path) -> None:
    path.write_bytes(canonical_bytes(document))


def test_v2_schema_is_packaged_identically_and_fixture_is_valid():
    collector = ROOT / "collector/schema/app_probe_v2_0_0.schema.json"
    packaged = ROOT / "analyzer/trustlab/schemas/app_probe_v2_0_0.schema.json"
    assert collector.read_bytes() == packaged.read_bytes()
    schema = load_schema("app_probe_v2_0_0.schema.json")
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(
        fixture_document()
    )
    assert (BUNDLE.parent / "app_probe.json").read_bytes() == canonical_bytes(
        fixture_document()
    )


def test_v2_adapter_preserves_typed_statuses_and_direct_normalization():
    parsed = parse_artifact(V2_FIXTURE)
    assert parsed.metadata.schema_version == "2.0.0"
    assert tuple(capture.name for capture in parsed.captures) == PROBE_IDS
    assert all(capture.status is CaptureStatus.OBSERVED for capture in parsed.captures)

    report = normalize_raw_file(V2_FIXTURE)
    validate_report(report)
    assert report["target"]["android_version"]["value"] == "17"
    assert report["target"]["sdk"]["value"] == "37"
    assert report["selinux"]["current_context"]["value"] == "u:r:untrusted_app:s0"
    assert report["emulator_state"]["is_emulator"]["value"] is True
    assert report["root_state"]["root_shell_available"]["status"] == "not_collected"
    assert report["magisk_state"]["binary_visibility"]["status"] == "not_collected"
    extension = report["extensions"]["org.androidtrustlab.app-probe"]
    assert extension["status"] == "observed"
    assert [item["probe_id"] for item in extension["value"]["probes"]] == list(
        PROBE_IDS
    )


def test_v1_remains_readable_but_does_not_activate_v2_app_dimension():
    parsed = parse_artifact(V1_FIXTURE)
    assert parsed.metadata.schema_version == "1.0.0"
    report = normalize_raw_file(V1_FIXTURE)
    validate_report(report)
    assert "org.androidtrustlab.app-probe" not in report["extensions"]
    assert extract_dimension(report, "app_visible_state")["status"] == "not_collected"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda document: document["probes"].pop(),
        lambda document: document["probes"].__setitem__(1, document["probes"][0]),
        lambda document: document["probes"][0].update(status="error"),
        lambda document: document["probes"][0].update(
            value=None,
            diagnostic={
                "exception_class": "RuntimeException",
                "message_code": "raw /data/user/0 message",
            },
        ),
        lambda document: document["probes"][2]["value"].update(
            installer_package_name="com.enterprise.private"
        ),
        lambda document: document["probes"][4]["value"].update(
            path="/data/user/0/private"
        ),
    ],
)
def test_v2_schema_rejects_missing_duplicate_incoherent_or_sensitive_channels(
    mutation,
):
    document = fixture_document()
    mutation(document)
    with pytest.raises(NormalizationError, match="does not match|canonical"):
        ADAPTERS[InputKind.APP_PROBE_JSON].parse(
            json.dumps(document), source_ref="fixture"
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda document: document.update(ended_at="2026-07-16T09:59:59Z"),
        lambda document: document.update(completion_status="partial"),
        lambda document: document["probes"][2]["value"].update(source_category="none"),
        lambda document: document["target"].update(target_type="unknown"),
        lambda document: document["probes"][11]["value"].update(
            outcome="not_indicated"
        ),
        lambda document: document["probes"][4]["value"].update(exists=False),
        lambda document: document["probes"][11].update(
            status="unsupported",
            value=None,
            diagnostic={
                "exception_class": "UnsupportedOperationException",
                "message_code": "capability_unavailable",
            },
        ),
    ],
)
def test_v2_semantics_reject_schema_valid_cross_field_contradictions(mutation):
    document = fixture_document()
    mutation(document)
    with pytest.raises(NormalizationError):
        ADAPTERS[InputKind.APP_PROBE_JSON].parse(
            json.dumps(document), source_ref="fixture"
        )


def test_inaccessible_and_error_probes_remain_distinct_in_adapter_and_report(tmp_path):
    document = fixture_document()
    selinux = document["probes"][3]
    selinux.update(
        status="inaccessible",
        value=None,
        diagnostic={
            "exception_class": "SecurityException",
            "message_code": "access_denied",
        },
    )
    proc_status = document["probes"][9]
    proc_status.update(
        status="error",
        value=None,
        diagnostic={
            "exception_class": "RuntimeException",
            "message_code": "malformed_data",
        },
    )
    document["completion_status"] = "partial"
    path = tmp_path / "app_probe.json"
    write_artifact(document, path)

    parsed = parse_artifact(path)
    assert parsed.captures[3].status is CaptureStatus.INACCESSIBLE
    assert parsed.captures[9].status is CaptureStatus.ERROR
    report = normalize_raw_file(path)
    validate_report(report)
    probes = report["extensions"]["org.androidtrustlab.app-probe"]["value"]["probes"]
    assert probes[3]["status"] == "inaccessible"
    assert probes[9]["status"] == "command_error"
    assert probes[3]["value"] is None
    assert probes[9]["value"] is None
    assert report["selinux"]["current_context"]["status"] == "inaccessible"


def test_manifest_bound_v2_normalizes_and_rejects_metadata_mismatch(tmp_path):
    report = normalize_collection_manifest(BUNDLE)
    validate_report(report)
    assert report["raw_artifacts"][0]["media_type"] == "application/json"
    assert report["raw_artifacts"][0]["collector_name"] == "trustlab-app"
    assert (
        report["extensions"]["org.androidtrustlab.collection"]["portable_binding"][
            "raw_artifact_sha256"
        ]
        == hashlib.sha256((BUNDLE.parent / "app_probe.json").read_bytes()).hexdigest()
    )

    document = json.loads(BUNDLE.read_text(encoding="utf-8"))
    document["collector"]["version"] = "0.3.0"
    document["tool_versions"]["trustlab_app"] = "0.3.0"
    manifest = tmp_path / "manifest.json"
    artifact = tmp_path / "app_probe.json"
    artifact.write_bytes((BUNDLE.parent / "app_probe.json").read_bytes())
    manifest.write_text(json.dumps(document), encoding="utf-8")
    validate_collection_manifest(document)
    with pytest.raises(NormalizationError, match="app probe collector"):
        normalize_collection_manifest(manifest)


def test_partial_manifest_must_exactly_bind_every_unavailable_probe(tmp_path):
    document = fixture_document()
    document["probes"][3].update(
        status="inaccessible",
        value=None,
        diagnostic={
            "exception_class": "SecurityException",
            "message_code": "access_denied",
        },
    )
    document["completion_status"] = "partial"
    payload = canonical_bytes(document)
    (tmp_path / "app_probe.json").write_bytes(payload)

    manifest = json.loads(BUNDLE.read_text(encoding="utf-8"))
    manifest["completion_status"] = "partial"
    manifest["artifacts"][0]["byte_size"] = len(payload)
    manifest["artifacts"][0]["sha256"] = hashlib.sha256(payload).hexdigest()
    manifest["artifacts"].append(
        {
            "logical_name": "probe_outcome.selinux_self_context",
            "relative_path": None,
            "media_type": "application/json",
            "byte_size": None,
            "sha256": None,
            "probe_id": "app.selinux_self_context",
            "status": "inaccessible",
            "exit_code": None,
            "timed_out": False,
            "sensitivity": "internal",
            "redaction_state": "withheld",
            "detail": None,
        }
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    report = normalize_collection_manifest(manifest_path)
    validate_report(report)
    assert (
        report["extensions"]["org.androidtrustlab.app-probe"]["value"]["probes"][3][
            "status"
        ]
        == "inaccessible"
    )

    manifest["artifacts"][1]["logical_name"] = "probe_outcome.install_source"
    manifest["artifacts"][1]["probe_id"] = "app.install_source"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    validate_collection_manifest(manifest)
    with pytest.raises(NormalizationError, match="outcomes do not match"):
        normalize_collection_manifest(manifest_path)


def test_app_visible_state_compares_only_validated_v2_payloads(tmp_path):
    before_document = fixture_document()
    after_document = copy.deepcopy(before_document)
    after_document["probes"][1]["value"]["app_uid"] = 10124
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    write_artifact(before_document, before_path)
    write_artifact(after_document, after_path)
    before = normalize_raw_file(before_path)
    after = normalize_raw_file(after_path)
    assert extract_dimension(before, "app_visible_state")["status"] == "observed"

    diff = make_diff(before, after, allow_mixed=True)
    assert "app_visible_state" in {
        item["dimension"] for item in diff["changed_dimensions"]
    }
    assert (
        next(
            item
            for item in diff["changed_dimensions"]
            if item["dimension"] == "app_visible_state"
        )["materiality"]
        == "informational"
    )


def test_portable_app_extension_rejects_new_identifier_channel():
    report = normalize_raw_file(V2_FIXTURE)
    report["extensions"]["org.androidtrustlab.app-probe"]["value"]["probes"][2][
        "value"
    ]["installer_package_name"] = "com.enterprise.private"
    with pytest.raises(SchemaValidationError, match="app-probe value"):
        validate_portable_report(report)


@pytest.mark.parametrize(
    ("probe_index", "field", "value"),
    [
        (0, "release", 17),
        (0, "build_type", {}),
        (3, "base_context", f"u:r:{'a' * 250}:s0"),
        (10, "malformed_record_count", False),
        (10, "filesystem_type", 7),
        (11, "outcome", {}),
    ],
)
def test_portable_app_extension_rejects_wrong_types_and_bounds(
    probe_index, field, value
):
    report = normalize_raw_file(V2_FIXTURE)
    probe = report["extensions"]["org.androidtrustlab.app-probe"]["value"]["probes"][
        probe_index
    ]
    if field == "filesystem_type":
        probe["value"]["selected_mounts"][0][field] = value
    else:
        probe["value"][field] = value
    with pytest.raises(SchemaValidationError, match="app-probe"):
        validate_report(report)


def test_portable_app_extension_rejects_unhashable_status_cleanly():
    report = normalize_raw_file(V2_FIXTURE)
    report["extensions"]["org.androidtrustlab.app-probe"]["value"]["probes"][0][
        "status"
    ] = {}
    with pytest.raises(SchemaValidationError, match="app-probe"):
        validate_report(report)
