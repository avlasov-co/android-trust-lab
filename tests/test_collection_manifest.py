from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from trustlab import cli
from trustlab import normalizer as normalizer_module
from trustlab.collection_manifest import (
    MAX_COLLECTION_ARTIFACT_BYTES,
    CollectionManifest,
    read_collection_manifest,
    verify_collection_artifacts,
    write_collection_manifest,
)
from trustlab.exceptions import (
    CollectionError,
    NormalizationError,
    SchemaValidationError,
)
from trustlab.identity import finalize_report_identity
from trustlab.normalizer import (
    normalize_collection_manifest,
    normalize_collection_payload,
    normalize_raw_file,
)
from trustlab.report_writer import load_json
from trustlab.validators import (
    load_schema,
    validate_collection_manifest,
    validate_report,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = (
    ROOT
    / "datasets"
    / "samples"
    / "magisk_collector"
    / "collector_manifest_sample.json"
)


def sample_document() -> dict[str, object]:
    return load_json(SAMPLE)


def test_manually_authored_manifest_validates_and_round_trips_typed_model(tmp_path):
    document = sample_document()
    validate_collection_manifest(document)

    manifest = CollectionManifest.from_dict(document)
    assert manifest.schema_version == "1.0.0"
    assert manifest.observer.observer_type == "root_collector"
    assert manifest.artifacts[0].logical_name == "raw_report"
    assert manifest.to_dict() == document
    with pytest.raises(TypeError):
        manifest.tool_versions["mutated"] = "1.0.0"

    output = tmp_path / "manifest.json"
    write_collection_manifest(manifest, output)
    assert read_collection_manifest(output) == manifest


def test_collection_manifest_schema_is_strict_and_complete():
    schema = load_schema("collection_manifest_v1_0_0.schema.json")
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    for name in (
        "collector",
        "observer",
        "target",
        "environment",
        "redactionPolicy",
        "artifactEntry",
    ):
        definition = schema["$defs"][name]
        assert definition["additionalProperties"] is False
        assert set(definition["required"]) == set(definition["properties"])


def test_manifest_artifact_binding_and_normalization_match_legacy_raw_flow():
    manifest = read_collection_manifest(SAMPLE)
    verified = verify_collection_artifacts(manifest, SAMPLE)
    assert verified["raw_report"].path == (SAMPLE.parent / "raw_sample.txt").resolve()
    assert verified["raw_report"].payload is None

    from_manifest = normalize_collection_manifest(SAMPLE)
    from_raw = normalize_raw_file(
        SAMPLE.parent / "raw_sample.txt",
        experiment_id="E05_magisk_collector",
        target_type="avd",
        observer_type="root_collector",
        collection_method="magisk_module_manual",
        collection_timestamp="2026-04-25T15:50:00Z",
        raw_artifact_ref="raw_sample.txt",
    )
    assert from_manifest["root_state"] == from_raw["root_state"]
    assert {
        key: value
        for key, value in from_manifest["verified_boot"].items()
        if key != "confidence"
    } == {
        key: value
        for key, value in from_raw["verified_boot"].items()
        if key != "confidence"
    }
    assert from_manifest["verified_boot"]["confidence"]["source_quality"] == (
        "legacy_inferred"
    )
    assert from_raw["verified_boot"]["confidence"]["source_quality"] == (
        "legacy_inferred"
    )
    assert from_manifest["report_id"] != from_raw["report_id"]
    assert [
        result["status"] for result in from_manifest["provenance"]["command_results"]
    ] == ["observed", "not_collected"]
    assert (
        "collection manifest completion status: partial"
        in from_manifest["limitations"]["collection_errors"]
    )
    collection = from_manifest["extensions"]["org.androidtrustlab.collection"]
    canonical = json.dumps(
        sample_document(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    assert (
        collection["canonical_manifest_sha256"] == hashlib.sha256(canonical).hexdigest()
    )
    assert collection["portable_binding"] == {
        "artifact_results": from_manifest["provenance"]["command_results"],
        "collection_id": from_manifest["raw_artifacts"][0]["collection_id"],
        "collection_errors": [
            "collection manifest completion status: partial",
            "probe 002: not_collected",
        ],
        "completion_status": "partial",
        "raw_artifact_sha256": from_manifest["raw_artifacts"][0]["sha256"],
        "raw_artifact_status": "observed",
        "redaction_state": "redacted",
    }
    validate_report(from_manifest)


def test_manifest_path_change_preserves_content_but_changes_event_binding():
    payload = (SAMPLE.parent / "raw_sample.txt").read_bytes()
    original = CollectionManifest.from_dict(sample_document())
    moved_document = sample_document()
    moved_document["artifacts"][0]["relative_path"] = "moved/raw_sample.txt"
    moved = CollectionManifest.from_dict(moved_document)

    first = normalize_collection_payload(payload, original, label="raw_sample.txt")
    second = normalize_collection_payload(payload, moved, label="raw_sample.txt")

    assert first["content_digest"] == second["content_digest"]
    assert first["collection_event_id"] != second["collection_event_id"]
    assert first["report_id"] != second["report_id"]


@pytest.mark.parametrize("invalid_digest", [None, 0, [], "not-a-digest"])
def test_report_rejects_invalid_collection_extension_digest_type(invalid_digest):
    report = normalize_collection_manifest(SAMPLE)
    report["extensions"]["org.androidtrustlab.collection"][
        "canonical_manifest_sha256"
    ] = invalid_digest

    with pytest.raises(SchemaValidationError, match="portable collection binding"):
        validate_report(report)


def test_report_binds_all_command_results_and_manifest_limitations():
    report = normalize_collection_manifest(SAMPLE)

    forged_result = copy.deepcopy(report)
    forged_result["provenance"]["command_results"][1].update(
        {"status": "observed", "exit_code": 0, "detail": "success"}
    )
    with pytest.raises(SchemaValidationError, match="command results do not match"):
        validate_report(forged_result)

    reordered = copy.deepcopy(report)
    reordered["provenance"]["command_results"].reverse()
    with pytest.raises(SchemaValidationError, match="command results do not match"):
        validate_report(reordered)

    omitted_limitation = copy.deepcopy(report)
    omitted_limitation["limitations"]["collection_errors"].remove(
        "collection manifest completion status: partial"
    )
    omitted_limitation = finalize_report_identity(omitted_limitation)
    with pytest.raises(SchemaValidationError, match="limitations do not retain"):
        validate_report(omitted_limitation)


def test_report_rejects_unbound_additional_manifest_raw_reference():
    report = normalize_collection_manifest(SAMPLE)
    forged = copy.deepcopy(report)
    extra = copy.deepcopy(forged["raw_artifacts"][0])
    extra["logical_id"] = "zz-unbound-source"
    extra["relative_path"] = "zz-unbound-source.txt"
    forged["raw_artifacts"].append(extra)
    forged = finalize_report_identity(forged)

    with pytest.raises(SchemaValidationError, match="unique observed raw_report"):
        validate_report(forged)


def test_report_rejects_substitution_with_another_bound_manifest_artifact():
    document = sample_document()
    document["artifacts"].append(
        {
            "logical_name": "other_observed_artifact",
            "relative_path": "other_artifact.json",
            "media_type": "application/json",
            "byte_size": 1,
            "sha256": "0" * 64,
            "probe_id": "magisk.other_observed_artifact",
            "status": "observed",
            "exit_code": 0,
            "timed_out": False,
            "sensitivity": "internal",
            "redaction_state": "redacted",
            "detail": None,
        }
    )
    manifest = CollectionManifest.from_dict(document)
    payload = (SAMPLE.parent / "raw_sample.txt").read_bytes()
    forged = normalize_collection_payload(payload, manifest, label="raw_sample.txt")
    other = document["artifacts"][-1]
    raw_reference = forged["raw_artifacts"][0]
    raw_reference.update(
        {
            "logical_id": other["logical_name"],
            "relative_path": other["relative_path"],
            "sha256": other["sha256"],
            "byte_size": other["byte_size"],
            "media_type": other["media_type"],
            "status": other["status"],
            "redaction_state": other["redaction_state"],
        }
    )
    forged = finalize_report_identity(forged)

    with pytest.raises(SchemaValidationError, match="portable collection binding"):
        validate_report(forged)


@pytest.mark.parametrize(
    ("fixture", "message"),
    [
        (
            "collection_manifest_invalid_absolute_path.json",
            "collection manifest schema validation failed",
        ),
        (
            "collection_manifest_invalid_complete_with_missing_probe.json",
            "complete collections cannot contain failed or omitted probes",
        ),
    ],
)
def test_negative_manifest_fixtures_are_rejected(fixture, message):
    document = load_json(ROOT / "tests/fixtures" / fixture)
    with pytest.raises(SchemaValidationError, match=message):
        validate_collection_manifest(document)


def test_partial_failed_timed_out_and_missing_artifacts_remain_distinct():
    document = sample_document()
    statuses = {artifact["status"] for artifact in document["artifacts"]}
    assert statuses == {"observed", "not_collected"}

    failed = copy.deepcopy(document)
    failed["completion_status"] = "failed"
    failed["artifacts"] = [
        {
            "logical_name": "raw_report",
            "relative_path": None,
            "media_type": "text/plain",
            "byte_size": None,
            "sha256": None,
            "probe_id": "magisk.readonly_snapshot",
            "status": "command_error",
            "exit_code": None,
            "timed_out": True,
            "sensitivity": "sensitive",
            "redaction_state": "withheld",
            "detail": None,
        }
    ]
    validate_collection_manifest(failed)
    assert failed["artifacts"][0]["status"] == "command_error"
    assert failed["artifacts"][0]["timed_out"] is True

    falsely_empty = copy.deepcopy(failed)
    artifact = falsely_empty["artifacts"][0]
    artifact.update(
        {
            "relative_path": "empty_raw.txt",
            "byte_size": 0,
            "sha256": hashlib.sha256(b"").hexdigest(),
            "status": "observed",
            "exit_code": 0,
            "timed_out": False,
            "redaction_state": "redacted",
        }
    )
    with pytest.raises(SchemaValidationError, match="failed collections"):
        validate_collection_manifest(falsely_empty)


def test_manifest_semantics_reject_duplicates_privilege_mismatch_and_secret_text():
    duplicate = sample_document()
    duplicate["artifacts"].append(copy.deepcopy(duplicate["artifacts"][0]))
    with pytest.raises(SchemaValidationError, match="logical names must be unique"):
        validate_collection_manifest(duplicate)

    mismatch = sample_document()
    mismatch["observer"]["privilege_level"] = "shell"
    with pytest.raises(SchemaValidationError, match="privilege does not match"):
        validate_collection_manifest(mismatch)

    collector_mismatch = sample_document()
    collector_mismatch["collector"]["name"] = "trustlab-app"
    with pytest.raises(SchemaValidationError, match="does not match observer"):
        validate_collection_manifest(collector_mismatch)

    transport_mismatch = sample_document()
    transport_mismatch["environment"]["transport"] = "adb"
    with pytest.raises(SchemaValidationError, match="environment transport"):
        validate_collection_manifest(transport_mismatch)

    platform_mismatch = sample_document()
    platform_mismatch["environment"]["platform"] = "windows"
    with pytest.raises(SchemaValidationError, match="environment platform"):
        validate_collection_manifest(platform_mismatch)

    leaked = sample_document()
    leaked["warnings"] = ["token=private-value"]
    with pytest.raises(SchemaValidationError, match="identifiers, or secrets"):
        validate_collection_manifest(leaked)

    leaked_tool_value = sample_document()
    leaked_tool_value["tool_versions"]["unsafe"] = "token=private-value"
    with pytest.raises(SchemaValidationError, match="schema validation failed"):
        validate_collection_manifest(leaked_tool_value)

    host_path = sample_document()
    host_path["warnings"] = ["source remained under /Users/private/raw.txt"]
    with pytest.raises(SchemaValidationError, match="absolute paths"):
        validate_collection_manifest(host_path)

    redacted_diagnostics = sample_document()
    redacted_diagnostics["warnings"] = [
        "Device serial was redacted; access token is withheld; Bearer redacted."
    ]
    with pytest.raises(SchemaValidationError, match="structured statuses"):
        validate_collection_manifest(redacted_diagnostics)


@pytest.mark.parametrize("location", ["warning", "detail"])
def test_manifest_rejects_process_identity_and_command_line_diagnostics(location):
    document = sample_document()
    diagnostic = "root 88 com.private.bank"
    if location == "warning":
        document["warnings"] = [diagnostic]
    else:
        document["artifacts"][0]["detail"] = diagnostic

    with pytest.raises(SchemaValidationError, match="structured statuses"):
        validate_collection_manifest(document)


@pytest.mark.parametrize("location", ["warning", "detail"])
def test_normalization_revalidates_directly_constructed_manifest_diagnostics(
    location,
):
    manifest = CollectionManifest.from_dict(sample_document())
    diagnostic = "root 88 com.private.bank"
    if location == "warning":
        unsafe = replace(manifest, warnings=(diagnostic,))
    else:
        unsafe_artifact = replace(manifest.artifacts[0], detail=diagnostic)
        unsafe = replace(
            manifest,
            artifacts=(unsafe_artifact, *manifest.artifacts[1:]),
        )
    payload = (SAMPLE.parent / "raw_sample.txt").read_bytes()

    with pytest.raises(SchemaValidationError, match="structured statuses"):
        normalize_collection_payload(payload, unsafe, label="raw_sample.txt")


def test_normalization_rejects_directly_constructed_free_text_tool_version():
    manifest = CollectionManifest.from_dict(sample_document())
    unsafe = replace(
        manifest,
        tool_versions={"ps": "sh -c PRIVATE_PAYLOAD"},
    )
    payload = (SAMPLE.parent / "raw_sample.txt").read_bytes()

    with pytest.raises(SchemaValidationError, match="schema validation failed"):
        normalize_collection_payload(payload, unsafe, label="raw_sample.txt")


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("collector", "name"), "alice"),
        (("collector", "version"), "1.2.3-alice"),
        (("observer", "collection_method"), "alice"),
        (("observer", "collection_method"), "alice_probe"),
        (("environment", "execution_context"), "alice"),
        (("tool_versions", "android_shell"), "alice"),
        (("tool_versions", "trustlab_magisk"), "1.2.3-alice"),
        (("artifacts", 0, "logical_name"), "alice"),
        (("artifacts", 0, "logical_name"), "alice_private"),
        (("artifacts", 0, "probe_id"), "alice"),
        (("artifacts", 0, "probe_id"), "alice.private"),
        (
            ("artifacts", 0, "relative_path"),
            "captures/R58M1234ABC-alice-10.0.0.7.txt",
        ),
        (("artifacts", 0, "relative_path"), "captures/alice_private.txt"),
        (("artifacts", 0, "relative_path"), "capture-ZX1G22BHQP.txt"),
        (("artifacts", 0, "relative_path"), "capture-0123456789ABCDEF.txt"),
        (
            ("artifacts", 0, "relative_path"),
            "capture-AKIAIOSFODNN7EXAMPLE.txt",
        ),
    ],
)
def test_manifest_rejects_identifiers_in_structured_fields(path, value):
    document = sample_document()
    current = document
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = value

    with pytest.raises(SchemaValidationError):
        validate_collection_manifest(document)


def test_manifest_timestamp_order_handles_every_rfc3339_z_spelling():
    for suffix in ("Z", "z"):
        document = sample_document()
        document["started_at"] = f"2026-04-25T15:50:01{suffix}"
        document["ended_at"] = f"2026-04-25T15:50:00{suffix}"
        with pytest.raises(SchemaValidationError, match="precedes its start"):
            validate_collection_manifest(document)

    leap_second = sample_document()
    leap_second["started_at"] = "2016-12-31T23:59:60Z"
    leap_second["ended_at"] = "2016-12-31T23:59:59Z"
    with pytest.raises(SchemaValidationError, match="precedes its start"):
        validate_collection_manifest(leap_second)

    after_leap = sample_document()
    after_leap["started_at"] = "2017-01-01T00:00:00Z"
    after_leap["ended_at"] = "2016-12-31T23:59:60Z"
    with pytest.raises(SchemaValidationError, match="precedes its start"):
        validate_collection_manifest(after_leap)

    year_zero = sample_document()
    year_zero["started_at"] = "0000-01-01T00:00:01Z"
    year_zero["ended_at"] = "0000-01-01T00:00:00Z"
    with pytest.raises(SchemaValidationError, match="precedes its start"):
        validate_collection_manifest(year_zero)


@pytest.mark.parametrize(
    "warning",
    [
        "source:/Users/alice/raw.txt",
        "source[/home/alice/raw.txt]",
        r"source at \\server\share\raw.txt",
        r"source at \Windows\System32\raw.txt",
        "source at //server/share/raw.txt",
        "source at ~alice/raw.txt",
        "device serial R58M1234ABC failed",
        "adb -s R58M1234ABC shell failed",
        "ADB target R58M1234ABC unavailable",
        "Authorization: Bearer ghp_privatevalue",
        "-----BEGIN " + "PRIVATE KEY-----",
        "ADB target emulator-5554 unavailable",
        "ADB target 0123456789ABCDEF unavailable",
        "ADB target 192.0.2.10:5555 unavailable",
    ],
)
def test_manifest_portability_rejects_paths_identifiers_and_credentials(warning):
    document = sample_document()
    document["warnings"] = [warning]
    with pytest.raises(SchemaValidationError, match="absolute paths|identifiers"):
        validate_collection_manifest(document)


def test_artifact_verification_rejects_changed_bytes_and_symlink_escape(tmp_path):
    raw = tmp_path / "raw_sample.txt"
    shutil.copyfile(SAMPLE.parent / "raw_sample.txt", raw)
    manifest_path = tmp_path / "manifest.json"
    write_collection_manifest(sample_document(), manifest_path)
    manifest = read_collection_manifest(manifest_path)
    verify_collection_artifacts(manifest, manifest_path)

    raw.write_bytes(raw.read_bytes() + b"tampered")
    with pytest.raises(CollectionError, match="size mismatch"):
        verify_collection_artifacts(manifest, manifest_path)

    raw.write_bytes(b"x" * 1953)
    with pytest.raises(CollectionError, match="digest mismatch"):
        verify_collection_artifacts(manifest, manifest_path)

    outside = tmp_path.parent / "outside.raw"
    outside.write_text("outside", encoding="utf-8")
    raw.unlink()
    raw.symlink_to(outside)
    with pytest.raises(CollectionError, match="escapes the manifest directory"):
        verify_collection_artifacts(manifest, manifest_path)


def test_artifact_verification_rejects_symlinks_and_non_regular_files(tmp_path):
    actual = tmp_path / "actual.txt"
    shutil.copyfile(SAMPLE.parent / "raw_sample.txt", actual)
    raw = tmp_path / "raw_sample.txt"
    raw.symlink_to(actual.name)
    manifest_path = tmp_path / "manifest.json"
    write_collection_manifest(sample_document(), manifest_path)
    manifest = read_collection_manifest(manifest_path)
    with pytest.raises(CollectionError, match="must not contain symlinks"):
        verify_collection_artifacts(manifest, manifest_path)

    raw.unlink()
    raw.mkdir()
    with pytest.raises(CollectionError, match="regular files"):
        verify_collection_artifacts(manifest, manifest_path)

    if hasattr(os, "mkfifo"):
        raw.rmdir()
        os.mkfifo(raw)
        with pytest.raises(CollectionError, match="regular files"):
            verify_collection_artifacts(manifest, manifest_path)


def test_artifact_schema_enforces_bounded_verification_size():
    document = sample_document()
    document["artifacts"][0]["byte_size"] = MAX_COLLECTION_ARTIFACT_BYTES + 1
    with pytest.raises(SchemaValidationError, match="collection manifest schema"):
        validate_collection_manifest(document)


def test_manifest_normalizer_parses_exact_verified_snapshot(tmp_path, monkeypatch):
    raw = tmp_path / "raw_sample.txt"
    shutil.copyfile(SAMPLE.parent / "raw_sample.txt", raw)
    manifest_path = tmp_path / "manifest.json"
    write_collection_manifest(sample_document(), manifest_path)
    original_verify = normalizer_module.verify_collection_artifacts

    def verify_then_mutate(*args, **kwargs):
        verified = original_verify(*args, **kwargs)
        raw.write_bytes(
            raw.read_bytes().replace(
                b"observer_effective_uid_is_root=observed\n",
                b"observer_effective_uid_is_root=observed_absent\n",
                1,
            )
        )
        return verified

    monkeypatch.setattr(
        normalizer_module, "verify_collection_artifacts", verify_then_mutate
    )
    report = normalize_collection_manifest(manifest_path)

    assert report["root_state"]["observer_effective_uid_is_root"]["value"] is True
    assert b"observer_effective_uid_is_root=observed_absent" in raw.read_bytes()


@pytest.mark.parametrize(
    (
        "collector_name",
        "observer_type",
        "privilege_level",
        "transport",
        "platform",
        "collection_method",
    ),
    [
        ("trustlab-host", "host", "host", "local", "linux", "host_snapshot"),
        ("trustlab-adb", "adb_shell", "shell", "adb", "android", "adb_snapshot"),
        (
            "trustlab-app",
            "unprivileged_app",
            "app_sandbox",
            "app_api",
            "android",
            "app_snapshot",
        ),
        (
            "trustlab-magisk",
            "root_collector",
            "root",
            "on_device",
            "android",
            "magisk_module_manual",
        ),
    ],
)
def test_all_observers_share_manifest_validation_round_trip_and_normalization(
    tmp_path,
    collector_name,
    observer_type,
    privilege_level,
    transport,
    platform,
    collection_method,
):
    raw = tmp_path / "raw_sample.txt"
    shutil.copyfile(SAMPLE.parent / "raw_sample.txt", raw)
    document = sample_document()
    document["collector"]["name"] = collector_name
    document["observer"] = {
        "observer_type": observer_type,
        "privilege_level": privilege_level,
        "collection_method": collection_method,
    }
    document["environment"] = {
        "platform": platform,
        "transport": transport,
        "execution_context": f"{collector_name.removeprefix('trustlab-')}_collector",
    }
    manifest_path = tmp_path / "manifest.json"
    write_collection_manifest(document, manifest_path)

    assert read_collection_manifest(manifest_path).to_dict() == document
    report = normalize_collection_manifest(manifest_path)
    assert report["observer"]["observer_type"] == observer_type
    assert report["provenance"]["command_results"][1]["status"] == "not_collected"
    validate_report(report)


def test_collection_manifest_cli_validation_and_normalization(tmp_path, capsys):
    assert cli.main(["validate-collection-manifest", str(SAMPLE)]) == 0
    assert capsys.readouterr().out == "valid collection manifest\n"

    output = tmp_path / "report.json"
    assert (
        cli.main(
            [
                "normalize",
                "--manifest",
                str(SAMPLE),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["observer"]["observer_type"] == "root_collector"
    assert report["raw_artifacts"] == [
        {
            "logical_id": "raw-artifact-001",
            "relative_path": "artifacts/raw-artifact-001.txt",
            "sha256": "b974a58ea553607d0fe852005607934d877a864d7727732f89c4de75e3f33ade",
            "byte_size": 1953,
            "media_type": "text/plain",
            "collector_name": "trustlab-magisk",
            "collector_version": "0.3.0-dev0",
            "collection_id": "collection-redacted",
            "status": "observed",
            "redaction_state": "redacted",
        }
    ]
    validate_report(report)


def test_manifest_normalization_refuses_to_replace_bound_raw_evidence(tmp_path):
    raw = tmp_path / "raw_sample.txt"
    shutil.copyfile(SAMPLE.parent / "raw_sample.txt", raw)
    manifest_path = tmp_path / "manifest.json"
    write_collection_manifest(sample_document(), manifest_path)
    before = raw.read_bytes()

    assert (
        cli.main(
            [
                "normalize",
                "--manifest",
                str(manifest_path),
                "--output",
                str(raw),
            ]
        )
        == cli.EXIT_OUTPUT_WRITE_FAILURE
    )
    assert raw.read_bytes() == before


def test_manifest_normalization_requires_one_observed_plain_text_raw_report(tmp_path):
    raw = tmp_path / "raw_sample.txt"
    shutil.copyfile(SAMPLE.parent / "raw_sample.txt", raw)
    document = sample_document()
    document["artifacts"][0]["media_type"] = "application/json"
    manifest_path = tmp_path / "manifest.json"
    write_collection_manifest(document, manifest_path)

    with pytest.raises(NormalizationError, match="one observed raw_report"):
        normalize_collection_manifest(manifest_path)
