from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from trustlab import cli
from trustlab.artifacts import (
    ADAPTERS,
    ArtifactMetadata,
    ArtifactParseResult,
    CaptureStatus,
    InputKind,
    adapter_for_text,
    parse_artifact,
    parse_collection_payload_text,
)
from trustlab.exceptions import (
    InvalidJSONError,
    NormalizationError,
    UnsupportedSchemaVersionError,
)
from trustlab.normalizer import normalize_collection_manifest, normalize_raw_file
from trustlab.validators import load_schema, validate_report

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "adapters"
COLLECTION_MANIFEST = (
    ROOT / "datasets/samples/magisk_collector/collector_manifest_sample.json"
)


@pytest.mark.parametrize("input_kind", list(InputKind))
def test_every_adapter_satisfies_shared_contract(input_kind):
    adapter = ADAPTERS[input_kind]
    assert adapter.input_kind is input_kind
    assert adapter.supported_schema_versions
    assert adapter.supported_collector_versions
    assert callable(adapter.parse)


@pytest.mark.parametrize(
    ("name", "kind", "observer"),
    [
        ("adb_manifest.json", InputKind.ADB_COLLECTION_MANIFEST, "adb_shell"),
        (
            "magisk_manifest.json",
            InputKind.MAGISK_COLLECTION_MANIFEST,
            "root_collector",
        ),
        ("host_manifest.json", InputKind.HOST_COLLECTION_MANIFEST, "host"),
        ("app_probe.json", InputKind.APP_PROBE_JSON, "unprivileged_app"),
    ],
)
def test_adapter_specific_fixtures(name, kind, observer):
    result = parse_artifact(FIXTURES / name)
    assert isinstance(result, ArtifactParseResult)
    assert result.input_kind is kind
    assert result.metadata.observer_type == observer
    assert result.metadata.collector_version == "0.3.0"
    assert all(capture.source_ref for capture in result.captures)


@pytest.mark.parametrize(
    "name",
    [
        "adb_manifest.json",
        "magisk_manifest.json",
        "host_manifest.json",
        "app_probe.json",
    ],
)
def test_adapter_parsing_is_deterministic(name):
    path = FIXTURES / name
    assert parse_artifact(path) == parse_artifact(path)


def test_legacy_fixture_has_deliberate_compatibility_warning():
    result = parse_artifact(ROOT / "tests/fixtures/sample_raw_report.txt")
    assert result.input_kind is InputKind.LEGACY_SECTIONED_TEXT
    assert "inferred command status" in result.warnings[0]
    assert result.fragments.properties["ro.secure"] == "1"
    assert result.captures[0].status is CaptureStatus.OBSERVED


def test_adapter_selection_uses_metadata_not_filename(tmp_path):
    misleading = tmp_path / "looks-like-legacy.txt"
    misleading.write_bytes((FIXTURES / "adb_manifest.json").read_bytes())
    result = parse_artifact(misleading)
    assert result.input_kind is InputKind.ADB_COLLECTION_MANIFEST


def test_json_without_artifact_kind_is_not_guessed_as_legacy():
    with pytest.raises(NormalizationError, match="artifact_kind"):
        adapter_for_text('{"schema_version":"1.0.0"}')


def test_explicit_adapter_must_match_declared_kind():
    text = (FIXTURES / "adb_manifest.json").read_text(encoding="utf-8")
    adapter = adapter_for_text(text, explicit_kind="magisk_collection_manifest")
    with pytest.raises(NormalizationError, match="does not match"):
        adapter.parse(text, source_ref="fixture")


def test_adapter_rejects_unsupported_versions():
    document = json.loads((FIXTURES / "adb_manifest.json").read_text(encoding="utf-8"))
    document["schema_version"] = "9.0.0"
    adapter = ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST]
    with pytest.raises(UnsupportedSchemaVersionError):
        adapter.parse(json.dumps(document), source_ref="fixture")


def test_adapter_rejects_unsupported_collector_version():
    document = json.loads((FIXTURES / "adb_manifest.json").read_text(encoding="utf-8"))
    document["collector_version"] = "99.0.0"

    with pytest.raises(UnsupportedSchemaVersionError, match="collector version"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        "null",
        '"scalar"',
        "42",
        "\ufeff{}",
        '{"artifact_kind":"adb_collection_manifest","artifact_kind":"host_collection_manifest"}',
        '{"artifact_kind":"adb_collection_manifest",',
    ],
)
def test_malformed_or_ambiguous_json_fails_closed(text):
    with pytest.raises((InvalidJSONError, NormalizationError)):
        adapter_for_text(text)


def test_capture_source_reference_must_be_portable():
    document = json.loads((FIXTURES / "adb_manifest.json").read_text(encoding="utf-8"))
    document["captures"][0]["source_ref"] = "/Users/private/capture.txt"

    with pytest.raises(NormalizationError, match="portable and relative"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )


def test_capture_failures_are_preserved_and_not_parsed_as_facts():
    document = json.loads((FIXTURES / "adb_manifest.json").read_text(encoding="utf-8"))
    document["captures"][0].update(
        status="command_error", exit_code=1, stdout="[ro.secure]: [0]"
    )
    result = ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
        json.dumps(document), source_ref="fixture"
    )
    assert result.fragments.properties == {}
    assert result.errors == ("capture getprop_selected ended with command_error",)


@pytest.mark.parametrize(
    "updates",
    [
        {"status": "observed", "exit_code": 1},
        {"status": "observed", "timed_out": True},
        {"status": "empty", "stdout": "[ro.secure]: [0]"},
        {"status": "timeout", "timed_out": False, "exit_code": None},
        {"status": "not_collected", "exit_code": 0},
        {"status": "unsupported", "exit_code": 0},
        {"status": "inaccessible", "exit_code": 0},
        {"status": "command_error", "exit_code": 0},
    ],
)
def test_capture_outcome_tuples_must_be_coherent(updates):
    document = json.loads((FIXTURES / "adb_manifest.json").read_text(encoding="utf-8"))
    document["captures"][0].update(updates)

    with pytest.raises(NormalizationError):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )


def test_duplicate_capture_names_and_semantic_aliases_fail_closed():
    document = json.loads((FIXTURES / "adb_manifest.json").read_text(encoding="utf-8"))
    duplicate = dict(document["captures"][0])
    document["captures"].append(duplicate)
    with pytest.raises(NormalizationError, match="duplicate capture"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )

    duplicate["name"] = "properties"
    with pytest.raises(NormalizationError, match="duplicates an existing"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )


def test_observer_specific_capture_vocabulary_rejects_android_host_evidence():
    document = json.loads((FIXTURES / "host_manifest.json").read_text(encoding="utf-8"))
    document["captures"][0].update(name="identity", stdout="uid=0(root) gid=0(root)")

    with pytest.raises(NormalizationError, match="not valid for host"):
        ADAPTERS[InputKind.HOST_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )


@pytest.mark.parametrize(
    ("capture_name", "stdout"),
    [
        ("getprop_selected", "garbage"),
        ("identity", "not an id record"),
        ("mounts", "not a mount record"),
        ("getenforce", "maybe enforcing"),
    ],
)
def test_malformed_successful_capture_does_not_become_observed_absence(
    capture_name, stdout
):
    document = json.loads((FIXTURES / "adb_manifest.json").read_text(encoding="utf-8"))
    capture = dict(document["captures"][0])
    capture.update(name=capture_name, stdout=stdout)
    document["captures"] = [capture]

    with pytest.raises(NormalizationError, match="malformed observed output"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )


@pytest.mark.parametrize(
    ("fixture_name", "kind", "capture_name", "stdout"),
    [
        (
            "adb_manifest.json",
            InputKind.ADB_COLLECTION_MANIFEST,
            "su_paths",
            "permission denied",
        ),
        (
            "magisk_manifest.json",
            InputKind.MAGISK_COLLECTION_MANIFEST,
            "magisk",
            "error: service unavailable",
        ),
        (
            "adb_manifest.json",
            InputKind.ADB_COLLECTION_MANIFEST,
            "processes",
            "command not found",
        ),
        (
            "adb_manifest.json",
            InputKind.ADB_COLLECTION_MANIFEST,
            "getenforce",
            "permission denied",
        ),
        (
            "magisk_manifest.json",
            InputKind.MAGISK_COLLECTION_MANIFEST,
            "magisk",
            "magisk: inaccessible",
        ),
        (
            "adb_manifest.json",
            InputKind.ADB_COLLECTION_MANIFEST,
            "processes",
            "system_server inaccessible",
        ),
    ],
)
def test_successful_capture_rejects_shell_diagnostics(
    fixture_name, kind, capture_name, stdout
):
    document = json.loads((FIXTURES / fixture_name).read_text(encoding="utf-8"))
    capture = dict(document["captures"][0])
    capture.update(name=capture_name, stdout=stdout)
    document["captures"] = [capture]

    with pytest.raises(NormalizationError, match="malformed observed output"):
        ADAPTERS[kind].parse(json.dumps(document), source_ref="fixture")


@pytest.mark.parametrize(
    ("fixture_name", "kind", "capture_name"),
    [
        ("adb_manifest.json", InputKind.ADB_COLLECTION_MANIFEST, "su_paths"),
        (
            "magisk_manifest.json",
            InputKind.MAGISK_COLLECTION_MANIFEST,
            "magisk",
        ),
        ("adb_manifest.json", InputKind.ADB_COLLECTION_MANIFEST, "processes"),
    ],
)
def test_loose_text_captures_require_recognized_grammar(
    fixture_name, kind, capture_name
):
    document = json.loads((FIXTURES / fixture_name).read_text(encoding="utf-8"))
    capture = dict(document["captures"][0])
    capture.update(name=capture_name, stdout="garbage")
    document["captures"] = [capture]

    with pytest.raises(NormalizationError, match="malformed observed output"):
        ADAPTERS[kind].parse(json.dumps(document), source_ref="fixture")


def test_magisk_capture_requires_every_line_to_match_grammar():
    document = json.loads(
        (FIXTURES / "magisk_manifest.json").read_text(encoding="utf-8")
    )
    document["captures"] = [
        {
            **document["captures"][1],
            "stdout": "magisk_version=28.1\nversion: forged-version",
        }
    ]

    with pytest.raises(NormalizationError, match="malformed observed output"):
        ADAPTERS[InputKind.MAGISK_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )


@pytest.mark.parametrize(
    "capture_name",
    ["getprop_selected", "identity", "mounts", "getenforce"],
)
def test_impossible_empty_success_does_not_manufacture_absence(capture_name):
    document = json.loads((FIXTURES / "adb_manifest.json").read_text(encoding="utf-8"))
    capture = dict(document["captures"][0])
    capture.update(name=capture_name, status="empty", stdout="")
    document["captures"] = [capture]

    with pytest.raises(NormalizationError, match="malformed observed output"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )


def test_partial_getprop_parse_fails_closed():
    document = json.loads((FIXTURES / "adb_manifest.json").read_text(encoding="utf-8"))
    document["captures"] = [
        {
            **document["captures"][0],
            "stdout": "[ro.secure]: [1]\ngarbage",
        }
    ]

    with pytest.raises(NormalizationError, match="malformed observed output"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )


def test_portable_host_sections_map_to_host_capture_vocabulary():
    result = parse_collection_payload_text(
        "=== HOST_OS ===\nLinux\n=== ADB_VERSION ===\n35.0.2\n",
        source_ref="host.txt",
        metadata=ArtifactMetadata(
            schema_version="1.0.0",
            collector_version="0.3.0-dev0",
            observer_type="host",
            collection_method="host_snapshot",
            experiment_id="E16_adapter_contract",
            target_type="unknown",
            collection_timestamp="2026-07-16T10:00:00Z",
        ),
    )
    assert result.input_kind is InputKind.HOST_COLLECTION_MANIFEST
    assert [capture.name for capture in result.captures] == [
        "host_os",
        "adb_version",
        "emulator_version",
        "python_version",
    ]
    assert [capture.status for capture in result.captures] == [
        CaptureStatus.OBSERVED,
        CaptureStatus.OBSERVED,
        CaptureStatus.NOT_COLLECTED,
        CaptureStatus.NOT_COLLECTED,
    ]
    assert not any("ignored observer-inapplicable" in item for item in result.warnings)


@pytest.mark.parametrize(
    ("text", "fragment_name"),
    [
        ("=== SU_PATHS ===\nPermission denied\n", "su_paths"),
        ("=== MAGISK ===\nmagisk: permission denied\n", "magisk"),
        (
            "=== PS ===\npermission denied while querying magisk process\n",
            "processes",
        ),
    ],
)
def test_legacy_diagnostics_are_warned_and_removed_from_fragments(text, fragment_name):
    result = ADAPTERS[InputKind.LEGACY_SECTIONED_TEXT].parse(
        text, source_ref="legacy.txt"
    )
    assert fragment_name not in result.parsed_capture_names
    assert any("malformed observed output" in warning for warning in result.warnings)
    if fragment_name == "su_paths":
        assert result.fragments.su_paths == ()
    elif fragment_name == "magisk":
        assert result.fragments.magisk_text == ""
    else:
        assert result.fragments.processes["raw_line_count"] == 0


def test_legacy_diagnostic_does_not_normalize_as_root_evidence(tmp_path):
    source = tmp_path / "diagnostic.txt"
    source.write_text("=== SU_PATHS ===\nPermission denied\n", encoding="utf-8")
    report = normalize_raw_file(
        source,
        collection_timestamp="2026-07-16T10:00:00Z",
    )
    validate_report(report)
    assert report["root_state"]["su_present"]["status"] == "not_collected"
    assert report["root_state"]["root_paths"]["status"] == "not_collected"


def test_versioned_adapter_schema_is_enforced_during_parse():
    document = json.loads((FIXTURES / "adb_manifest.json").read_text(encoding="utf-8"))
    document["unexpected"] = True
    with pytest.raises(NormalizationError, match="does not match"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )

    document.pop("unexpected")
    document.pop("collection")
    with pytest.raises(NormalizationError, match="does not match"):
        ADAPTERS[InputKind.ADB_COLLECTION_MANIFEST].parse(
            json.dumps(document), source_ref="fixture"
        )


def test_current_collector_prerelease_version_is_supported():
    document = json.loads(
        (FIXTURES / "magisk_manifest.json").read_text(encoding="utf-8")
    )
    document["collector_version"] = "0.3.0-dev0"
    result = ADAPTERS[InputKind.MAGISK_COLLECTION_MANIFEST].parse(
        json.dumps(document), source_ref="fixture"
    )
    assert result.metadata.collector_version == "0.3.0-dev0"


def test_typed_metadata_cannot_be_overridden_by_caller():
    with pytest.raises(NormalizationError, match="observer_type conflicts"):
        normalize_raw_file(
            FIXTURES / "adb_manifest.json",
            observer_type="root_collector",
        )

    with pytest.raises(NormalizationError, match="target_type conflicts"):
        normalize_raw_file(
            FIXTURES / "adb_manifest.json",
            target_type="physical",
        )


def test_portable_manifest_metadata_selects_observer_adapter():
    report = normalize_collection_manifest(COLLECTION_MANIFEST)
    adapter = report["extensions"]["org.androidtrustlab.adapter"]
    assert adapter["input_kind"] == "magisk_collection_manifest"
    assert "portable collection manifest selected" in adapter["warnings"][0]


def test_portable_text_manifest_rejects_json_payload_substitution():
    metadata = ArtifactMetadata(
        schema_version="1.0.0",
        collector_version="0.3.0-dev0",
        observer_type="root_collector",
        collection_method="magisk_module_manual",
        experiment_id="E05_magisk_collector",
        target_type="avd",
        collection_timestamp="2026-04-25T15:50:00Z",
    )
    with pytest.raises(NormalizationError, match="text/plain raw_report"):
        parse_collection_payload_text(
            (FIXTURES / "adb_manifest.json").read_text(encoding="utf-8"),
            source_ref="raw_sample.txt",
            metadata=metadata,
        )


def test_observer_metadata_does_not_manufacture_root_or_su_evidence():
    report = normalize_raw_file(FIXTURES / "magisk_manifest.json")
    validate_report(report)
    assert report["observer"]["observer_type"] == "root_collector"
    assert report["root_state"]["root_shell_available"]["value"] is True
    assert report["root_state"]["su_present"]["value"] is True
    assert report["root_state"]["root_paths"]["status"] == "not_collected"
    assert report["root_state"]["root_paths"]["value"] is None
    assert report["raw_artifacts"][0]["collector_version"] == "0.3.0"
    assert report["raw_artifacts"][0]["media_type"] == "application/json"


def test_app_manifest_normalizes_using_declared_observer_context():
    report = normalize_raw_file(FIXTURES / "app_probe.json")
    validate_report(report)
    assert report["observer"] == {
        "observer_type": "unprivileged_app",
        "privilege_level": "app_sandbox",
        "collection_method": "synthetic_app_fixture",
    }
    assert report["root_state"]["su_present"]["status"] == "not_collected"
    assert report["root_state"]["su_present"]["value"] is None
    assert report["emulator_state"]["is_emulator"]["status"] == "not_collected"
    assert report["selinux"]["mode"]["status"] == "inaccessible"
    assert report["provenance"]["command_results"][1]["status"] == "inaccessible"


def test_root_observer_metadata_without_identity_does_not_create_root_evidence(
    tmp_path,
):
    document = json.loads(
        (FIXTURES / "magisk_manifest.json").read_text(encoding="utf-8")
    )
    document["captures"] = [
        capture for capture in document["captures"] if capture["name"] != "identity"
    ]
    source = tmp_path / "root-observer-without-identity.json"
    source.write_text(json.dumps(document), encoding="utf-8")

    report = normalize_raw_file(source)
    validate_report(report)
    assert report["observer"]["observer_type"] == "root_collector"
    assert report["root_state"]["root_shell_available"]["status"] == "not_collected"
    assert report["root_state"]["uid"]["status"] == "not_collected"


def test_explicit_cli_artifact_kind_preserves_legacy_compatibility(tmp_path):
    report = normalize_raw_file(
        ROOT / "tests/fixtures/sample_raw_report.txt",
        artifact_kind="legacy_sectioned_text",
        collection_timestamp="2026-01-02T03:04:05Z",
    )
    validate_report(report)
    adapter = report["extensions"]["org.androidtrustlab.adapter"]
    assert adapter["input_kind"] == "legacy_sectioned_text"
    assert "inferred command status" in adapter["warnings"][0]

    output = tmp_path / "legacy-report.json"
    assert (
        cli.main(
            [
                "normalize",
                "--input",
                str(ROOT / "tests/fixtures/sample_raw_report.txt"),
                "--artifact-kind",
                "legacy_sectioned_text",
                "--collection-timestamp",
                "2026-01-02T03:04:05Z",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    validate_report(json.loads(output.read_text(encoding="utf-8")))


def test_explicit_legacy_kind_cannot_bypass_json_selection():
    text = (FIXTURES / "adb_manifest.json").read_text(encoding="utf-8")
    with pytest.raises(NormalizationError, match="cannot contain a JSON"):
        adapter_for_text(text, explicit_kind="legacy_sectioned_text")


def test_adapter_fixtures_match_their_declared_json_schemas():
    collection_schema = load_schema("artifact_collection_manifest_v1_0_0.schema.json")
    app_schema = load_schema("app_probe_v1_0_0.schema.json")
    for name in ("adb_manifest.json", "magisk_manifest.json", "host_manifest.json"):
        Draft202012Validator(collection_schema).validate(
            json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        )
    Draft202012Validator(app_schema).validate(
        json.loads((FIXTURES / "app_probe.json").read_text(encoding="utf-8"))
    )
