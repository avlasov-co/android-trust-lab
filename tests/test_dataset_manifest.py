from __future__ import annotations

import copy
import hashlib
import os
import shutil
from pathlib import Path

import pytest

from trustlab import cli
from trustlab.canonical_json import framed_content_digest
from trustlab.collection_manifest import CollectionManifest
from trustlab.dataset_manifest import (
    MAX_DATASET_ARTIFACT_BYTES,
    parse_dataset_json,
    read_regular_file_beneath,
    stable_pretty_json_bytes,
    verify_dataset_manifest,
)
from trustlab.exceptions import (
    CollectionError,
    InvalidJSONError,
    MissingFileError,
    SchemaValidationError,
    UnsupportedSchemaVersionError,
)
from trustlab.identity import finalize_report_identity
from trustlab.normalizer import (
    normalize_collection_manifest,
    normalize_collection_payload,
)
from trustlab.report_writer import load_json
from trustlab.validators import validate_dataset_manifest, validate_dataset_source

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "datasets/manifest.json"
SOURCE = ROOT / "datasets/source.json"


def write_json(path: Path, value: object) -> None:
    path.write_bytes(stable_pretty_json_bytes(value))


def copied_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "portable-dataset"
    shutil.copytree(ROOT / "datasets", bundle)
    return bundle


def artifact_by_role(manifest: dict, role: str) -> dict:
    return next(
        artifact for artifact in manifest["artifacts"] if artifact["role"] == role
    )


def rebind_artifact(manifest: dict, bundle: Path, artifact_id: str) -> None:
    artifact = next(
        item for item in manifest["artifacts"] if item["artifact_id"] == artifact_id
    )
    payload = (bundle / artifact["relative_path"]).read_bytes()
    artifact["byte_size"] = len(payload)
    artifact["sha256"] = hashlib.sha256(payload).hexdigest()


def mark_sample_as_collector_produced(source: dict, sample: dict) -> None:
    producer = {
        "kind": "collector",
        "name": "manual-collector",
        "version": "1.0.0",
    }
    for artifact_id in (
        sample["raw_artifact_id"],
        sample["collection_manifest"]["artifact_id"],
    ):
        artifact = next(
            item for item in source["artifacts"] if item["artifact_id"] == artifact_id
        )
        artifact["producer"] = copy.deepcopy(producer)


def make_captured_bundle(tmp_path: Path, origin: str) -> Path:
    source = load_json(SOURCE)
    sample = copy.deepcopy(source["samples"][-1])
    source["samples"] = [sample]
    source["derived_diffs"] = []
    source["origin_classifications"] = [origin]
    sample["origin_classification"] = origin
    if origin == "avd_captured":
        source["authorization"] = {
            "classification": "authorized_avd_collection",
            "statement": "Authorized AVD contract fixture.",
            "physical_data_disclosed": False,
        }
    else:
        source["authorization"] = {
            "classification": "authorized_physical_collection",
            "statement": "Authorized and disclosed physical contract fixture.",
            "physical_data_disclosed": True,
        }
        sample["target_type"] = "physical"

    retained_ids = {
        source["declarative_source_artifact_id"],
        sample["raw_artifact_id"],
        sample["collection_manifest"]["artifact_id"],
        sample["normalized_report_artifact_id"],
    }
    source["artifacts"] = [
        artifact
        for artifact in source["artifacts"]
        if artifact["artifact_id"] in retained_ids
    ]
    artifacts = {artifact["artifact_id"]: artifact for artifact in source["artifacts"]}
    collector = {
        "kind": "collector",
        "name": "trustlab-magisk",
        "version": "0.3.0-dev0",
    }
    artifacts[sample["raw_artifact_id"]]["producer"] = copy.deepcopy(collector)
    collection_id = sample["collection_manifest"]["artifact_id"]
    artifacts[collection_id]["producer"] = copy.deepcopy(collector)

    bundle = tmp_path / f"{origin}-bundle"
    raw_artifact = artifacts[sample["raw_artifact_id"]]
    raw_payload = (ROOT / "datasets" / raw_artifact["relative_path"]).read_bytes()
    raw_path = bundle / raw_artifact["relative_path"]
    raw_path.parent.mkdir(parents=True)
    raw_path.write_bytes(raw_payload)

    collection_artifact = artifacts[collection_id]
    collection = load_json(ROOT / "datasets" / collection_artifact["relative_path"])
    collection["target"]["target_type"] = sample["target_type"]
    collection["warnings"] = []
    collection_path = bundle / collection_artifact["relative_path"]
    write_json(collection_path, collection)

    report_artifact = artifacts[sample["normalized_report_artifact_id"]]
    report = normalize_collection_payload(
        raw_payload,
        CollectionManifest.from_dict(collection),
        label=raw_path.name,
    )
    write_json(bundle / report_artifact["relative_path"], report)
    write_json(bundle / "source.json", source)

    payloads = {
        artifact_id: (bundle / artifact["relative_path"]).read_bytes()
        for artifact_id, artifact in artifacts.items()
    }
    manifest = copy.deepcopy(source)
    manifest["schema_version"] = "2.0.0"
    manifest["artifacts"] = [
        {
            **artifact,
            "byte_size": len(payloads[artifact["artifact_id"]]),
            "sha256": hashlib.sha256(payloads[artifact["artifact_id"]]).hexdigest(),
        }
        for artifact in source["artifacts"]
    ]
    write_json(bundle / "manifest.json", manifest)
    return bundle


def test_current_dataset_verifies_as_a_closed_fresh_bundle():
    result = verify_dataset_manifest(MANIFEST)

    assert result.dataset_id == "atlds-android-trust-lab-samples"
    assert result.dataset_version == "0.1.0"
    assert result.artifact_count == 16
    assert result.sample_count == 5
    assert result.diff_count == 4


def test_observed_manifest_dataset_report_uses_the_exact_manifest_normalization():
    manifest_path = (
        ROOT / "datasets/samples/magisk_collector/collector_manifest_sample.json"
    )
    report_path = (
        ROOT / "datasets/samples/magisk_collector/"
        "E05_magisk_collector__observer-root__sample.json"
    )

    checked = load_json(report_path)
    expected = normalize_collection_manifest(manifest_path)
    assert checked == expected
    assert checked["raw_artifacts"][0]["collector_name"] == "trustlab-magisk"
    assert (
        "collection manifest completion status: partial"
        in checked["limitations"]["collection_errors"]
    )


@pytest.mark.parametrize("origin", ["avd_captured", "physical_captured"])
def test_captured_origin_bundles_verify_end_to_end(tmp_path, origin):
    bundle = make_captured_bundle(tmp_path, origin)

    result = verify_dataset_manifest(bundle / "manifest.json")

    assert result.sample_count == 1
    assert result.artifact_count == 4
    assert result.diff_count == 0


def test_dataset_cli_is_cwd_independent_and_has_exact_success_output(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)

    assert cli.main(["dataset", "verify", str(MANIFEST)]) == 0

    captured = capsys.readouterr()
    assert captured.out == "dataset verified\n"
    assert captured.err == ""
    assert str(ROOT) not in captured.out


def test_frozen_historical_manifest_remains_readable_but_is_not_verifiable():
    historical = ROOT / "tests/fixtures/dataset_manifest_v1_historical.json"
    validate_dataset_manifest(load_json(historical))

    with pytest.raises(UnsupportedSchemaVersionError, match="requires.*2.0.0"):
        verify_dataset_manifest(historical)


def test_frozen_prior_v2_artifact_profile_remains_readable():
    historical = ROOT / "tests/fixtures/dataset_manifest_v2_historical.json"

    assert (
        hashlib.sha256(historical.read_bytes()).hexdigest()
        == "5a000a270739f2195e9818218bd7c2178651b4863ba65fbc659da64983dc29c6"  # pragma: allowlist secret
    )
    validate_dataset_manifest(load_json(historical))


def test_dataset_source_writer_requires_current_artifact_profile():
    source = load_json(SOURCE)
    source["artifact_schema_versions"]["normalized_report"] = "2.0.0"
    source["artifact_schema_versions"]["derived_diff"] = "1.0.0"
    for artifact in source["artifacts"]:
        if artifact["role"] == "normalized_report":
            artifact["schema_version"] = "2.0.0"
        elif artifact["role"] == "derived_diff":
            artifact["schema_version"] = "1.0.0"

    with pytest.raises(SchemaValidationError, match="current artifact schema profile"):
        validate_dataset_source(source)


@pytest.mark.parametrize(
    ("fixture", "message"),
    [
        (
            "dataset_source_invalid_traversal.json",
            "normalized relative paths",
        ),
        (
            "dataset_source_invalid_undisclosed_physical.json",
            "physical data requires disclosure",
        ),
    ],
)
def test_manual_negative_dataset_sources_fail_closed(fixture, message):
    document = load_json(ROOT / "tests/fixtures" / fixture)
    with pytest.raises(SchemaValidationError, match=message):
        validate_dataset_source(document)


def test_current_source_is_valid_and_classifies_fixture_text_as_synthetic():
    source = load_json(SOURCE)
    validate_dataset_source(source)

    assert source["origin_classifications"] == ["synthetic"]
    assert {sample["origin_classification"] for sample in source["samples"]} == {
        "synthetic"
    }
    assert all(
        "captured" not in sample["collection_method"] for sample in source["samples"]
    )


def test_dataset_schemas_close_every_structured_object():
    from trustlab.validators import load_schema

    for name in (
        "dataset_source_v1_0_0.schema.json",
        "dataset_manifest_v2_0_0.schema.json",
    ):
        schema = load_schema(name)
        objects = [schema]
        objects.extend(
            definition
            for definition in schema["$defs"].values()
            if definition.get("type") == "object"
        )
        for definition in objects:
            assert definition["additionalProperties"] is False
            assert set(definition["required"]) == set(definition["properties"])


def test_source_and_manifest_schemas_remain_structurally_aligned():
    from trustlab.validators import load_schema

    source_schema = load_schema("dataset_source_v1_0_0.schema.json")
    manifest_schema = load_schema("dataset_manifest_v2_0_0.schema.json")
    for field in ("$id", "title", "description"):
        source_schema.pop(field)
        manifest_schema.pop(field)
    source_schema["properties"]["schema_version"] = {"const": "2.0.0"}
    source_artifact = source_schema["$defs"].pop("artifactDefinition")
    manifest_artifact = manifest_schema["$defs"].pop("artifactBinding")
    for field in ("byte_size", "sha256"):
        manifest_artifact["properties"].pop(field)
        manifest_artifact["required"].remove(field)
    source_schema["$defs"]["artifactBinding"] = source_artifact
    manifest_schema["$defs"]["artifactBinding"] = manifest_artifact
    source_schema["properties"]["artifacts"]["items"]["$ref"] = (
        "#/$defs/artifactBinding"
    )

    assert source_schema == manifest_schema


@pytest.mark.parametrize(
    "relative_path",
    [
        "/absolute/raw.txt",
        "../raw.txt",
        "sample/../raw.txt",
        "sample\\raw.txt",
        "file:raw.txt",
        "sample/./raw.txt",
        "sample/\u0001raw.txt",
    ],
)
def test_manifest_rejects_nonportable_artifact_paths(relative_path):
    manifest = load_json(MANIFEST)
    artifact_by_role(manifest, "raw_artifact")["relative_path"] = relative_path

    with pytest.raises(SchemaValidationError, match="artifact path"):
        validate_dataset_manifest(manifest)


@pytest.mark.parametrize("field", ["artifact_id", "relative_path"])
def test_manifest_rejects_duplicate_artifact_identity_and_paths(field):
    manifest = load_json(MANIFEST)
    manifest["artifacts"][1][field] = manifest["artifacts"][0][field]

    with pytest.raises(SchemaValidationError, match="must be unique"):
        validate_dataset_manifest(manifest)


def test_manifest_rejects_duplicate_sample_and_derivation_ids():
    manifest = load_json(MANIFEST)
    manifest["samples"][1]["sample_id"] = manifest["samples"][0]["sample_id"]
    with pytest.raises(SchemaValidationError, match="sample IDs must be unique"):
        validate_dataset_manifest(manifest)

    manifest = load_json(MANIFEST)
    manifest["derived_diffs"][1]["derivation_id"] = manifest["derived_diffs"][0][
        "derivation_id"
    ]
    with pytest.raises(SchemaValidationError, match="derivation IDs must be unique"):
        validate_dataset_manifest(manifest)

    manifest = load_json(MANIFEST)
    manifest["derived_diffs"][1]["artifact_id"] = manifest["derived_diffs"][0][
        "artifact_id"
    ]
    with pytest.raises(SchemaValidationError, match="diff artifact references"):
        validate_dataset_manifest(manifest)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("raw_artifact_id", "sample raw artifact references"),
        ("normalized_report_artifact_id", "sample report artifact references"),
    ],
)
def test_manifest_rejects_reused_sample_artifact_bindings(field, message):
    manifest = load_json(MANIFEST)
    manifest["samples"][1][field] = manifest["samples"][0][field]

    with pytest.raises(SchemaValidationError, match=message):
        validate_dataset_manifest(manifest)


def test_manifest_rejects_mixed_or_unsupported_artifact_schema_versions():
    manifest = load_json(MANIFEST)
    artifact_by_role(manifest, "normalized_report")["schema_version"] = "1.0.0"

    with pytest.raises(SchemaValidationError, match="schema profile must agree"):
        validate_dataset_manifest(manifest)


def test_mixed_origins_require_mixed_authorization():
    source = load_json(SOURCE)
    source["origin_classifications"] = ["synthetic", "avd_captured"]
    sample = source["samples"][0]
    sample["origin_classification"] = "avd_captured"
    sample["collection_manifest"] = copy.deepcopy(
        source["samples"][-1]["collection_manifest"]
    )
    collection_id = sample["collection_manifest"]["artifact_id"]
    source["samples"][-1]["collection_manifest"] = {
        "status": "not_collected",
        "artifact_id": None,
        "reason": "Moved to the first sample for this semantic fixture.",
    }
    mark_sample_as_collector_produced(source, sample)

    with pytest.raises(SchemaValidationError, match="mixed authorization"):
        validate_dataset_source(source)

    assert collection_id is not None


def test_physical_sample_artifacts_require_redaction():
    source = load_json(
        ROOT / "tests/fixtures/dataset_source_invalid_undisclosed_physical.json"
    )
    source["authorization"] = {
        "classification": "authorized_physical_collection",
        "statement": "Owned physical test target.",
        "physical_data_disclosed": True,
    }
    for artifact in source["artifacts"]:
        artifact["redaction_state"] = "not_required"

    with pytest.raises(SchemaValidationError, match="artifacts require redaction"):
        validate_dataset_source(source)


def test_physical_only_dataset_rejects_mixed_authorization():
    source = load_json(
        ROOT / "tests/fixtures/dataset_source_invalid_undisclosed_physical.json"
    )
    source["authorization"] = {
        "classification": "mixed_authorized",
        "statement": "Invalid mixed authorization for one physical origin.",
        "physical_data_disclosed": True,
    }

    with pytest.raises(SchemaValidationError, match="physical data requires"):
        validate_dataset_source(source)


def test_diffs_derived_from_physical_samples_require_redaction():
    source = load_json(SOURCE)
    source["origin_classifications"] = ["synthetic", "physical_captured"]
    source["authorization"] = {
        "classification": "mixed_authorized",
        "statement": "Mixed synthetic and authorized physical fixture.",
        "physical_data_disclosed": True,
    }
    physical = source["samples"][0]
    physical["origin_classification"] = "physical_captured"
    physical["target_type"] = "physical"
    physical["collection_manifest"] = copy.deepcopy(
        source["samples"][-1]["collection_manifest"]
    )
    source["samples"][-1]["collection_manifest"] = {
        "status": "not_collected",
        "artifact_id": None,
        "reason": "Moved to the physical semantic fixture.",
    }
    mark_sample_as_collector_produced(source, physical)
    artifact_by_role(source, "derived_diff")["redaction_state"] = "not_required"

    with pytest.raises(
        SchemaValidationError, match="physical samples require redaction"
    ):
        validate_dataset_source(source)

    manifest = load_json(MANIFEST)
    artifact_by_role(manifest, "derived_diff")["producer"]["version"] = "9.9.9"
    with pytest.raises(SchemaValidationError, match="match creation tooling"):
        validate_dataset_manifest(manifest)


def test_manifest_rejects_unreferenced_and_wrong_role_artifacts():
    manifest = load_json(MANIFEST)
    manifest["artifacts"].append(
        {
            **copy.deepcopy(artifact_by_role(manifest, "raw_artifact")),
            "artifact_id": "unreferenced-raw",
            "relative_path": "samples/unreferenced/raw.txt",
        }
    )
    with pytest.raises(SchemaValidationError, match="closed, fully referenced graph"):
        validate_dataset_manifest(manifest)

    manifest = load_json(MANIFEST)
    report_id = manifest["samples"][0]["normalized_report_artifact_id"]
    next(item for item in manifest["artifacts"] if item["artifact_id"] == report_id)[
        "role"
    ] = "raw_artifact"
    with pytest.raises(SchemaValidationError, match="role, format"):
        validate_dataset_manifest(manifest)


def test_verifier_rejects_missing_artifact(tmp_path):
    bundle = copied_bundle(tmp_path)
    manifest = load_json(bundle / "manifest.json")
    raw = artifact_by_role(manifest, "raw_artifact")
    (bundle / raw["relative_path"]).unlink()

    with pytest.raises(MissingFileError, match="dataset artifact"):
        verify_dataset_manifest(bundle / "manifest.json")


def test_verifier_rejects_digest_and_size_mismatch(tmp_path):
    bundle = copied_bundle(tmp_path)
    manifest_path = bundle / "manifest.json"
    manifest = load_json(manifest_path)
    raw = artifact_by_role(manifest, "raw_artifact")
    raw_path = bundle / raw["relative_path"]
    raw_path.write_bytes(raw_path.read_bytes() + b"tampered\n")

    with pytest.raises(CollectionError, match="byte size mismatch"):
        verify_dataset_manifest(manifest_path)

    raw["byte_size"] = raw_path.stat().st_size
    write_json(manifest_path, manifest)
    with pytest.raises(CollectionError, match="digest mismatch"):
        verify_dataset_manifest(manifest_path)


def test_verifier_rejects_excessive_cumulative_declared_bytes(tmp_path):
    bundle = copied_bundle(tmp_path)
    manifest_path = bundle / "manifest.json"
    manifest = load_json(manifest_path)
    for artifact in manifest["artifacts"][:3]:
        artifact["byte_size"] = MAX_DATASET_ARTIFACT_BYTES
    write_json(manifest_path, manifest)

    with pytest.raises(CollectionError, match="cumulative verification limit"):
        verify_dataset_manifest(manifest_path)


@pytest.mark.parametrize(
    "relative_path",
    ["../secret", "/absolute", "nested/../secret", "nested\\secret", "file:x"],
)
def test_safe_snapshot_primitive_rejects_traversal(relative_path, tmp_path):
    with pytest.raises(CollectionError, match="normalized and relative"):
        read_regular_file_beneath(
            tmp_path,
            relative_path,
            limit=1024,
            label="fixture",
        )


@pytest.mark.parametrize("replacement", ["symlink", "directory"])
def test_verifier_rejects_symlink_and_nonregular_artifacts(tmp_path, replacement):
    bundle = copied_bundle(tmp_path)
    manifest = load_json(bundle / "manifest.json")
    raw = artifact_by_role(manifest, "raw_artifact")
    raw_path = bundle / raw["relative_path"]
    payload = raw_path.read_bytes()
    raw_path.unlink()
    if replacement == "symlink":
        outside = tmp_path / "outside.txt"
        outside.write_bytes(payload)
        raw_path.symlink_to(outside)
    else:
        raw_path.mkdir()

    with pytest.raises(
        CollectionError,
        match="regular non-symlink file|path contains a non-directory or symlink",
    ):
        verify_dataset_manifest(bundle / "manifest.json")


def test_verifier_rejects_symlinked_intermediate_directory(tmp_path):
    bundle = copied_bundle(tmp_path)
    manifest = load_json(bundle / "manifest.json")
    raw = artifact_by_role(manifest, "raw_artifact")
    top = bundle / Path(raw["relative_path"]).parts[0]
    moved = tmp_path / "moved-samples"
    top.rename(moved)
    top.symlink_to(moved, target_is_directory=True)

    with pytest.raises(CollectionError, match="contains a non-directory or symlink"):
        verify_dataset_manifest(bundle / "manifest.json")


@pytest.mark.parametrize(
    "relative_path",
    [
        "samples/unbound.txt",
        "samples/unbound.log",
        "samples/unbound.bin",
        "samples/unbound/README.md",
        "unbound.bin",
        "other/physical-capture.raw",
    ],
)
def test_verifier_rejects_unbound_evidence_regardless_of_suffix(
    tmp_path, relative_path
):
    bundle = copied_bundle(tmp_path)
    extra = bundle / relative_path
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_text("unbound\n", encoding="utf-8")

    with pytest.raises(SchemaValidationError, match="unbound artifacts"):
        verify_dataset_manifest(bundle / "manifest.json")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission semantics required")
def test_verifier_fails_closed_when_evidence_directory_is_unreadable(tmp_path):
    bundle = copied_bundle(tmp_path)
    hidden = bundle / "hidden"
    hidden.mkdir()
    (hidden / "physical.raw").write_text("undisclosed\n", encoding="utf-8")
    hidden.chmod(0)
    try:
        if os.access(hidden, os.R_OK):
            pytest.skip("test process can still read mode-000 directories")
        with pytest.raises(CollectionError, match="inspect dataset evidence tree"):
            verify_dataset_manifest(bundle / "manifest.json")
    finally:
        hidden.chmod(0o700)


@pytest.mark.parametrize(
    ("role", "field", "value", "message"),
    [
        (
            "normalized_report",
            "limitations",
            "toggle",
            "normalized dataset report is stale",
        ),
        (
            "derived_diff",
            "summary",
            "tampered summary",
            "derived dataset diff is stale|diff summary is not canonical",
        ),
    ],
)
def test_verifier_regenerates_outputs_instead_of_trusting_rehashed_bytes(
    tmp_path, role, field, value, message
):
    bundle = copied_bundle(tmp_path)
    manifest_path = bundle / "manifest.json"
    manifest = load_json(manifest_path)
    artifact = artifact_by_role(manifest, role)
    artifact_path = bundle / artifact["relative_path"]
    document = load_json(artifact_path)
    if field == "limitations":
        document[field]["missing_tee_validation"] = not document[field][
            "missing_tee_validation"
        ]
        document = finalize_report_identity(document)
    else:
        document[field] = value
        projection = {
            key: item
            for key, item in document.items()
            if key not in {"diff_id", "content_digest"}
        }
        content_digest = framed_content_digest(
            family="diff", schema_version=document["schema_version"], value=projection
        )
        document["content_digest"] = content_digest
        document["diff_id"] = f"atldiff-{content_digest[:32]}"
    write_json(artifact_path, document)
    rebind_artifact(manifest, bundle, artifact["artifact_id"])
    write_json(manifest_path, manifest)

    with pytest.raises((CollectionError, SchemaValidationError), match=message):
        verify_dataset_manifest(manifest_path)


def test_verifier_rejects_source_driven_metadata_change_until_regenerated(tmp_path):
    bundle = copied_bundle(tmp_path)
    source_path = bundle / "source.json"
    source = load_json(source_path)
    source["samples"][0]["collection_method"] = "changed_fixture_method"
    write_json(source_path, source)

    manifest_path = bundle / "manifest.json"
    manifest = load_json(manifest_path)
    manifest["samples"][0]["collection_method"] = "changed_fixture_method"
    rebind_artifact(manifest, bundle, manifest["declarative_source_artifact_id"])
    write_json(manifest_path, manifest)

    with pytest.raises(CollectionError, match="normalized dataset report is stale"):
        verify_dataset_manifest(manifest_path)


def test_contract_pins_report_producer_to_canonical_tooling(tmp_path):
    bundle = copied_bundle(tmp_path)
    source_path = bundle / "source.json"
    source = load_json(source_path)
    report_source = artifact_by_role(source, "normalized_report")
    report_source["producer"]["name"] = "different-generator"
    write_json(source_path, source)

    manifest_path = bundle / "manifest.json"
    manifest = load_json(manifest_path)
    report_manifest = next(
        artifact
        for artifact in manifest["artifacts"]
        if artifact["artifact_id"] == report_source["artifact_id"]
    )
    report_manifest["producer"]["name"] = "different-generator"
    rebind_artifact(manifest, bundle, manifest["declarative_source_artifact_id"])
    write_json(manifest_path, manifest)

    with pytest.raises(SchemaValidationError, match="producers.*creation tooling"):
        verify_dataset_manifest(manifest_path)


def test_verifier_cross_checks_collection_manifest_relationships(tmp_path):
    bundle = copied_bundle(tmp_path)
    manifest_path = bundle / "manifest.json"
    manifest = load_json(manifest_path)
    collection = artifact_by_role(manifest, "collection_manifest")
    collection_path = bundle / collection["relative_path"]
    document = load_json(collection_path)
    document["experiment_id"] = "E99_manual"
    write_json(collection_path, document)
    rebind_artifact(manifest, bundle, collection["artifact_id"])
    write_json(manifest_path, manifest)

    with pytest.raises(
        SchemaValidationError,
        match="collection relationship|artifact binding is not semantic",
    ):
        verify_dataset_manifest(manifest_path)


@pytest.mark.parametrize("materialize_extra", [False, True])
def test_verifier_rejects_additional_observed_collection_evidence(
    tmp_path, materialize_extra
):
    bundle = copied_bundle(tmp_path)
    manifest_path = bundle / "manifest.json"
    manifest = load_json(manifest_path)
    collection = artifact_by_role(manifest, "collection_manifest")
    collection_path = bundle / collection["relative_path"]
    document = load_json(collection_path)
    extra_payload = b"additional observed evidence\n"
    extra = copy.deepcopy(document["artifacts"][0])
    extra.update(
        {
            "logical_name": "extra_device_log",
            "relative_path": "extra_device_artifact.log",
            "byte_size": len(extra_payload),
            "sha256": hashlib.sha256(extra_payload).hexdigest(),
            "probe_id": "manual.extra_device_log",
        }
    )
    document["artifacts"].append(extra)
    write_json(collection_path, document)
    if materialize_extra:
        collection_path.with_name("extra_device_artifact.log").write_bytes(
            extra_payload
        )
    rebind_artifact(manifest, bundle, collection["artifact_id"])
    write_json(manifest_path, manifest)

    with pytest.raises(
        SchemaValidationError,
        match="collection relationship|artifact binding is not semantic",
    ):
        verify_dataset_manifest(manifest_path)


def test_verifier_rejects_duplicate_keys_and_nonfinite_json(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_bytes(b'{"schema_version":"2.0.0","schema_version":"2.0.0"}\n')
    with pytest.raises(InvalidJSONError, match="invalid JSON"):
        verify_dataset_manifest(duplicate)

    with pytest.raises(InvalidJSONError, match="invalid JSON"):
        parse_dataset_json(b'{"value":NaN}\n', label="nonfinite.json")


def test_cli_maps_dataset_failures_to_stable_exit_codes(tmp_path, capsys):
    bundle = copied_bundle(tmp_path)
    manifest_path = bundle / "manifest.json"
    manifest = load_json(manifest_path)
    raw = artifact_by_role(manifest, "raw_artifact")
    (bundle / raw["relative_path"]).unlink()

    assert cli.main(["dataset", "verify", str(manifest_path)]) == cli.EXIT_MISSING_FILE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: input file not found: dataset artifact\n"
    assert str(tmp_path) not in captured.err

    unsupported = tmp_path / "unsupported.json"
    write_json(unsupported, {"schema_version": "9.9.9"})
    assert (
        cli.main(["dataset", "verify", str(unsupported)]) == cli.EXIT_UNSUPPORTED_SCHEMA
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: unsupported dataset manifest schema version\n"


def test_manifest_and_source_are_canonical_and_deterministic():
    manifest_payload = MANIFEST.read_bytes()
    manifest = parse_dataset_json(manifest_payload, label=MANIFEST.name)
    assert manifest_payload == stable_pretty_json_bytes(manifest)

    source = parse_dataset_json(SOURCE.read_bytes(), label=SOURCE.name)
    assert stable_pretty_json_bytes(source) == stable_pretty_json_bytes(
        copy.deepcopy(source)
    )
