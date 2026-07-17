from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from trustlab import cli, magisk_importer
from trustlab.canonical_json import canonical_json_bytes
from trustlab.collection_manifest import CollectionManifest, write_collection_manifest
from trustlab.compatibility import EvidenceStatus
from trustlab.exceptions import (
    CollectionError,
    InvalidJSONError,
    MissingFileError,
    NormalizationError,
    OutputWriteError,
    SchemaValidationError,
    UnsupportedSchemaVersionError,
)
from trustlab.magisk_importer import (
    COMPLETION_MANIFEST_NAME,
    IMPORT_LOCK_NAME,
    NORMALIZED_REPORT_NAME,
    import_magisk,
)
from trustlab.report_writer import load_json
from trustlab.validators import validate_report

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_ROOT = ROOT / "datasets" / "samples" / "magisk_collector"
SAMPLE_MANIFEST = SAMPLE_ROOT / "collector_manifest_sample.json"
SAMPLE_RAW = SAMPLE_ROOT / "raw_sample.txt"


def complete_document() -> dict[str, object]:
    document = load_json(SAMPLE_MANIFEST)
    document["completion_status"] = "complete"
    command_results = document["artifacts"][1]
    command_results["status"] = "observed_absent"
    command_results["exit_code"] = 0
    return document


def write_json_unchecked(path: Path, document: object) -> None:
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")


def make_bundle(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    source = tmp_path / "source"
    source.mkdir(parents=True)
    shutil.copyfile(SAMPLE_RAW, source / "raw_sample.txt")
    document = complete_document()
    write_collection_manifest(document, source / COMPLETION_MANIFEST_NAME)
    return source, document


def assert_private(path: Path, expected: int) -> None:
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == expected


def test_import_publishes_content_addressed_valid_private_bundle(tmp_path):
    source, document = make_bundle(tmp_path)
    output = tmp_path / "imports"

    result = import_magisk(source, output)

    expected_digest = hashlib.sha256(canonical_json_bytes(document)).hexdigest()
    assert result.content_id == f"sha256-{expected_digest}"
    assert result.directory == output / result.content_id
    assert result.manifest_path == result.directory / COMPLETION_MANIFEST_NAME
    assert result.report_path == result.directory / NORMALIZED_REPORT_NAME
    assert result.manifest_path.is_file()
    assert (result.directory / "raw_sample.txt").read_bytes() == SAMPLE_RAW.read_bytes()
    report = load_json(result.report_path)
    validate_report(report)
    assert report["observer"]["observer_type"] == "root_collector"
    assert (
        report["extensions"]["org.androidtrustlab.collection"][
            "canonical_manifest_sha256"
        ]
        == expected_digest
    )
    assert list(output.glob(".trustlab-magisk-import-*")) == []
    assert not (output / IMPORT_LOCK_NAME).exists()
    assert_private(output, 0o700)
    assert_private(result.directory, 0o700)
    assert_private(result.manifest_path, 0o600)
    assert_private(result.report_path, 0o600)
    assert_private(result.directory / "raw_sample.txt", 0o600)


def test_import_accepts_boot_method_and_runtime_raw_path(tmp_path):
    source, document = make_bundle(tmp_path)
    document["observer"]["collection_method"] = "magisk_module_boot"
    document["artifacts"][0]["relative_path"] = "raw.txt"
    (source / "raw_sample.txt").rename(source / "raw.txt")
    write_collection_manifest(document, source / COMPLETION_MANIFEST_NAME)

    result = import_magisk(source, tmp_path / "imports")

    report = load_json(result.report_path)
    assert report["observer"]["collection_method"] == "magisk_module_boot"
    assert (result.directory / "raw.txt").read_bytes() == SAMPLE_RAW.read_bytes()


def test_import_accepts_exact_completion_manifest_path_and_cli_is_silent(
    tmp_path, capsys
):
    source, _document = make_bundle(tmp_path)
    output = tmp_path / "imports"

    code = cli.main(
        [
            "import",
            "magisk",
            "--input",
            str(source / COMPLETION_MANIFEST_NAME),
            "--output",
            str(output),
        ]
    )

    assert code == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert len(list(output.glob("sha256-*"))) == 1


def test_cli_rejects_partial_import_without_output(tmp_path, capsys):
    source, document = make_bundle(tmp_path)
    document["completion_status"] = "partial"
    document["artifacts"][1]["status"] = "not_collected"
    document["artifacts"][1]["exit_code"] = None
    write_collection_manifest(document, source / COMPLETION_MANIFEST_NAME)
    output = tmp_path / "imports"

    code = cli.main(
        [
            "import",
            "magisk",
            "--input",
            str(source),
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    assert code == cli.EXIT_COLLECTION_FAILURE
    assert captured.out == ""
    assert captured.err == "error: Magisk import requires a complete collection\n"
    assert str(tmp_path) not in captured.err
    assert not output.exists()


def test_import_output_contains_no_absolute_source_path(tmp_path):
    source, _document = make_bundle(tmp_path)
    result = import_magisk(source, tmp_path / "imports")
    sensitive = str(source).encode()

    for path in result.directory.rglob("*"):
        if path.is_file():
            assert sensitive not in path.read_bytes()


@pytest.mark.parametrize("completion", ["partial", "failed"])
def test_import_rejects_incomplete_collections(tmp_path, completion):
    source, document = make_bundle(tmp_path)
    document["completion_status"] = completion
    if completion == "partial":
        document["artifacts"][1]["status"] = "not_collected"
        document["artifacts"][1]["exit_code"] = None
    else:
        document["artifacts"][0].update(
            {
                "status": "not_collected",
                "relative_path": None,
                "byte_size": None,
                "sha256": None,
                "exit_code": None,
            }
        )
        document["artifacts"][1]["status"] = "not_collected"
        document["artifacts"][1]["exit_code"] = None
        (source / "raw_sample.txt").unlink()
    write_collection_manifest(document, source / COMPLETION_MANIFEST_NAME)

    with pytest.raises(CollectionError, match="requires a complete collection"):
        import_magisk(source, tmp_path / "imports")


def test_import_rejects_missing_mismatched_and_unsupported_module_versions(tmp_path):
    source, document = make_bundle(tmp_path)
    del document["tool_versions"]["trustlab_magisk"]
    write_collection_manifest(document, source / COMPLETION_MANIFEST_NAME)
    with pytest.raises(SchemaValidationError, match="requires a module version"):
        import_magisk(source, tmp_path / "missing")

    document = complete_document()
    document["tool_versions"]["trustlab_magisk"] = "0.3.0"
    write_collection_manifest(document, source / COMPLETION_MANIFEST_NAME)
    with pytest.raises(SchemaValidationError, match="must match exactly"):
        import_magisk(source, tmp_path / "mismatch")

    document["collector"]["version"] = "2.0.0"
    document["tool_versions"]["trustlab_magisk"] = "2.0.0"
    write_collection_manifest(document, source / COMPLETION_MANIFEST_NAME)
    with pytest.raises(UnsupportedSchemaVersionError, match="collector major version"):
        import_magisk(source, tmp_path / "unsupported")

    document["collector"]["version"] = "0.9.0"
    document["tool_versions"]["trustlab_magisk"] = "0.9.0"
    write_collection_manifest(document, source / COMPLETION_MANIFEST_NAME)
    with pytest.raises(UnsupportedSchemaVersionError, match="collector version"):
        import_magisk(source, tmp_path / "unregistered")


def test_import_rejects_wrong_collector_and_missing_redaction(tmp_path):
    source, document = make_bundle(tmp_path)
    document["collector"]["name"] = "trustlab-fixture"
    document["observer"] = {
        "observer_type": "root_collector",
        "privilege_level": "root",
        "collection_method": "test_fixture",
    }
    document["environment"]["transport"] = "fixture"
    document["environment"]["execution_context"] = "test_fixture"
    document["tool_versions"] = {"trustlab_fixture": "0.3.0-dev0"}
    write_collection_manifest(document, source / COMPLETION_MANIFEST_NAME)
    with pytest.raises(SchemaValidationError, match="not a Magisk collection"):
        import_magisk(source, tmp_path / "wrong")

    document = complete_document()
    document["redaction_policy"]["redaction_state"] = "not_required"
    write_collection_manifest(document, source / COMPLETION_MANIFEST_NAME)
    with pytest.raises(SchemaValidationError, match="requires applied redaction"):
        import_magisk(source, tmp_path / "redaction")


@pytest.mark.parametrize(
    "path",
    ["../raw.txt", "/raw.txt", "captures\\raw.txt", "./raw.txt"],
)
def test_import_rejects_nonportable_artifact_paths(tmp_path, path):
    source, document = make_bundle(tmp_path)
    document["artifacts"][0]["relative_path"] = path
    write_json_unchecked(source / COMPLETION_MANIFEST_NAME, document)

    with pytest.raises(SchemaValidationError):
        import_magisk(source, tmp_path / "imports")


def test_import_rejects_duplicate_paths_and_duplicate_json_members(tmp_path):
    source, document = make_bundle(tmp_path)
    duplicate = copy.deepcopy(document["artifacts"][0])
    duplicate["logical_name"] = "other_observed_artifact"
    duplicate["probe_id"] = "magisk.other_observed_artifact"
    duplicate["media_type"] = "application/json"
    document["artifacts"].append(duplicate)
    write_json_unchecked(source / COMPLETION_MANIFEST_NAME, document)
    with pytest.raises(SchemaValidationError, match="paths must be unique"):
        import_magisk(source, tmp_path / "duplicate")

    source, document = make_bundle(tmp_path / "json")
    text = json.dumps(document)
    text = text.replace(
        '"schema_version": "1.0.0",',
        '"schema_version": "1.0.0", "schema_version": "1.0.0",',
        1,
    )
    (source / COMPLETION_MANIFEST_NAME).write_text(text, encoding="utf-8")
    with pytest.raises(InvalidJSONError):
        import_magisk(source, tmp_path / "duplicate-json")


def test_import_rejects_archive_and_interrupted_transfer(tmp_path):
    archive = tmp_path / "collection.zip"
    archive.write_bytes(b"PK\x03\x04hostile")
    with pytest.raises(CollectionError, match="archives are not extracted"):
        import_magisk(archive, tmp_path / "imports")

    interrupted = tmp_path / "interrupted"
    interrupted.mkdir()
    (interrupted / ".collector_manifest.tmp").write_text("{}", encoding="utf-8")
    with pytest.raises(MissingFileError, match="input not found"):
        import_magisk(interrupted, tmp_path / "imports")


def test_import_rejects_nonregular_and_symlink_parent_inputs(tmp_path):
    source = tmp_path / "nonregular"
    source.mkdir()
    (source / COMPLETION_MANIFEST_NAME).mkdir()
    with pytest.raises(CollectionError, match="manifest must be a regular file"):
        import_magisk(source, tmp_path / "directory-manifest-output")

    real_source, _document = make_bundle(tmp_path / "real")
    alias = tmp_path / "source-alias"
    alias.symlink_to(real_source, target_is_directory=True)
    with pytest.raises(CollectionError, match="root must not be a symlink"):
        import_magisk(alias / COMPLETION_MANIFEST_NAME, tmp_path / "alias-output")

    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "input-pipe"
        os.mkfifo(fifo)
        with pytest.raises(CollectionError, match="regular file or directory"):
            import_magisk(fifo, tmp_path / "fifo-output")


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        b"[]",
        b'{"value": NaN}',
        b'{"value": 1',
    ],
)
def test_import_rejects_invalid_completion_manifest_documents(tmp_path, payload):
    source = tmp_path / "source"
    source.mkdir()
    (source / COMPLETION_MANIFEST_NAME).write_bytes(payload)

    with pytest.raises((InvalidJSONError, SchemaValidationError)):
        import_magisk(source, tmp_path / "imports")


def test_import_rejects_symlinked_input_manifest_artifact_and_component(tmp_path):
    source, _document = make_bundle(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(source, target_is_directory=True)
    with pytest.raises(CollectionError, match="must not be a symlink"):
        import_magisk(alias, tmp_path / "alias-output")

    manifest = source / COMPLETION_MANIFEST_NAME
    manifest.unlink()
    manifest.symlink_to(SAMPLE_MANIFEST)
    with pytest.raises(CollectionError, match="manifest must not be a symlink"):
        import_magisk(source, tmp_path / "manifest-output")

    source, document = make_bundle(tmp_path / "artifact")
    raw = source / "raw_sample.txt"
    raw.unlink()
    raw.symlink_to(SAMPLE_RAW)
    with pytest.raises(CollectionError, match="must not contain symlinks"):
        import_magisk(source, tmp_path / "artifact-output")

    source, document = make_bundle(tmp_path / "component")
    document["artifacts"][0]["relative_path"] = "moved/raw_sample.txt"
    write_collection_manifest(document, source / COMPLETION_MANIFEST_NAME)
    (source / "raw_sample.txt").unlink()
    (source / "moved").symlink_to(SAMPLE_ROOT, target_is_directory=True)
    with pytest.raises(CollectionError, match="must not contain symlinks"):
        import_magisk(source, tmp_path / "component-output")


def test_import_rejects_undeclared_files_directories_and_special_files(tmp_path):
    source, _document = make_bundle(tmp_path)
    (source / "undeclared.txt").write_text("not bound", encoding="utf-8")
    with pytest.raises(CollectionError, match="undeclared file"):
        import_magisk(source, tmp_path / "file-output")

    (source / "undeclared.txt").unlink()
    (source / "undeclared").mkdir()
    with pytest.raises(CollectionError, match="undeclared directory"):
        import_magisk(source, tmp_path / "directory-output")

    if hasattr(os, "mkfifo"):
        (source / "undeclared").rmdir()
        os.mkfifo(source / "pipe")
        with pytest.raises(CollectionError, match="only regular files"):
            import_magisk(source, tmp_path / "fifo-output")


def test_import_rejects_hardlinked_manifest_and_artifacts(tmp_path):
    if not hasattr(os, "link"):
        pytest.skip("hard links are unavailable")
    source, document = make_bundle(tmp_path)
    manifest = source / COMPLETION_MANIFEST_NAME
    os.link(manifest, tmp_path / "manifest-hardlink.json")
    with pytest.raises(CollectionError, match="must not be hard linked"):
        import_magisk(source, tmp_path / "manifest-output")

    (tmp_path / "manifest-hardlink.json").unlink()
    other = copy.deepcopy(document["artifacts"][0])
    other.update(
        {
            "logical_name": "other_observed_artifact",
            "relative_path": "other_artifact.json",
            "media_type": "application/json",
            "probe_id": "magisk.other_observed_artifact",
        }
    )
    document["artifacts"].append(other)
    write_collection_manifest(document, manifest)
    os.link(source / "raw_sample.txt", source / "other_artifact.json")
    with pytest.raises(CollectionError, match="must not be hard linked"):
        import_magisk(source, tmp_path / "artifact-output")


def test_import_path_projection_rejects_case_reserved_and_prefix_collisions():
    manifest = CollectionManifest.from_dict(complete_document())
    raw, command = manifest.artifacts

    case_collision = replace(
        manifest,
        artifacts=(raw, replace(command, relative_path="RAW_SAMPLE.TXT")),
    )
    with pytest.raises(SchemaValidationError, match="case-insensitive"):
        magisk_importer._artifact_paths(case_collision)

    reserved = replace(
        manifest,
        artifacts=(replace(raw, relative_path="captures/CON.txt"), command),
    )
    with pytest.raises(SchemaValidationError, match="portably representable"):
        magisk_importer._artifact_paths(reserved)

    prefix = replace(
        manifest,
        artifacts=(
            replace(raw, relative_path="captures"),
            replace(command, relative_path="captures/result.json"),
        ),
    )
    with pytest.raises(SchemaValidationError, match="file-directory collisions"):
        magisk_importer._artifact_paths(prefix)

    import_reserved = replace(
        manifest,
        artifacts=(replace(raw, relative_path=NORMALIZED_REPORT_NAME), command),
    )
    with pytest.raises(SchemaValidationError, match="reserved import name"):
        magisk_importer._artifact_paths(import_reserved)

    with pytest.raises(SchemaValidationError, match="version is not semantic"):
        magisk_importer._version_major("v1", label="collector")


def test_dirfd_read_helpers_fail_closed(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "small").write_bytes(b"ab")
    (root / "component").write_bytes(b"file")
    descriptor = magisk_importer._open_source_root(root)
    try:
        with pytest.raises(CollectionError, match="normalized and relative"):
            magisk_importer._open_file_beneath(descriptor, "../escape")
        with pytest.raises(CollectionError, match="bundle is incomplete"):
            magisk_importer._open_file_beneath(descriptor, "missing")
        with pytest.raises(CollectionError, match="non-directory component"):
            magisk_importer._open_file_beneath(descriptor, "component/child")
        with pytest.raises(CollectionError, match="exceeds its byte limit"):
            magisk_importer._read_regular_file_beneath(
                descriptor,
                "small",
                limit=1,
            )
        if hasattr(os, "mkfifo"):
            os.mkfifo(root / "pipe")
            with pytest.raises(CollectionError, match="must be regular files"):
                magisk_importer._read_regular_file_beneath(
                    descriptor,
                    "pipe",
                    limit=1,
                )
    finally:
        os.close(descriptor)

    with pytest.raises(CollectionError, match="open Magisk import root safely"):
        magisk_importer._open_source_root(root / "missing")


def test_import_rejects_missing_changed_and_oversized_artifacts(tmp_path, monkeypatch):
    source, document = make_bundle(tmp_path)
    (source / "raw_sample.txt").unlink()
    with pytest.raises(CollectionError, match="incomplete"):
        import_magisk(source, tmp_path / "missing")

    shutil.copyfile(SAMPLE_RAW, source / "raw_sample.txt")
    (source / "raw_sample.txt").write_bytes(b"tampered")
    with pytest.raises(CollectionError, match="size mismatch"):
        import_magisk(source, tmp_path / "changed")

    shutil.copyfile(SAMPLE_RAW, source / "raw_sample.txt")
    monkeypatch.setattr(
        magisk_importer,
        "MAX_MAGISK_IMPORT_BYTES",
        document["artifacts"][0]["byte_size"] - 1,
    )
    with pytest.raises(CollectionError, match="total byte limit"):
        import_magisk(source, tmp_path / "oversized")


def test_import_rejects_excessive_tree_entries(tmp_path, monkeypatch):
    source, _document = make_bundle(tmp_path)
    monkeypatch.setattr(magisk_importer, "MAX_MAGISK_IMPORT_ENTRIES", 1)

    with pytest.raises(CollectionError, match="entry count limit"):
        import_magisk(source, tmp_path / "imports")


def test_verification_rejects_incomplete_and_aliased_typed_artifacts(
    tmp_path, monkeypatch
):
    manifest = CollectionManifest.from_dict(complete_document())
    raw, command = manifest.artifacts
    incomplete = replace(
        manifest,
        artifacts=(replace(raw, byte_size=None), command),
    )
    with pytest.raises(SchemaValidationError, match="artifact is incomplete"):
        magisk_importer._verify_payloads(incomplete, -1)

    payload = b"x"
    other = replace(
        command,
        logical_name="other_observed_artifact",
        relative_path="other_artifact.json",
        media_type="application/json",
        byte_size=1,
        sha256=hashlib.sha256(payload).hexdigest(),
        probe_id="magisk.other_observed_artifact",
        status=EvidenceStatus.OBSERVED,
        exit_code=0,
        redaction_state="redacted",
    )
    aliased = replace(
        manifest,
        artifacts=(
            replace(
                raw,
                byte_size=1,
                sha256=hashlib.sha256(payload).hexdigest(),
            ),
            other,
        ),
    )
    monkeypatch.setattr(
        magisk_importer,
        "_read_regular_file_beneath",
        lambda *_args, **_kwargs: (payload, (1, 1)),
    )
    with pytest.raises(CollectionError, match="must not alias one file"):
        magisk_importer._verify_payloads(aliased, -1)


def test_import_publishes_retained_snapshot_when_source_changes_after_verification(
    tmp_path, monkeypatch
):
    source, _document = make_bundle(tmp_path)
    original_copy = magisk_importer._copy_verified_bundle

    def mutate_then_copy(staging, manifest, verified, manifest_payload):
        (source / "raw_sample.txt").write_bytes(b"changed after verification")
        return original_copy(staging, manifest, verified, manifest_payload)

    monkeypatch.setattr(magisk_importer, "_copy_verified_bundle", mutate_then_copy)
    result = import_magisk(source, tmp_path / "imports")

    assert (result.directory / "raw_sample.txt").read_bytes() == SAMPLE_RAW.read_bytes()


@pytest.mark.parametrize("failure_point", ["normalize", "validate"])
def test_import_failure_cleans_staging_and_publishes_nothing(
    tmp_path, monkeypatch, failure_point
):
    source, _document = make_bundle(tmp_path)
    output = tmp_path / "imports"
    if failure_point == "normalize":
        monkeypatch.setattr(
            magisk_importer,
            "normalize_collection_payload",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                NormalizationError("failed")
            ),
        )
    else:
        monkeypatch.setattr(
            magisk_importer,
            "validate_report",
            lambda _report: (_ for _ in ()).throw(SchemaValidationError("failed")),
        )

    with pytest.raises((NormalizationError, SchemaValidationError)):
        import_magisk(source, output)

    assert list(output.glob("sha256-*")) == []
    assert list(output.glob(".trustlab-magisk-import-*")) == []
    assert not (output / IMPORT_LOCK_NAME).exists()


def test_import_interrupt_cleans_staging_and_lock(tmp_path, monkeypatch):
    source, _document = make_bundle(tmp_path)
    output = tmp_path / "imports"

    def interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(magisk_importer, "normalize_collection_payload", interrupt)
    with pytest.raises(KeyboardInterrupt):
        import_magisk(source, output)

    assert list(output.glob("sha256-*")) == []
    assert list(output.glob(".trustlab-magisk-import-*")) == []
    assert not (output / IMPORT_LOCK_NAME).exists()


def test_import_rejects_lock_collision_and_preserves_existing_destination(tmp_path):
    source, document = make_bundle(tmp_path)
    output = tmp_path / "imports"
    output.mkdir()
    lock = output / IMPORT_LOCK_NAME
    lock.write_text("held", encoding="utf-8")
    with pytest.raises(CollectionError, match="holds the output lock"):
        import_magisk(source, output)
    assert lock.read_text(encoding="utf-8") == "held"

    lock.unlink()
    digest = hashlib.sha256(canonical_json_bytes(document)).hexdigest()
    destination = output / f"sha256-{digest}"
    destination.mkdir()
    sentinel = destination / "sentinel"
    sentinel.write_text("preserve", encoding="utf-8")
    with pytest.raises(OutputWriteError, match="already exists"):
        import_magisk(source, output)
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert not lock.exists()


def test_lock_setup_and_publish_failures_leave_no_partial_import(tmp_path, monkeypatch):
    source, _document = make_bundle(tmp_path)
    output = tmp_path / "imports"
    output.mkdir()
    real_fchmod = getattr(os, "fchmod", None)
    if real_fchmod is not None:
        monkeypatch.setattr(
            os,
            "fchmod",
            lambda _descriptor, _mode: (_ for _ in ()).throw(OSError("denied")),
        )
        with pytest.raises(OutputWriteError, match="acquire Magisk import lock"):
            import_magisk(source, output)
        assert not (output / IMPORT_LOCK_NAME).exists()
        monkeypatch.setattr(os, "fchmod", real_fchmod)

    monkeypatch.setattr(
        magisk_importer,
        "_atomic_rename_noreplace",
        lambda _root, _source, _destination: (_ for _ in ()).throw(OSError("denied")),
    )
    with pytest.raises(OutputWriteError, match="publish Magisk import atomically"):
        import_magisk(source, output)
    assert list(output.glob("sha256-*")) == []
    assert list(output.glob(".trustlab-magisk-import-*")) == []
    assert not (output / IMPORT_LOCK_NAME).exists()


def test_atomic_publication_never_replaces_empty_destination(tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "evidence").write_text("verified", encoding="utf-8")
    destination = tmp_path / "destination"
    destination.mkdir()

    root_descriptor = os.open(tmp_path, magisk_importer._safe_directory_flags())
    try:
        with pytest.raises(FileExistsError):
            magisk_importer._atomic_rename_noreplace(
                root_descriptor,
                staging.name,
                destination.name,
            )
    finally:
        os.close(root_descriptor)

    assert staging.is_dir()
    assert (staging / "evidence").read_text(encoding="utf-8") == "verified"
    assert destination.is_dir()
    assert list(destination.iterdir()) == []


def test_output_root_swap_cannot_redirect_import(tmp_path, monkeypatch):
    source, _document = make_bundle(tmp_path)
    output = tmp_path / "imports"
    moved_output = tmp_path / "verified-output"
    alternate = tmp_path / "alternate"
    alternate.mkdir()
    real_acquire = magisk_importer._acquire_lock

    def swap_then_acquire(root_descriptor):
        output.rename(moved_output)
        output.symlink_to(alternate, target_is_directory=True)
        return real_acquire(root_descriptor)

    monkeypatch.setattr(magisk_importer, "_acquire_lock", swap_then_acquire)

    with pytest.raises(OutputWriteError, match="output changed during publication"):
        import_magisk(source, output)

    assert list(alternate.iterdir()) == []
    assert list(moved_output.iterdir()) == []
    assert output.is_symlink()


def test_import_rejects_symlinked_or_overlapping_output(tmp_path):
    source, _document = make_bundle(tmp_path)
    real_output = tmp_path / "real-output"
    real_output.mkdir()
    alias = tmp_path / "output-alias"
    alias.symlink_to(real_output, target_is_directory=True)
    with pytest.raises(CollectionError, match="output must not be a symlink"):
        import_magisk(source, alias)

    nested = source / "imports"
    with pytest.raises(CollectionError, match="must not overlap"):
        import_magisk(source, nested)
    assert not nested.exists()

    with pytest.raises(CollectionError, match="must not overlap"):
        import_magisk(source, tmp_path)


def test_platform_and_serialization_helpers_fail_closed(tmp_path, monkeypatch):
    with monkeypatch.context() as context:
        context.setattr(os, "supports_dir_fd", set())
        with pytest.raises(CollectionError, match="unsupported on this platform"):
            magisk_importer._safe_directory_flags()

    with monkeypatch.context() as context:
        context.setattr(magisk_importer.sys, "platform", "win32")
        context.setattr(magisk_importer.sys, "version_info", (3, 12))
        with pytest.raises(CollectionError, match="Python 3.13 or newer"):
            magisk_importer._prepare_output_root(
                tmp_path / "output", tmp_path / "source"
            )

    with pytest.raises(OutputWriteError, match="serialize Magisk import report"):
        magisk_importer._json_bytes({"invalid": complex(1, 2)})

    descriptor = os.open(tmp_path, magisk_importer._safe_directory_flags())
    os.close(descriptor)
    with pytest.raises(OutputWriteError, match="inspect Magisk import destination"):
        magisk_importer._entry_exists(descriptor, "missing")


def test_import_has_no_command_execution_surface():
    source = Path(magisk_importer.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "os.system" not in source
    assert "adb " not in source.lower()
    assert " su " not in source.lower()
