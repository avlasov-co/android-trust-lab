"""Strict dataset bundle loading, integrity checks, and freshness verification."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .collection_manifest import CollectionManifest
from .comparison import attach_comparison_context
from .diff import make_diff
from .exceptions import (
    CollectionError,
    InvalidJSONError,
    MissingFileError,
    SchemaValidationError,
    UnsupportedSchemaVersionError,
    safe_path_label,
)
from .normalizer import normalize_collection_payload, normalize_raw_bytes
from .validators import (
    validate_collection_manifest,
    validate_dataset_manifest,
    validate_dataset_source,
    validate_diff,
    validate_report,
)

MAX_DATASET_JSON_BYTES = 8 * 1024 * 1024
MAX_DATASET_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_DATASET_TOTAL_BYTES = 128 * 1024 * 1024
MAX_DATASET_TREE_ENTRIES = 100_000
MAX_DATASET_TREE_DEPTH = 32
ALLOWED_DATASET_DOCUMENTATION_PATHS = frozenset(
    {
        "README.md",
        "samples/magisk_collector/README.md",
        "samples/rooted_avd/README.md",
        "samples/stock_avd/README.md",
        "samples/writable_system_avd/README.md",
    }
)


@dataclass(frozen=True, slots=True)
class DatasetVerification:
    """Value-safe summary of a verified dataset bundle."""

    dataset_id: str
    dataset_version: str
    artifact_count: int
    sample_count: int
    diff_count: int


def stable_pretty_json_bytes(data: object) -> bytes:
    """Return the exact deterministic pretty-JSON representation for generated files."""

    return (
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _reject_constant(_value: str) -> None:
    raise ValueError("non-standard JSON constant")


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def parse_dataset_json(payload: bytes, *, label: str) -> dict[str, Any]:
    """Parse strict UTF-8 JSON while rejecting duplicates and non-finite values."""

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidJSONError(f"invalid UTF-8 JSON: {label}") from exc
    try:
        value = json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_object,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise InvalidJSONError(f"invalid JSON: {label}") from exc
    if not isinstance(value, dict):
        raise SchemaValidationError("dataset JSON document must be an object")
    return value


def _open_file_beneath(root: Path, relative_path: str, *, missing_label: str) -> int:
    """Open a non-symlink file beneath immutable directory handles."""

    pure_path = PurePosixPath(relative_path)
    if (
        pure_path.is_absolute()
        or relative_path != pure_path.as_posix()
        or "\\" in relative_path
        or ":" in relative_path
        or any(part in {"", ".", ".."} for part in pure_path.parts)
        or any(
            ord(character) < 32 or ord(character) == 127 for character in relative_path
        )
    ):
        raise CollectionError("dataset file path must remain normalized and relative")
    if (
        os.open not in os.supports_dir_fd
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise CollectionError(
            "safe non-symlink dataset file opening is unsupported on this platform"
        )

    parts = PurePosixPath(relative_path).parts
    if not parts:
        raise CollectionError("dataset input path must name a file")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    file_flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptors: list[int] = []
    try:
        current = os.open(root, directory_flags)
        descriptors.append(current)
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        return os.open(parts[-1], file_flags, dir_fd=current)
    except FileNotFoundError as exc:
        raise MissingFileError(f"input file not found: {missing_label}") from exc
    except OSError as exc:
        raise CollectionError(
            "dataset artifact path contains a non-directory or symlink"
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def read_regular_file_beneath(
    root: Path,
    relative_path: str,
    *,
    limit: int,
    label: str,
) -> bytes:
    """Read one bounded regular file using a no-follow directory walk."""

    descriptor = _open_file_beneath(root, relative_path, missing_label=label)
    chunks: list[bytes] = []
    byte_count = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CollectionError(f"input must be a regular non-symlink file: {label}")
        if metadata.st_size > limit:
            raise CollectionError(f"input exceeds verification limit: {label}")
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            byte_count += len(chunk)
            if byte_count > limit:
                raise CollectionError(f"input exceeds verification limit: {label}")
            chunks.append(chunk)
    except CollectionError:
        raise
    except OSError as exc:
        raise CollectionError(f"could not read input: {label}") from exc
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _read_artifact(bundle_root: Path, artifact: dict[str, Any]) -> bytes:
    expected_size = artifact["byte_size"]
    if expected_size > MAX_DATASET_ARTIFACT_BYTES:
        raise CollectionError("dataset artifact exceeds verification limit")
    payload = read_regular_file_beneath(
        bundle_root,
        artifact["relative_path"],
        limit=MAX_DATASET_ARTIFACT_BYTES,
        label="dataset artifact",
    )
    if len(payload) != expected_size:
        raise CollectionError("dataset artifact byte size mismatch")
    if hashlib.sha256(payload).hexdigest() != artifact["sha256"]:
        raise CollectionError("dataset artifact digest mismatch")
    return payload


def _source_as_manifest(
    source: dict[str, Any], artifact_payloads: dict[str, bytes]
) -> dict[str, Any]:
    expected = deepcopy(source)
    expected["schema_version"] = "2.0.0"
    expected["artifacts"] = [
        {
            **artifact,
            "byte_size": len(artifact_payloads[artifact["artifact_id"]]),
            "sha256": hashlib.sha256(
                artifact_payloads[artifact["artifact_id"]]
            ).hexdigest(),
        }
        for artifact in source["artifacts"]
    ]
    return expected


def _validate_intrinsic_artifacts(
    manifest: dict[str, Any], payloads: dict[str, bytes]
) -> dict[str, dict[str, Any]]:
    parsed: dict[str, dict[str, Any]] = {}
    for artifact in manifest["artifacts"]:
        role = artifact["role"]
        if role == "raw_artifact":
            try:
                payloads[artifact["artifact_id"]].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CollectionError(
                    "raw dataset artifact is not valid UTF-8"
                ) from exc
            continue
        document = parse_dataset_json(
            payloads[artifact["artifact_id"]], label="dataset artifact"
        )
        parsed[artifact["artifact_id"]] = document
        if role == "declarative_source":
            validate_dataset_source(document)
        elif role == "collection_manifest":
            validate_collection_manifest(document)
        elif role == "normalized_report":
            validate_report(document)
        elif role == "derived_diff":
            validate_diff(document)
    return parsed


def validate_dataset_collection_relationships(
    manifest: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    documents: dict[str, dict[str, Any]],
) -> None:
    for sample in manifest["samples"]:
        relationship = sample["collection_manifest"]
        if relationship["status"] != "observed":
            continue
        collection_id = relationship["artifact_id"]
        collection = documents[collection_id]
        raw_artifact = artifacts[sample["raw_artifact_id"]]
        raw_entries = [
            entry
            for entry in collection["artifacts"]
            if entry["logical_name"] == "raw_report" and entry["status"] == "observed"
        ]
        observed_entries = [
            entry for entry in collection["artifacts"] if entry["status"] == "observed"
        ]
        collection_artifact = artifacts[collection_id]
        expected_raw_path = (
            (
                PurePosixPath(collection_artifact["relative_path"]).parent
                / raw_entries[0]["relative_path"]
            ).as_posix()
            if len(raw_entries) == 1
            else None
        )
        if (
            len(raw_entries) != 1
            or observed_entries != raw_entries
            or expected_raw_path != raw_artifact["relative_path"]
            or raw_entries[0]["byte_size"] != raw_artifact["byte_size"]
            or raw_entries[0]["sha256"] != raw_artifact["sha256"]
            or collection["experiment_id"] != sample["experiment_id"]
            or collection["observer"]["observer_type"] != sample["observer_type"]
            or collection["observer"]["collection_method"]
            != sample["collection_method"]
            or collection["target"]["target_type"] != sample["target_type"]
            or collection["ended_at"] != sample["collection_timestamp"]
            or (
                sample["origin_classification"] != "synthetic"
                and (
                    collection["collector"]["version"]
                    != collection_artifact["producer"]["version"]
                    or collection["collector"]["name"]
                    != collection_artifact["producer"]["name"]
                )
            )
            or raw_entries[0]["media_type"] != raw_artifact["media_type"]
            or raw_entries[0]["redaction_state"] != raw_artifact["redaction_state"]
            or (
                collection["redaction_policy"]["redaction_state"] == "applied"
                and collection_artifact["redaction_state"]
                not in {"redacted", "verified"}
            )
            or (
                collection["redaction_policy"]["redaction_state"] == "not_required"
                and collection_artifact["redaction_state"] != "not_required"
            )
            or (
                manifest["redaction"]["status"] in {"applied", "verified"}
                and collection["redaction_policy"]["policy_id"]
                != manifest["redaction"]["policy_id"]
            )
            or (
                sample["origin_classification"] == "physical_captured"
                and collection["redaction_policy"]["redaction_state"] != "applied"
            )
        ):
            raise SchemaValidationError(
                "dataset collection relationship does not match its sample or raw artifact"
            )


def _validate_freshness(
    manifest: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    payloads: dict[str, bytes],
    documents: dict[str, dict[str, Any]],
) -> None:
    reports: dict[str, dict[str, Any]] = {}
    for sample in manifest["samples"]:
        raw = artifacts[sample["raw_artifact_id"]]
        collection_relationship = sample["collection_manifest"]
        if collection_relationship["status"] == "observed":
            collection = CollectionManifest.from_dict(
                documents[collection_relationship["artifact_id"]]
            )
            expected = normalize_collection_payload(
                payloads[raw["artifact_id"]],
                collection,
                label=PurePosixPath(raw["relative_path"]).name,
            )
        else:
            expected = normalize_raw_bytes(
                payloads[raw["artifact_id"]],
                label=PurePosixPath(raw["relative_path"]).name,
                experiment_id=sample["experiment_id"],
                target_type=sample["target_type"],
                observer_type=sample["observer_type"],
                collection_method=sample["collection_method"],
                collection_timestamp=sample["collection_timestamp"],
                raw_artifact_ref=f"datasets/{raw['relative_path']}",
                raw_artifact_id=raw["artifact_id"],
                collector_name=raw["producer"]["name"],
                collector_version=raw["producer"]["version"],
                collection_id=None,
                redaction_state=raw["redaction_state"],
                media_type=raw["media_type"],
                expected_sha256=raw["sha256"],
                expected_byte_size=raw["byte_size"],
            )
        validate_report(expected)
        report_id = sample["normalized_report_artifact_id"]
        producer = artifacts[report_id]["producer"]
        normalizer = expected["provenance"]["normalizer"]
        if (
            producer["name"] != normalizer["name"]
            or producer["version"] != normalizer["version"]
        ):
            raise SchemaValidationError(
                "dataset report producer does not match report provenance"
            )
        if stable_pretty_json_bytes(expected) != payloads[report_id]:
            expected = attach_comparison_context(
                expected,
                target_pseudonym=(
                    f"target-{sample['origin_classification'].replace('_', '-')}-"
                    f"{sample['target_type']}"
                ),
                state_id=f"state-{sample['experiment_id'].lower().replace('_', '-')}",
                environment_context=sample["origin_classification"],
            )
            validate_report(expected)
            if stable_pretty_json_bytes(expected) != payloads[report_id]:
                raise CollectionError("normalized dataset report is stale")
        reports[sample["sample_id"]] = expected

    for derivation in manifest["derived_diffs"]:
        expected = make_diff(
            reports[derivation["base_sample_id"]],
            reports[derivation["compare_sample_id"]],
            allow_mixed=(
                derivation["derivation_id"] == "rooted-adb-vs-magisk-root-collector"
            ),
        )
        validate_diff(expected)
        if stable_pretty_json_bytes(expected) != payloads[derivation["artifact_id"]]:
            raise CollectionError("derived dataset diff is stale")


def _validate_no_unbound_evidence(bundle_root: Path, manifest: dict[str, Any]) -> None:
    bound = {artifact["relative_path"] for artifact in manifest["artifacts"]}
    observed: set[str] = set()
    entry_count = 0

    def reject_walk_error(error: OSError) -> None:
        raise CollectionError("could not inspect dataset evidence tree") from error

    for current_root, directory_names, file_names in os.walk(
        bundle_root,
        followlinks=False,
        onerror=reject_walk_error,
    ):
        current = Path(current_root)
        if len(current.relative_to(bundle_root).parts) > MAX_DATASET_TREE_DEPTH:
            raise CollectionError("dataset evidence tree exceeds depth limit")
        entry_count += len(directory_names) + len(file_names)
        if entry_count > MAX_DATASET_TREE_ENTRIES:
            raise CollectionError("dataset evidence tree exceeds entry limit")
        for name in directory_names:
            if (current / name).is_symlink():
                raise CollectionError("dataset evidence tree contains a symlink")
        for name in file_names:
            path = current / name
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise CollectionError(
                    "could not inspect dataset evidence tree"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise CollectionError("dataset evidence tree contains a symlink")
            if not stat.S_ISREG(metadata.st_mode):
                raise CollectionError(
                    "dataset evidence tree contains a non-regular file"
                )
            relative_path = path.relative_to(bundle_root).as_posix()
            if relative_path not in (
                ALLOWED_DATASET_DOCUMENTATION_PATHS | {"manifest.json"}
            ):
                observed.add(relative_path)
    if observed != bound:
        raise SchemaValidationError(
            "dataset evidence tree contains missing or unbound artifacts"
        )


def verify_dataset_manifest(path: str | Path) -> DatasetVerification:
    """Verify all bindings and deterministic derivations in one v2 dataset bundle."""

    manifest_path = Path(path)
    manifest_name = manifest_path.name
    if not manifest_name:
        raise CollectionError("dataset manifest path must name a file")
    manifest_payload = read_regular_file_beneath(
        manifest_path.parent.resolve(),
        manifest_name,
        limit=MAX_DATASET_JSON_BYTES,
        label=safe_path_label(manifest_path),
    )
    manifest = parse_dataset_json(
        manifest_payload, label=safe_path_label(manifest_path)
    )
    validate_dataset_manifest(manifest)
    if manifest.get("schema_version") != "2.0.0":
        raise UnsupportedSchemaVersionError(
            "dataset verification requires dataset manifest schema version 2.0.0"
        )

    bundle_root = manifest_path.parent.resolve()
    artifacts = {
        artifact["artifact_id"]: artifact for artifact in manifest["artifacts"]
    }
    if sum(artifact["byte_size"] for artifact in artifacts.values()) > (
        MAX_DATASET_TOTAL_BYTES
    ):
        raise CollectionError("dataset artifacts exceed cumulative verification limit")
    payloads = {
        artifact_id: _read_artifact(bundle_root, artifact)
        for artifact_id, artifact in artifacts.items()
    }
    documents = _validate_intrinsic_artifacts(manifest, payloads)
    source = documents[manifest["declarative_source_artifact_id"]]
    if _source_as_manifest(source, payloads) != manifest:
        raise CollectionError("dataset manifest is stale relative to its source")
    validate_dataset_collection_relationships(manifest, artifacts, documents)
    _validate_freshness(manifest, artifacts, payloads, documents)
    _validate_no_unbound_evidence(bundle_root, manifest)
    return DatasetVerification(
        dataset_id=manifest["dataset_id"],
        dataset_version=manifest["dataset_version"],
        artifact_count=len(artifacts),
        sample_count=len(manifest["samples"]),
        diff_count=len(manifest["derived_diffs"]),
    )
