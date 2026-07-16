"""Typed collection-manifest models and portable artifact verification."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .compatibility import EvidenceStatus
from .exceptions import CollectionError, SchemaValidationError, safe_path_label
from .report_writer import load_json, write_json
from .validators import validate_collection_manifest

MAX_COLLECTION_ARTIFACT_BYTES = 64 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class CollectorMetadata:
    name: str
    version: str


@dataclass(frozen=True, slots=True)
class ObserverMetadata:
    observer_type: str
    privilege_level: str
    collection_method: str


@dataclass(frozen=True, slots=True)
class TargetMetadata:
    pseudonymous_id: str
    target_type: str


@dataclass(frozen=True, slots=True)
class EnvironmentMetadata:
    platform: str
    transport: str
    execution_context: str


@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    policy_id: str
    redaction_state: str
    direct_identifiers_removed: bool
    serials_removed: bool
    secrets_removed: bool


@dataclass(frozen=True, slots=True)
class ArtifactEntry:
    logical_name: str
    relative_path: str | None
    media_type: str
    byte_size: int | None
    sha256: str | None
    probe_id: str
    status: EvidenceStatus
    exit_code: int | None
    timed_out: bool
    sensitivity: str
    redaction_state: str
    detail: str | None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ArtifactEntry:
        return cls(
            logical_name=data["logical_name"],
            relative_path=data["relative_path"],
            media_type=data["media_type"],
            byte_size=data["byte_size"],
            sha256=data["sha256"],
            probe_id=data["probe_id"],
            status=EvidenceStatus(data["status"]),
            exit_code=data["exit_code"],
            timed_out=data["timed_out"],
            sensitivity=data["sensitivity"],
            redaction_state=data["redaction_state"],
            detail=data["detail"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_name": self.logical_name,
            "relative_path": self.relative_path,
            "media_type": self.media_type,
            "byte_size": self.byte_size,
            "sha256": self.sha256,
            "probe_id": self.probe_id,
            "status": self.status,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "sensitivity": self.sensitivity,
            "redaction_state": self.redaction_state,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class CollectionManifest:
    collection_id: str
    schema_version: str
    experiment_id: str
    collector: CollectorMetadata
    observer: ObserverMetadata
    target: TargetMetadata
    started_at: str
    ended_at: str
    completion_status: str
    tool_versions: Mapping[str, str]
    environment: EnvironmentMetadata
    warnings: tuple[str, ...]
    redaction_policy: RedactionPolicy
    artifacts: tuple[ArtifactEntry, ...]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CollectionManifest:
        validate_collection_manifest(data)
        collector = data["collector"]
        observer = data["observer"]
        target = data["target"]
        environment = data["environment"]
        redaction = data["redaction_policy"]
        return cls(
            collection_id=data["collection_id"],
            schema_version=data["schema_version"],
            experiment_id=data["experiment_id"],
            collector=CollectorMetadata(**collector),
            observer=ObserverMetadata(**observer),
            target=TargetMetadata(**target),
            started_at=data["started_at"],
            ended_at=data["ended_at"],
            completion_status=data["completion_status"],
            tool_versions=MappingProxyType(dict(data["tool_versions"])),
            environment=EnvironmentMetadata(**environment),
            warnings=tuple(data["warnings"]),
            redaction_policy=RedactionPolicy(**redaction),
            artifacts=tuple(
                ArtifactEntry.from_dict(item) for item in data["artifacts"]
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "collection_id": self.collection_id,
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "collector": {
                "name": self.collector.name,
                "version": self.collector.version,
            },
            "observer": {
                "observer_type": self.observer.observer_type,
                "privilege_level": self.observer.privilege_level,
                "collection_method": self.observer.collection_method,
            },
            "target": {
                "pseudonymous_id": self.target.pseudonymous_id,
                "target_type": self.target.target_type,
            },
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "completion_status": self.completion_status,
            "tool_versions": dict(self.tool_versions),
            "environment": {
                "platform": self.environment.platform,
                "transport": self.environment.transport,
                "execution_context": self.environment.execution_context,
            },
            "warnings": list(self.warnings),
            "redaction_policy": {
                "policy_id": self.redaction_policy.policy_id,
                "redaction_state": self.redaction_policy.redaction_state,
                "direct_identifiers_removed": (
                    self.redaction_policy.direct_identifiers_removed
                ),
                "serials_removed": self.redaction_policy.serials_removed,
                "secrets_removed": self.redaction_policy.secrets_removed,
            },
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
        }


@dataclass(frozen=True, slots=True)
class VerifiedArtifact:
    """One artifact path plus an optional exact verified byte snapshot."""

    path: Path
    payload: bytes | None


def _resolve_artifact_path(base: Path, relative_path: str) -> tuple[Path, Path]:
    lexical_candidate = base.joinpath(*Path(relative_path).parts)
    candidate = lexical_candidate.resolve(strict=False)
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise CollectionError(
            "collection artifact escapes the manifest directory"
        ) from exc
    current = base
    try:
        for part in Path(relative_path).parts:
            current /= part
            if current.is_symlink():
                raise CollectionError(
                    "collection artifact paths must not contain symlinks"
                )
    except OSError as exc:
        raise CollectionError(
            f"could not inspect collection artifact: {safe_path_label(candidate)}"
        ) from exc
    return lexical_candidate, candidate


def _open_artifact(lexical_candidate: Path, candidate: Path) -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        return os.open(lexical_candidate, flags)
    except FileNotFoundError as exc:
        raise CollectionError(
            f"collection artifact not found: {safe_path_label(candidate)}"
        ) from exc
    except OSError as exc:
        raise CollectionError(
            f"could not open collection artifact: {safe_path_label(candidate)}"
        ) from exc


def _verify_open_artifact(
    descriptor: int,
    artifact: ArtifactEntry,
    candidate: Path,
    *,
    retain_payload: bool,
) -> VerifiedArtifact:
    if artifact.byte_size is None or artifact.sha256 is None:
        raise SchemaValidationError("observed collection artifact is incomplete")
    retained = bytearray() if retain_payload else None
    digest = hashlib.sha256()
    byte_count = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CollectionError("collection artifacts must be regular files")
        if metadata.st_size != artifact.byte_size:
            raise CollectionError(
                f"collection artifact size mismatch: {safe_path_label(candidate)}"
            )
        if metadata.st_size > MAX_COLLECTION_ARTIFACT_BYTES:
            raise CollectionError("collection artifact exceeds the verification limit")
        while True:
            chunk = os.read(descriptor, _READ_CHUNK_BYTES)
            if not chunk:
                break
            byte_count += len(chunk)
            if byte_count > artifact.byte_size:
                raise CollectionError(
                    f"collection artifact size mismatch: {safe_path_label(candidate)}"
                )
            digest.update(chunk)
            if retained is not None:
                retained.extend(chunk)
    except OSError as exc:
        raise CollectionError(
            f"could not read collection artifact: {safe_path_label(candidate)}"
        ) from exc
    finally:
        os.close(descriptor)
    if byte_count != artifact.byte_size:
        raise CollectionError(
            f"collection artifact size mismatch: {safe_path_label(candidate)}"
        )
    if digest.hexdigest() != artifact.sha256:
        raise CollectionError(
            f"collection artifact digest mismatch: {safe_path_label(candidate)}"
        )
    return VerifiedArtifact(
        path=candidate,
        payload=bytes(retained) if retained is not None else None,
    )


def read_collection_manifest(path: str | Path) -> CollectionManifest:
    """Read and validate one strict collection manifest."""

    return CollectionManifest.from_dict(load_json(path))


def write_collection_manifest(
    manifest: CollectionManifest | dict[str, Any], path: str | Path
) -> None:
    """Validate and atomically write one collection manifest."""

    data = manifest.to_dict() if isinstance(manifest, CollectionManifest) else manifest
    validate_collection_manifest(data)
    write_json(data, path)


def verify_collection_artifacts(
    manifest: CollectionManifest,
    manifest_path: str | Path,
    *,
    retain_payloads: frozenset[str] = frozenset(),
) -> dict[str, VerifiedArtifact]:
    """Verify bounded regular artifacts, optionally retaining exact bytes."""

    manifest_file = Path(manifest_path)
    base = manifest_file.parent.resolve()
    verified: dict[str, VerifiedArtifact] = {}
    for artifact in manifest.artifacts:
        if artifact.status is not EvidenceStatus.OBSERVED:
            continue
        if (
            artifact.relative_path is None
            or artifact.byte_size is None
            or artifact.sha256 is None
        ):
            raise SchemaValidationError("observed collection artifact is incomplete")
        if artifact.byte_size > MAX_COLLECTION_ARTIFACT_BYTES:
            raise CollectionError("collection artifact exceeds the verification limit")
        lexical_candidate, candidate = _resolve_artifact_path(
            base, artifact.relative_path
        )
        verified[artifact.logical_name] = _verify_open_artifact(
            _open_artifact(lexical_candidate, candidate),
            artifact,
            candidate,
            retain_payload=artifact.logical_name in retain_payloads,
        )
    return verified
