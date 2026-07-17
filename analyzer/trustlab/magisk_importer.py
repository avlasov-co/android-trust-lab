"""Verify and atomically import one hostile Magisk collection bundle."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .artifacts import ADAPTERS, InputKind
from .canonical_json import canonical_json_bytes
from .collection_manifest import CollectionManifest
from .compatibility import EvidenceStatus
from .exceptions import (
    CollectionError,
    InvalidJSONError,
    MissingFileError,
    OutputWriteError,
    SchemaValidationError,
    UnsupportedSchemaVersionError,
    safe_path_label,
)
from .normalizer import normalize_collection_payload
from .validators import validate_report

COMPLETION_MANIFEST_NAME = "collector_manifest.json"
NORMALIZED_REPORT_NAME = "trust_report.json"
IMPORT_LOCK_NAME = ".trustlab-magisk-import.lock"
CONTENT_ADDRESS_PREFIX = "sha256-"
MAX_MAGISK_IMPORT_BYTES = 128 * 1024 * 1024
MAX_MAGISK_MANIFEST_BYTES = 1024 * 1024
MAX_MAGISK_IMPORT_ENTRIES = 512
MAX_MAGISK_IMPORT_DEPTH = 16
SUPPORTED_MAGISK_MAJOR_VERSIONS = frozenset({0, 1})

_VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$"
)
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
_RENAME_NOREPLACE = 1
_DARWIN_RENAME_EXCL = 0x00000004


@dataclass(frozen=True, slots=True)
class MagiskImportResult:
    """Published paths for one content-addressed Magisk import."""

    content_id: str
    directory: Path
    manifest_path: Path
    report_path: Path


def _path_metadata(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except FileNotFoundError as exc:
        raise MissingFileError(
            f"Magisk import input not found: {safe_path_label(path)}"
        ) from exc
    except OSError as exc:
        raise CollectionError(
            f"could not inspect Magisk import input: {safe_path_label(path)}"
        ) from exc


def _resolve_input(input_path: str | Path) -> tuple[Path, Path]:
    source = Path(input_path)
    metadata = _path_metadata(source)
    if stat.S_ISLNK(metadata.st_mode):
        raise CollectionError("Magisk import input must not be a symlink")
    if stat.S_ISDIR(metadata.st_mode):
        root = source
        manifest_path = root / COMPLETION_MANIFEST_NAME
    elif stat.S_ISREG(metadata.st_mode):
        if source.name != COMPLETION_MANIFEST_NAME:
            raise CollectionError(
                "Magisk import accepts only an unpacked collection directory or "
                "collector_manifest.json; archives are not extracted"
            )
        root = source.parent
        if root.is_symlink():
            raise CollectionError("Magisk import root must not be a symlink")
        manifest_path = source
    else:
        raise CollectionError("Magisk import input must be a regular file or directory")

    manifest_metadata = _path_metadata(manifest_path)
    if stat.S_ISLNK(manifest_metadata.st_mode):
        raise CollectionError("Magisk completion manifest must not be a symlink")
    if not stat.S_ISREG(manifest_metadata.st_mode):
        raise CollectionError("Magisk completion manifest must be a regular file")
    try:
        return root.resolve(strict=True), manifest_path.resolve(strict=True)
    except OSError as exc:
        raise CollectionError("could not resolve Magisk import input") from exc


def _version_major(value: str, *, label: str) -> int:
    match = _VERSION_RE.fullmatch(value)
    if match is None:
        raise SchemaValidationError(f"Magisk {label} version is not semantic")
    major = int(match.group(1))
    if major not in SUPPORTED_MAGISK_MAJOR_VERSIONS:
        raise UnsupportedSchemaVersionError(f"unsupported Magisk {label} major version")
    return major


def _validate_magisk_contract(manifest: CollectionManifest) -> None:
    if manifest.collector.name != "trustlab-magisk":
        raise SchemaValidationError("imported collection is not a Magisk collection")
    if manifest.completion_status != "complete":
        raise CollectionError("Magisk import requires a complete collection")
    if manifest.redaction_policy.redaction_state != "applied":
        raise SchemaValidationError("Magisk import requires applied redaction")

    module_version = manifest.tool_versions.get("trustlab_magisk")
    if module_version is None:
        raise SchemaValidationError("Magisk import requires a module version")
    collector_major = _version_major(
        manifest.collector.version,
        label="collector",
    )
    module_major = _version_major(module_version, label="module")
    if module_version != manifest.collector.version or module_major != collector_major:
        raise SchemaValidationError(
            "Magisk collector and module versions must match exactly"
        )
    adapter = ADAPTERS[InputKind.MAGISK_COLLECTION_MANIFEST]
    if manifest.collector.version not in adapter.supported_collector_versions:
        raise UnsupportedSchemaVersionError("unsupported Magisk collector version")
    raw_reports = [
        artifact
        for artifact in manifest.artifacts
        if artifact.logical_name == "raw_report"
        and artifact.media_type == "text/plain"
        and artifact.status is EvidenceStatus.OBSERVED
    ]
    if len(raw_reports) != 1:
        raise SchemaValidationError(
            "Magisk import requires one observed text raw_report artifact"
        )


def _artifact_paths(manifest: CollectionManifest) -> tuple[PurePosixPath, ...]:
    paths = tuple(
        PurePosixPath(artifact.relative_path)
        for artifact in manifest.artifacts
        if artifact.relative_path is not None
    )
    folded = [path.as_posix().casefold() for path in paths]
    if len(folded) != len(set(folded)):
        raise SchemaValidationError(
            "Magisk artifact paths must remain unique on case-insensitive filesystems"
        )
    reserved = {
        COMPLETION_MANIFEST_NAME.casefold(),
        NORMALIZED_REPORT_NAME.casefold(),
    }
    if any(
        len(part.encode("utf-8")) > 255
        or part.rstrip(". ").casefold().split(".", 1)[0] in _WINDOWS_RESERVED_NAMES
        for path in paths
        for part in path.parts
    ):
        raise SchemaValidationError(
            "Magisk artifact path is not portably representable"
        )
    if any(path.as_posix().casefold() in reserved for path in paths):
        raise SchemaValidationError("Magisk artifact path uses a reserved import name")
    path_strings = {path.as_posix() for path in paths}
    for path in paths:
        if any(parent.as_posix() in path_strings for parent in path.parents[:-1]):
            raise SchemaValidationError(
                "Magisk artifact paths must not contain file-directory collisions"
            )
    return paths


def _expected_directories(paths: tuple[PurePosixPath, ...]) -> frozenset[str]:
    return frozenset(
        parent.as_posix()
        for path in paths
        for parent in path.parents[:-1]
        if parent.as_posix() != "."
    )


def _scan_closed_bundle(
    root_descriptor: int,
    artifact_paths: tuple[PurePosixPath, ...],
) -> None:
    expected_files = {
        COMPLETION_MANIFEST_NAME,
        *(path.as_posix() for path in artifact_paths),
    }
    expected_directories = _expected_directories(artifact_paths)
    found_files: set[str] = set()
    entry_count = 0
    pending: list[tuple[int, PurePosixPath, int]] = [
        (os.dup(root_descriptor), PurePosixPath("."), 0)
    ]
    try:
        while pending:
            directory_descriptor, relative_directory, depth = pending.pop()
            try:
                try:
                    with os.scandir(directory_descriptor) as iterator:
                        for entry in iterator:
                            entry_count += 1
                            if entry_count > MAX_MAGISK_IMPORT_ENTRIES:
                                raise CollectionError(
                                    "Magisk import exceeds the entry count limit"
                                )
                            relative = (
                                PurePosixPath(entry.name)
                                if relative_directory.as_posix() == "."
                                else relative_directory / entry.name
                            )
                            relative_name = relative.as_posix()
                            try:
                                metadata = entry.stat(follow_symlinks=False)
                            except OSError as exc:
                                raise CollectionError(
                                    "could not inspect Magisk import entry"
                                ) from exc
                            if stat.S_ISLNK(metadata.st_mode):
                                raise CollectionError(
                                    "Magisk import bundles must not contain symlinks"
                                )
                            if stat.S_ISDIR(metadata.st_mode):
                                if relative_name not in expected_directories:
                                    raise CollectionError(
                                        "Magisk import bundle contains an undeclared "
                                        "directory"
                                    )
                                if depth + 1 > MAX_MAGISK_IMPORT_DEPTH:
                                    raise CollectionError(
                                        "Magisk import exceeds the directory depth limit"
                                    )
                                try:
                                    child_descriptor = os.open(
                                        entry.name,
                                        _safe_directory_flags(),
                                        dir_fd=directory_descriptor,
                                    )
                                except OSError as exc:
                                    raise CollectionError(
                                        "Magisk import directory changed during inspection"
                                    ) from exc
                                pending.append((child_descriptor, relative, depth + 1))
                            elif stat.S_ISREG(metadata.st_mode):
                                if relative_name not in expected_files:
                                    raise CollectionError(
                                        "Magisk import bundle contains an undeclared file"
                                    )
                                found_files.add(relative_name)
                            else:
                                raise CollectionError(
                                    "Magisk import bundles must contain only regular "
                                    "files and directories"
                                )
                except OSError as exc:
                    raise CollectionError(
                        "could not inspect Magisk import bundle"
                    ) from exc
            finally:
                os.close(directory_descriptor)
    finally:
        for directory_descriptor, _relative, _depth in pending:
            os.close(directory_descriptor)
    if found_files != expected_files:
        raise CollectionError("Magisk import bundle is incomplete")


def _safe_directory_flags() -> int:
    if (
        os.open not in os.supports_dir_fd
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise CollectionError(
            "safe no-follow Magisk import is unsupported on this platform"
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_source_root(root: Path) -> int:
    descriptor = -1
    try:
        descriptor = os.open(root, _safe_directory_flags())
        metadata = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise CollectionError("could not open Magisk import root safely") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise CollectionError("Magisk import root must be a directory")
    return descriptor


def _open_file_beneath(root_descriptor: int, relative_path: str) -> int:
    parts = PurePosixPath(relative_path).parts
    if (
        not parts
        or PurePosixPath(relative_path).is_absolute()
        or relative_path != PurePosixPath(relative_path).as_posix()
        or any(part in {"", ".", ".."} for part in parts)
        or "\\" in relative_path
        or ":" in relative_path
        or any(
            ord(character) < 32 or ord(character) == 127 for character in relative_path
        )
    ):
        raise CollectionError("Magisk import path must remain normalized and relative")
    directory_flags = _safe_directory_flags()
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    file_flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptors: list[int] = []
    try:
        current = os.dup(root_descriptor)
        descriptors.append(current)
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        return os.open(parts[-1], file_flags, dir_fd=current)
    except FileNotFoundError as exc:
        raise CollectionError("Magisk import bundle is incomplete") from exc
    except OSError as exc:
        raise CollectionError(
            "Magisk artifact path contains a symlink or non-directory component"
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_regular_file_beneath(
    root_descriptor: int,
    relative_path: str,
    *,
    limit: int,
) -> tuple[bytes, tuple[int, int]]:
    descriptor = _open_file_beneath(root_descriptor, relative_path)
    chunks: list[bytes] = []
    byte_count = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CollectionError("Magisk import entries must be regular files")
        if before.st_nlink != 1:
            raise CollectionError("Magisk import files must not be hard linked")
        if before.st_size > limit:
            raise CollectionError("Magisk import file exceeds its byte limit")
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, (limit + 1) - byte_count))
            if not chunk:
                break
            chunks.append(chunk)
            byte_count += len(chunk)
            if byte_count > limit:
                raise CollectionError("Magisk import file exceeds its byte limit")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or byte_count != after.st_size:
            raise CollectionError("Magisk import was interrupted while reading input")
        return b"".join(chunks), (after.st_dev, after.st_ino)
    except OSError as exc:
        raise CollectionError("could not read Magisk import file") from exc
    finally:
        os.close(descriptor)


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-standard JSON constant")


def _reject_duplicate_json_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def _read_manifest(root_descriptor: int) -> tuple[bytes, CollectionManifest]:
    payload, _identity = _read_regular_file_beneath(
        root_descriptor,
        COMPLETION_MANIFEST_NAME,
        limit=MAX_MAGISK_MANIFEST_BYTES,
    )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidJSONError("Magisk completion manifest is not valid UTF-8") from exc
    try:
        document = json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_json_members,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise InvalidJSONError("Magisk completion manifest is not valid JSON") from exc
    if not isinstance(document, dict):
        raise SchemaValidationError("Magisk completion manifest must be an object")
    return payload, CollectionManifest.from_dict(document)


def _verify_payloads(
    manifest: CollectionManifest,
    root_descriptor: int,
) -> dict[str, bytes]:
    total_size = sum(
        artifact.byte_size or 0
        for artifact in manifest.artifacts
        if artifact.relative_path is not None
    )
    if total_size > MAX_MAGISK_IMPORT_BYTES:
        raise CollectionError("Magisk import exceeds the total byte limit")
    verified: dict[str, bytes] = {}
    file_identities: set[tuple[int, int]] = set()
    for artifact in sorted(manifest.artifacts, key=lambda item: item.logical_name):
        if artifact.relative_path is None:
            continue
        if artifact.byte_size is None or artifact.sha256 is None:
            raise SchemaValidationError("observed Magisk artifact is incomplete")
        payload, identity = _read_regular_file_beneath(
            root_descriptor,
            artifact.relative_path,
            limit=artifact.byte_size,
        )
        if identity in file_identities:
            raise CollectionError("Magisk artifact paths must not alias one file")
        file_identities.add(identity)
        if len(payload) != artifact.byte_size:
            raise CollectionError("Magisk artifact byte size mismatch")
        if hashlib.sha256(payload).hexdigest() != artifact.sha256:
            raise CollectionError("Magisk artifact digest mismatch")
        verified[artifact.logical_name] = payload
    return verified


def _reject_tree_overlap(source_root: Path, output_candidate: Path) -> None:
    try:
        source_root.relative_to(output_candidate)
    except ValueError:
        try:
            output_candidate.relative_to(source_root)
        except ValueError:
            pass
        else:
            raise CollectionError("Magisk input and output trees must not overlap")
    else:
        raise CollectionError("Magisk input and output trees must not overlap")


def _prepare_output_root(output_dir: str | Path, source_root: Path) -> tuple[Path, int]:
    if sys.platform == "win32" and sys.version_info < (3, 13):
        raise CollectionError(
            "Magisk import on Windows requires Python 3.13 or newer for private "
            "directory ACLs"
        )
    directory_flags = _safe_directory_flags()
    output = Path(output_dir)
    _reject_tree_overlap(source_root, output.resolve(strict=False))
    try:
        if output.is_symlink():
            raise CollectionError("Magisk import output must not be a symlink")
        output.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = output.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise CollectionError("Magisk import output must be a directory")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise CollectionError(
                "Magisk import output must be owned by the current user"
            )
        output_root = output.resolve(strict=True)
    except CollectionError:
        raise
    except OSError as exc:
        raise OutputWriteError("could not prepare Magisk import output") from exc
    try:
        os.chmod(output_root, 0o700)
        protected = output_root.lstat()
    except OSError as exc:
        raise OutputWriteError("could not protect Magisk import output") from exc
    if (
        not stat.S_ISDIR(protected.st_mode)
        or (metadata.st_dev, metadata.st_ino) != (protected.st_dev, protected.st_ino)
        or (os.name != "nt" and stat.S_IMODE(protected.st_mode) != 0o700)
    ):
        raise OutputWriteError("Magisk import output changed while being protected")
    descriptor = -1
    try:
        descriptor = os.open(output_root, directory_flags)
        anchored = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise OutputWriteError("could not anchor Magisk import output") from exc
    if (protected.st_dev, protected.st_ino) != (anchored.st_dev, anchored.st_ino):
        os.close(descriptor)
        raise OutputWriteError("Magisk import output changed while being opened")
    return output_root, descriptor


def _acquire_lock(root_descriptor: int) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    created = False
    try:
        descriptor = os.open(
            IMPORT_LOCK_NAME,
            flags,
            0o600,
            dir_fd=root_descriptor,
        )
        created = True
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            os.chmod(IMPORT_LOCK_NAME, 0o600, dir_fd=root_descriptor)
        return descriptor
    except FileExistsError as exc:
        raise CollectionError("another Magisk import holds the output lock") from exc
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if created:
            try:
                os.unlink(IMPORT_LOCK_NAME, dir_fd=root_descriptor)
            except OSError:
                pass
        raise OutputWriteError("could not acquire Magisk import lock") from exc


def _release_lock(descriptor: int, root_descriptor: int) -> None:
    release_error: OSError | None = None
    try:
        os.close(descriptor)
    except OSError as exc:
        release_error = exc
    try:
        os.unlink(IMPORT_LOCK_NAME, dir_fd=root_descriptor)
    except FileNotFoundError:
        pass
    except OSError as exc:
        release_error = release_error or exc
    if release_error is not None:
        raise OutputWriteError(
            "could not release Magisk import lock"
        ) from release_error


def _open_private_parent(root_descriptor: int, relative_path: str) -> tuple[int, str]:
    parts = PurePosixPath(relative_path).parts
    if not parts:
        raise OutputWriteError("private Magisk import path must name a file")
    current = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            try:
                following = os.open(part, _safe_directory_flags(), dir_fd=current)
            except FileNotFoundError:
                os.mkdir(part, mode=0o700, dir_fd=current)
                following = os.open(part, _safe_directory_flags(), dir_fd=current)
            if hasattr(os, "fchmod"):
                os.fchmod(following, 0o700)
            os.close(current)
            current = following
        return current, parts[-1]
    except BaseException:
        os.close(current)
        raise


def _write_private_bytes_beneath(
    root_descriptor: int,
    relative_path: str,
    payload: bytes,
) -> None:
    try:
        parent_descriptor, name = _open_private_parent(
            root_descriptor,
            relative_path,
        )
    except (OSError, OutputWriteError) as exc:
        raise OutputWriteError("could not prepare private Magisk import file") from exc
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
    except OSError as exc:
        os.close(parent_descriptor)
        raise OutputWriteError("could not prepare private Magisk import file") from exc
    descriptor_open = True
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor_open = False
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(parent_descriptor)
    except OSError as exc:
        raise OutputWriteError("could not write private Magisk import file") from exc
    finally:
        if descriptor_open:
            os.close(descriptor)
        os.close(parent_descriptor)


def _sync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise OutputWriteError("could not synchronize Magisk import directory") from exc


def _create_staging(root_descriptor: int) -> tuple[str, int]:
    for _attempt in range(32):
        name = f".trustlab-magisk-import-{secrets.token_hex(8)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=root_descriptor)
        except FileExistsError:
            continue
        except (OSError, OutputWriteError) as exc:
            raise OutputWriteError("could not create Magisk import staging") from exc
        descriptor = -1
        try:
            descriptor = os.open(name, _safe_directory_flags(), dir_fd=root_descriptor)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o700)
            _sync_directory(root_descriptor)
            return name, descriptor
        except (OSError, OutputWriteError) as exc:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.rmdir(name, dir_fd=root_descriptor)
            except OSError:
                pass
            raise OutputWriteError("could not protect Magisk import staging") from exc
    raise OutputWriteError("could not allocate Magisk import staging")


def _clear_directory(descriptor: int) -> None:
    try:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(
                    metadata.st_mode
                ):
                    child = os.open(
                        entry.name,
                        _safe_directory_flags(),
                        dir_fd=descriptor,
                    )
                    try:
                        _clear_directory(child)
                    finally:
                        os.close(child)
                    os.rmdir(entry.name, dir_fd=descriptor)
                else:
                    os.unlink(entry.name, dir_fd=descriptor)
    except OSError as exc:
        raise OutputWriteError("could not clean Magisk import staging") from exc


def _remove_staging(root_descriptor: int, name: str) -> None:
    descriptor = -1
    try:
        descriptor = os.open(name, _safe_directory_flags(), dir_fd=root_descriptor)
        _clear_directory(descriptor)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OutputWriteError(
            "could not open Magisk import staging for cleanup"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        os.rmdir(name, dir_fd=root_descriptor)
        _sync_directory(root_descriptor)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise OutputWriteError("could not remove Magisk import staging") from exc


def _atomic_rename_noreplace(
    root_descriptor: int,
    source_name: str,
    destination_name: str,
) -> None:
    """Publish a directory atomically without replacing any destination."""

    if os.name == "nt":
        raise OSError(
            errno.ENOTSUP,
            "directory-relative no-replace publication is unsupported",
        )
    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source_name)
    destination_bytes = os.fsencode(destination_name)
    if sys.platform == "darwin":
        try:
            renameatx = library.renameatx_np
        except AttributeError as exc:
            raise OSError(
                errno.ENOTSUP,
                "atomic no-replace publication is unsupported",
            ) from exc
        renameatx.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameatx.restype = ctypes.c_int
        result = renameatx(
            root_descriptor,
            source_bytes,
            root_descriptor,
            destination_bytes,
            _DARWIN_RENAME_EXCL,
        )
    elif sys.platform.startswith("linux"):
        try:
            renameat2 = library.renameat2
        except AttributeError as exc:
            raise OSError(
                errno.ENOTSUP,
                "atomic no-replace publication is unsupported",
            ) from exc
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            root_descriptor,
            source_bytes,
            root_descriptor,
            destination_bytes,
            _RENAME_NOREPLACE,
        )
    else:
        raise OSError(
            errno.ENOTSUP,
            "atomic no-replace publication is unsupported",
        )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _copy_verified_bundle(
    staging_descriptor: int,
    manifest: CollectionManifest,
    verified: dict[str, bytes],
    manifest_payload: bytes,
) -> None:
    for artifact in manifest.artifacts:
        if artifact.relative_path is None:
            continue
        _write_private_bytes_beneath(
            staging_descriptor,
            artifact.relative_path,
            verified[artifact.logical_name],
        )
    _write_private_bytes_beneath(
        staging_descriptor,
        COMPLETION_MANIFEST_NAME,
        manifest_payload,
    )


def _json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise OutputWriteError("could not serialize Magisk import report") from exc


def _entry_exists(root_descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise OutputWriteError("could not inspect Magisk import destination") from exc
    return True


def _verify_output_anchor(root: Path, descriptor: int) -> None:
    try:
        path_metadata = root.lstat()
        anchored = os.fstat(descriptor)
    except OSError as exc:
        raise OutputWriteError("could not verify Magisk import output anchor") from exc
    if not stat.S_ISDIR(path_metadata.st_mode) or (
        path_metadata.st_dev,
        path_metadata.st_ino,
    ) != (anchored.st_dev, anchored.st_ino):
        raise OutputWriteError("Magisk import output changed during publication")


def import_magisk(input_path: str | Path, output_dir: str | Path) -> MagiskImportResult:
    """Verify, normalize, and atomically publish one complete Magisk bundle."""

    source_root, _source_manifest = _resolve_input(input_path)
    root_descriptor = _open_source_root(source_root)
    try:
        manifest_payload, manifest = _read_manifest(root_descriptor)
        _validate_magisk_contract(manifest)
        paths = _artifact_paths(manifest)
        _scan_closed_bundle(root_descriptor, paths)
        verified = _verify_payloads(manifest, root_descriptor)
    finally:
        os.close(root_descriptor)

    manifest_digest = hashlib.sha256(
        canonical_json_bytes(manifest.to_dict())
    ).hexdigest()
    content_id = f"{CONTENT_ADDRESS_PREFIX}{manifest_digest}"
    raw_entry = next(
        artifact
        for artifact in manifest.artifacts
        if artifact.logical_name == "raw_report"
        and artifact.status is EvidenceStatus.OBSERVED
    )
    report = normalize_collection_payload(
        verified[raw_entry.logical_name],
        manifest,
        label=raw_entry.relative_path or "raw_report",
    )
    validate_report(report)
    report_payload = _json_bytes(report)

    output_root, output_descriptor = _prepare_output_root(output_dir, source_root)
    try:
        lock_descriptor = _acquire_lock(output_descriptor)
    except BaseException:
        os.close(output_descriptor)
        raise
    staging_name: str | None = None
    staging_descriptor = -1
    primary_failure = False
    try:
        if _entry_exists(output_descriptor, content_id):
            raise OutputWriteError("content-addressed Magisk import already exists")
        staging_name, staging_descriptor = _create_staging(output_descriptor)
        _copy_verified_bundle(
            staging_descriptor,
            manifest,
            verified,
            manifest_payload,
        )
        _write_private_bytes_beneath(
            staging_descriptor,
            NORMALIZED_REPORT_NAME,
            report_payload,
        )
        _sync_directory(staging_descriptor)
        os.close(staging_descriptor)
        staging_descriptor = -1
        _verify_output_anchor(output_root, output_descriptor)
        try:
            _atomic_rename_noreplace(
                output_descriptor,
                staging_name,
                content_id,
            )
        except FileExistsError as exc:
            raise OutputWriteError(
                "content-addressed Magisk import already exists"
            ) from exc
        except OSError as exc:
            raise OutputWriteError(
                "could not publish Magisk import atomically"
            ) from exc
        staging_name = None
        _sync_directory(output_descriptor)
        _verify_output_anchor(output_root, output_descriptor)
        destination = output_root / content_id
        return MagiskImportResult(
            content_id=content_id,
            directory=destination,
            manifest_path=destination / COMPLETION_MANIFEST_NAME,
            report_path=destination / NORMALIZED_REPORT_NAME,
        )
    except (CollectionError, OutputWriteError):
        primary_failure = True
        raise
    except BaseException:
        primary_failure = True
        raise
    finally:
        if staging_descriptor >= 0:
            os.close(staging_descriptor)
        if staging_name is not None:
            try:
                _remove_staging(output_descriptor, staging_name)
            except OutputWriteError:
                if not primary_failure:
                    raise
        try:
            _release_lock(lock_descriptor, output_descriptor)
        except OutputWriteError:
            if not primary_failure:
                raise
        finally:
            os.close(output_descriptor)
