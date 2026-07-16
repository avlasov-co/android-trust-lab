"""Typed artifact-adapter boundary for untrusted collector output.

Adapters parse capture facts and provenance only. Trust-state interpretation belongs
to :mod:`trustlab.normalizer`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from jsonschema import Draft202012Validator, FormatChecker

from .bounded_io import read_bounded_regular_file
from .canonical_json import MAX_CANONICAL_BYTES
from .exceptions import (
    CollectionError,
    InvalidJSONError,
    NormalizationError,
    UnsupportedSchemaVersionError,
    safe_path_label,
)
from .identity import validate_relative_artifact_path
from .parser import (
    ParsedIdentity,
    ParsedMount,
    ParsedProcesses,
    parse_getenforce,
    parse_getprop,
    parse_id,
    parse_key_values,
    parse_mounts,
    parse_paths,
    parse_processes,
    parse_raw_text,
)
from .validators import load_schema


class InputKind(StrEnum):
    LEGACY_SECTIONED_TEXT = "legacy_sectioned_text"
    ADB_COLLECTION_MANIFEST = "adb_collection_manifest"
    MAGISK_COLLECTION_MANIFEST = "magisk_collection_manifest"
    HOST_COLLECTION_MANIFEST = "host_collection_manifest"
    APP_PROBE_JSON = "app_probe_json"


class CaptureStatus(StrEnum):
    OBSERVED = "observed"
    EMPTY = "empty"
    NOT_COLLECTED = "not_collected"
    INACCESSIBLE = "inaccessible"
    COMMAND_ERROR = "command_error"
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class CommandCapture:
    """One command/probe result with status kept separate from its output."""

    name: str
    status: CaptureStatus
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    source_ref: str


@dataclass(frozen=True, slots=True)
class ArtifactMetadata:
    schema_version: str
    collector_version: str
    observer_type: str | None = None
    collection_method: str | None = None
    experiment_id: str | None = None
    target_type: str | None = None
    collection_timestamp: str | None = None


def _unknown_identity() -> ParsedIdentity:
    return {
        "uid": "unknown",
        "user": "unknown",
        "gid": "unknown",
        "group": "unknown",
        "raw": "",
    }


def _empty_processes() -> ParsedProcesses:
    return {
        "raw_line_count": 0,
        "init_visible": False,
        "adbd_visible": False,
        "zygote_visible": False,
        "system_server_visible": False,
        "magisk_processes_visible": False,
        "process_contexts_available": False,
    }


@dataclass(frozen=True, slots=True)
class EvidenceFragments:
    """Constrained syntactic fragments consumed by the normalizer."""

    sections: Mapping[str, str] = field(default_factory=dict)
    properties: Mapping[str, str] = field(default_factory=dict)
    boot_state: Mapping[str, str] = field(default_factory=dict)
    mounts: tuple[ParsedMount, ...] = ()
    identity: ParsedIdentity = field(default_factory=_unknown_identity)
    selinux_mode: str = "unknown"
    cmdline: str = ""
    su_paths: tuple[str, ...] = ()
    magisk_text: str = ""
    processes: ParsedProcesses = field(default_factory=_empty_processes)


@dataclass(frozen=True, slots=True)
class ArtifactParseResult:
    input_kind: InputKind
    metadata: ArtifactMetadata
    captures: tuple[CommandCapture, ...]
    warnings: tuple[str, ...]
    errors: tuple[str, ...]
    fragments: EvidenceFragments
    parsed_capture_names: frozenset[str]


class ArtifactAdapter(Protocol):
    """Contract shared by every observer-specific artifact family."""

    input_kind: InputKind
    supported_schema_versions: frozenset[str]
    supported_collector_versions: frozenset[str]

    def parse(self, text: str, *, source_ref: str) -> ArtifactParseResult:
        """Return facts, capture statuses, diagnostics, and normalized fragments."""


def _capture_status(value: object, *, capture_name: str) -> CaptureStatus:
    if not isinstance(value, str):
        raise NormalizationError(f"capture {capture_name!r} status must be a string")
    try:
        return CaptureStatus(value)
    except ValueError as exc:
        raise NormalizationError(
            f"capture {capture_name!r} has unsupported status"
        ) from exc


def _optional_string(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise NormalizationError(f"manifest field {field_name!r} must be a string")
    return value


def _required_string(value: object, *, field_name: str) -> str:
    result = _optional_string(value, field_name=field_name)
    if not result:
        raise NormalizationError(f"manifest field {field_name!r} is required")
    return result


def _strict_json(text: str) -> Mapping[str, object]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant: {value}")

    def reject_duplicate_members(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON object member")
            result[key] = item
        return result

    try:
        value = json.loads(
            text,
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicate_members,
        )
    except json.JSONDecodeError as exc:
        raise InvalidJSONError(
            f"invalid artifact JSON (line {exc.lineno}, column {exc.colno})"
        ) from exc
    except ValueError as exc:
        raise InvalidJSONError("invalid artifact JSON") from exc
    if not isinstance(value, dict):
        raise NormalizationError("artifact JSON must be an object")
    return value


def _metadata(document: Mapping[str, object]) -> ArtifactMetadata:
    observer_value = document.get("observer", {})
    if observer_value is None:
        observer_value = {}
    if not isinstance(observer_value, dict):
        raise NormalizationError("manifest observer must be an object")
    collection_value = document.get("collection", {})
    if collection_value is None:
        collection_value = {}
    if not isinstance(collection_value, dict):
        raise NormalizationError("manifest collection must be an object")
    return ArtifactMetadata(
        schema_version=_required_string(
            document.get("schema_version"), field_name="schema_version"
        ),
        collector_version=_required_string(
            document.get("collector_version"), field_name="collector_version"
        ),
        observer_type=_optional_string(
            observer_value.get("observer_type"), field_name="observer.observer_type"
        ),
        collection_method=_optional_string(
            observer_value.get("collection_method"),
            field_name="observer.collection_method",
        ),
        experiment_id=_optional_string(
            collection_value.get("experiment_id"),
            field_name="collection.experiment_id",
        ),
        target_type=_optional_string(
            collection_value.get("target_type"), field_name="collection.target_type"
        ),
        collection_timestamp=_optional_string(
            collection_value.get("timestamp"), field_name="collection.timestamp"
        ),
    )


_CAPTURE_SEMANTICS = {
    "properties": "properties",
    "getprop_selected": "properties",
    "boot_state": "boot_state",
    "mountinfo": "mounts",
    "mounts": "mounts",
    "proc_mounts": "mounts",
    "identity": "identity",
    "id": "identity",
    "selinux_mode": "selinux",
    "getenforce": "selinux",
    "kernel_cmdline": "cmdline",
    "su_paths": "su_paths",
    "magisk": "magisk",
    "processes": "processes",
    "ps_selected": "processes",
}

_ALLOWED_CAPTURE_NAMES = {
    InputKind.ADB_COLLECTION_MANIFEST: frozenset(
        name for name, semantic in _CAPTURE_SEMANTICS.items() if semantic != "magisk"
    ),
    InputKind.MAGISK_COLLECTION_MANIFEST: frozenset(_CAPTURE_SEMANTICS),
    InputKind.HOST_COLLECTION_MANIFEST: frozenset(
        {"python_version", "host_os", "adb_version", "emulator_version"}
    ),
    InputKind.APP_PROBE_JSON: frozenset(
        {
            "properties",
            "getprop_selected",
            "identity",
            "id",
            "selinux_mode",
            "getenforce",
            "su_paths",
            "magisk",
            "processes",
            "ps_selected",
        }
    ),
}


def _validate_capture_outcome(capture: CommandCapture) -> None:
    successful = capture.status in {CaptureStatus.OBSERVED, CaptureStatus.EMPTY}
    if successful and (capture.timed_out or capture.exit_code not in {None, 0}):
        raise NormalizationError(
            f"capture {capture.name!r} has an incoherent successful outcome"
        )
    if capture.status is CaptureStatus.OBSERVED and not capture.stdout:
        raise NormalizationError(
            f"capture {capture.name!r} observed status requires output"
        )
    if capture.status is CaptureStatus.EMPTY and capture.stdout:
        raise NormalizationError(
            f"capture {capture.name!r} empty status requires empty output"
        )
    if capture.status is CaptureStatus.TIMEOUT:
        if not capture.timed_out or capture.exit_code is not None:
            raise NormalizationError(
                f"capture {capture.name!r} has an incoherent timeout outcome"
            )
    elif capture.timed_out:
        raise NormalizationError(
            f"capture {capture.name!r} timed_out requires timeout status"
        )
    if capture.status in {CaptureStatus.NOT_COLLECTED, CaptureStatus.UNSUPPORTED}:
        if capture.exit_code is not None or capture.stdout:
            raise NormalizationError(
                f"capture {capture.name!r} has an incoherent unavailable outcome"
            )
    if capture.status is CaptureStatus.INACCESSIBLE:
        if capture.exit_code == 0 or capture.stdout:
            raise NormalizationError(
                f"capture {capture.name!r} has an incoherent inaccessible outcome"
            )
    if capture.status in {CaptureStatus.COMMAND_ERROR, CaptureStatus.ERROR}:
        if capture.exit_code == 0:
            raise NormalizationError(
                f"capture {capture.name!r} has an incoherent error outcome"
            )


def _captures(
    document: Mapping[str, object], *, input_kind: InputKind
) -> tuple[CommandCapture, ...]:
    raw_captures = document.get("captures")
    if not isinstance(raw_captures, list):
        raise NormalizationError("manifest captures must be an array")
    captures = []
    names: set[str] = set()
    semantics: set[str] = set()
    allowed_names = _ALLOWED_CAPTURE_NAMES[input_kind]
    for index, raw_capture in enumerate(raw_captures):
        if not isinstance(raw_capture, dict):
            raise NormalizationError(f"manifest capture {index} must be an object")
        name = _required_string(raw_capture.get("name"), field_name="captures.name")
        if name not in allowed_names:
            raise NormalizationError(
                f"capture {name!r} is not valid for {input_kind.value}"
            )
        if name in names:
            raise NormalizationError(f"duplicate capture name {name!r}")
        names.add(name)
        semantic = _CAPTURE_SEMANTICS.get(name)
        if semantic is not None and semantic in semantics:
            raise NormalizationError(
                f"capture {name!r} duplicates an existing evidence fragment"
            )
        if semantic is not None:
            semantics.add(semantic)
        exit_code_value = raw_capture.get("exit_code")
        if exit_code_value is not None and (
            isinstance(exit_code_value, bool) or not isinstance(exit_code_value, int)
        ):
            raise NormalizationError(
                f"capture {name!r} exit_code must be an integer or null"
            )
        timed_out = raw_capture.get("timed_out", False)
        if not isinstance(timed_out, bool):
            raise NormalizationError(f"capture {name!r} timed_out must be boolean")
        stdout = raw_capture.get("stdout", "")
        stderr = raw_capture.get("stderr", "")
        source_ref = raw_capture.get("source_ref", name)
        if not all(isinstance(value, str) for value in (stdout, stderr, source_ref)):
            raise NormalizationError(f"capture {name!r} text fields must be strings")
        try:
            validate_relative_artifact_path(source_ref)
        except CollectionError as exc:
            raise NormalizationError(
                f"capture {name!r} source_ref must be portable and relative"
            ) from exc
        capture = CommandCapture(
            name=name,
            status=_capture_status(raw_capture.get("status"), capture_name=name),
            exit_code=exit_code_value,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr,
            source_ref=source_ref,
        )
        _validate_capture_outcome(capture)
        captures.append(capture)
    return tuple(captures)


def _has_capture_diagnostic(text: str) -> bool:
    lowered_output = text.lower()
    return any(
        diagnostic in lowered_output
        for diagnostic in (
            "permission denied",
            "operation not permitted",
            "access denied",
            "inaccessible",
            "unavailable",
            "command not found",
            "no such file",
            "not found",
            "timed out",
            "timeout",
            "error:",
            "failed:",
        )
    )


def _is_legacy_negative_sentinel(capture: CommandCapture, semantic: str | None) -> bool:
    lowered_output = capture.stdout.lower()
    if semantic == "magisk":
        return "magisk" in lowered_output and "not found" in lowered_output
    if semantic == "su_paths":
        lines = [
            line.strip().lower() for line in capture.stdout.splitlines() if line.strip()
        ]
        return bool(lines) and all(line.startswith("not found") for line in lines)
    return semantic == "selinux" and "permission denied" in lowered_output


def _observed_capture_syntax_is_valid(
    capture: CommandCapture, semantic: str | None
) -> bool:
    if semantic in {"properties", "boot_state"}:
        lines = [line.strip() for line in capture.stdout.splitlines() if line.strip()]
        parsed = (
            parse_getprop(capture.stdout)
            if semantic == "properties"
            else parse_key_values(capture.stdout)
        )
        return bool(lines) and len(parsed) == len(lines)
    if semantic == "mounts":
        mounts = parse_mounts(capture.stdout)
        return bool(mounts) and all(
            mount["mount_point"].startswith("/")
            and mount["fs_type"] != "unknown"
            and bool(mount["options"])
            for mount in mounts
        )
    if semantic == "identity":
        return parse_id(capture.stdout)["uid"] != "unknown"
    if semantic == "selinux":
        return parse_getenforce(capture.stdout) != "unknown"
    if semantic == "magisk":
        lines = [
            line.strip().lower() for line in capture.stdout.splitlines() if line.strip()
        ]
        return (
            bool(lines)
            and any(line.startswith("magisk_") for line in lines)
            and all(
                re.fullmatch(
                    r"(?:magisk_(?:version|path|data_path)|module_context|zygisk_indicator)=[^\s]+",
                    line,
                )
                is not None
                for line in lines
            )
        )
    if semantic == "processes":
        known_processes = {
            "init",
            "adbd",
            "zygote",
            "zygote64",
            "system_server",
            "magisk",
            "magiskd",
        }
        process_lines = [
            line.split() for line in capture.stdout.splitlines() if line.strip()
        ]
        return bool(process_lines) and all(
            len(parts) >= 2
            and parts[-1].lower().rsplit("/", 1)[-1] in known_processes
            and any(part.isdigit() for part in parts[:-1])
            for parts in process_lines
        )
    if semantic == "cmdline":
        return bool(capture.stdout.strip())
    if semantic == "su_paths":
        paths = parse_paths(capture.stdout)
        return bool(paths) and all(
            path.startswith("/") and not any(character.isspace() for character in path)
            for path in paths
        )
    return True


def _capture_syntax_is_valid(
    capture: CommandCapture, *, reject_diagnostics: bool
) -> bool:
    semantic = _CAPTURE_SEMANTICS.get(capture.name)
    if capture.status is CaptureStatus.EMPTY:
        if not reject_diagnostics:
            return True
        return semantic in {"su_paths", "magisk", "processes"} or semantic is None
    if capture.status is not CaptureStatus.OBSERVED:
        return False
    if not reject_diagnostics and _is_legacy_negative_sentinel(capture, semantic):
        return True
    if _has_capture_diagnostic(capture.stdout):
        return False
    return _observed_capture_syntax_is_valid(capture, semantic)


def _legacy_capture_has_usable_fragments(capture: CommandCapture) -> bool:
    if capture.status is CaptureStatus.EMPTY:
        return True
    if capture.status is not CaptureStatus.OBSERVED:
        return False
    semantic = _CAPTURE_SEMANTICS.get(capture.name)
    if _is_legacy_negative_sentinel(capture, semantic):
        return True
    if _has_capture_diagnostic(capture.stdout):
        return False
    if semantic == "properties":
        return bool(parse_getprop(capture.stdout))
    if semantic == "boot_state":
        return bool(parse_key_values(capture.stdout))
    if semantic == "mounts":
        return any(
            mount["mount_point"].startswith("/")
            for mount in parse_mounts(capture.stdout)
        )
    return _observed_capture_syntax_is_valid(capture, semantic)


def _parsed_capture_names(
    captures: Sequence[CommandCapture], *, fail_on_malformed: bool
) -> tuple[frozenset[str], tuple[str, ...]]:
    parsed: set[str] = set()
    warnings: list[str] = []
    for capture in captures:
        if _capture_syntax_is_valid(capture, reject_diagnostics=fail_on_malformed):
            parsed.add(capture.name)
        elif capture.status in {CaptureStatus.OBSERVED, CaptureStatus.EMPTY}:
            message = f"capture {capture.name} contained malformed observed output"
            if fail_on_malformed:
                raise NormalizationError(message)
            if capture.status is CaptureStatus.OBSERVED:
                warnings.append(message)
    return frozenset(parsed), tuple(warnings)


def _first_observed(captures: Sequence[CommandCapture], *names: str) -> str:
    name_set = frozenset(names)
    for capture in captures:
        if capture.name in name_set and capture.status in {
            CaptureStatus.OBSERVED,
            CaptureStatus.EMPTY,
        }:
            return capture.stdout
    return ""


def _fragments_from_captures(captures: Sequence[CommandCapture]) -> EvidenceFragments:
    properties_text = _first_observed(captures, "properties", "getprop_selected")
    boot_text = _first_observed(captures, "boot_state")
    mounts_text = _first_observed(captures, "mountinfo", "mounts", "proc_mounts")
    identity_text = _first_observed(captures, "identity", "id")
    selinux_text = _first_observed(captures, "selinux_mode", "getenforce")
    if any(
        capture.name in {"selinux_mode", "getenforce"}
        and capture.status is CaptureStatus.INACCESSIBLE
        for capture in captures
    ):
        selinux_text = "inaccessible"
    cmdline_text = _first_observed(captures, "kernel_cmdline")
    su_text = _first_observed(captures, "su_paths")
    magisk_text = _first_observed(captures, "magisk")
    process_text = _first_observed(captures, "processes", "ps_selected")
    return EvidenceFragments(
        properties=parse_getprop(properties_text),
        boot_state=parse_key_values(boot_text),
        mounts=tuple(parse_mounts(mounts_text)),
        identity=parse_id(identity_text),
        selinux_mode=parse_getenforce(selinux_text),
        cmdline=cmdline_text,
        su_paths=tuple(parse_paths(su_text)),
        magisk_text=magisk_text,
        processes=parse_processes(process_text),
    )


class LegacySectionedTextAdapter:
    input_kind = InputKind.LEGACY_SECTIONED_TEXT
    supported_schema_versions = frozenset({"legacy-sectioned-text-1"})
    supported_collector_versions = frozenset({"legacy"})

    def parse(self, text: str, *, source_ref: str) -> ArtifactParseResult:
        raw = parse_raw_text(text)
        captures = []
        declared_sections = set(raw["section_names"])
        aliases = {
            "properties": ("GETPROP", "PROPS"),
            "boot_state": ("BOOT_STATE",),
            "mounts": ("MOUNT", "MOUNTS"),
            "identity": ("ID",),
            "selinux_mode": ("GETENFORCE", "SELINUX"),
            "kernel_cmdline": ("CMDLINE",),
            "su_paths": ("SU_PATHS",),
            "magisk": ("MAGISK",),
            "processes": ("PS", "PROCESSES"),
        }
        for capture_name, section_names in aliases.items():
            content = next(
                (
                    raw["sections"][name]
                    for name in section_names
                    if name in raw["sections"]
                ),
                "",
            )
            present = any(name in declared_sections for name in section_names)
            status = (
                CaptureStatus.OBSERVED
                if content
                else CaptureStatus.EMPTY
                if present
                else CaptureStatus.NOT_COLLECTED
            )
            captures.append(
                CommandCapture(
                    name=capture_name,
                    status=status,
                    exit_code=None,
                    timed_out=False,
                    stdout=content,
                    stderr="",
                    source_ref=f"legacy-sections/{section_names[0]}",
                )
            )
        parsed_names, parse_warnings = _parsed_capture_names(
            captures, fail_on_malformed=False
        )
        sanitized_captures = tuple(
            capture
            for capture in captures
            if _legacy_capture_has_usable_fragments(capture)
        )
        fragments = replace(
            _fragments_from_captures(sanitized_captures),
            sections=raw["sections"],
        )
        return ArtifactParseResult(
            input_kind=self.input_kind,
            metadata=ArtifactMetadata("legacy-sectioned-text-1", "legacy"),
            captures=tuple(captures),
            warnings=(
                "legacy sectioned text has inferred command status and no collector manifest",
                *parse_warnings,
            ),
            errors=(),
            fragments=fragments,
            parsed_capture_names=parsed_names,
        )


def _legacy_host_captures(text: str) -> tuple[CommandCapture, ...]:
    raw = parse_raw_text(text)
    declared_sections = set(raw["section_names"])
    aliases = {
        "host_os": "HOST_OS",
        "adb_version": "ADB_VERSION",
        "emulator_version": "EMULATOR_VERSION",
        "python_version": "PYTHON_VERSION",
    }
    captures: list[CommandCapture] = []
    for capture_name, section_name in aliases.items():
        content = raw["sections"].get(section_name, "")
        present = section_name in declared_sections
        status = (
            CaptureStatus.OBSERVED
            if content
            else CaptureStatus.EMPTY
            if present
            else CaptureStatus.NOT_COLLECTED
        )
        captures.append(
            CommandCapture(
                name=capture_name,
                status=status,
                exit_code=None,
                timed_out=False,
                stdout=content,
                stderr="",
                source_ref=f"legacy-sections/{section_name}",
            )
        )
    return tuple(captures)


class ManifestAdapter:
    supported_schema_versions = frozenset({"1.0.0"})
    supported_collector_versions = frozenset({"0.3.0", "0.3.0-dev0", "1.0.0"})

    def __init__(self, input_kind: InputKind) -> None:
        self.input_kind = input_kind

    def parse(self, text: str, *, source_ref: str) -> ArtifactParseResult:
        document = _strict_json(text)
        declared_kind = _required_string(
            document.get("artifact_kind"), field_name="artifact_kind"
        )
        if declared_kind != self.input_kind.value:
            raise NormalizationError("artifact kind does not match selected adapter")
        metadata = _metadata(document)
        self._validate_metadata(metadata)
        schema_name = (
            "app_probe_v1_0_0.schema.json"
            if self.input_kind is InputKind.APP_PROBE_JSON
            else "artifact_collection_manifest_v1_0_0.schema.json"
        )
        errors = sorted(
            Draft202012Validator(
                load_schema(schema_name), format_checker=FormatChecker()
            ).iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        if errors:
            raise NormalizationError(f"artifact JSON does not match {schema_name}")
        captures = _captures(document, input_kind=self.input_kind)
        parsed_names, _ = _parsed_capture_names(captures, fail_on_malformed=True)
        return self._result(document, metadata, captures, parsed_names)

    def _validate_metadata(self, metadata: ArtifactMetadata) -> None:
        if metadata.schema_version not in self.supported_schema_versions:
            raise UnsupportedSchemaVersionError(
                "unsupported collection manifest schema version"
            )
        if metadata.collector_version not in self.supported_collector_versions:
            raise UnsupportedSchemaVersionError("unsupported collector version")
        expected_observer = {
            InputKind.ADB_COLLECTION_MANIFEST: "adb_shell",
            InputKind.MAGISK_COLLECTION_MANIFEST: "root_collector",
            InputKind.HOST_COLLECTION_MANIFEST: "host",
            InputKind.APP_PROBE_JSON: "unprivileged_app",
        }[self.input_kind]
        if metadata.observer_type != expected_observer:
            raise NormalizationError(
                "artifact kind does not match its declared observer type"
            )

    def _result(
        self,
        document: Mapping[str, object],
        metadata: ArtifactMetadata,
        captures: tuple[CommandCapture, ...],
        parsed_names: frozenset[str],
    ) -> ArtifactParseResult:
        errors = tuple(
            f"capture {capture.name} ended with {capture.status.value}"
            for capture in captures
            if capture.status
            in {
                CaptureStatus.COMMAND_ERROR,
                CaptureStatus.ERROR,
                CaptureStatus.TIMEOUT,
            }
        )
        warnings_value = document.get("warnings", [])
        if not isinstance(warnings_value, list) or not all(
            isinstance(item, str) for item in warnings_value
        ):
            raise NormalizationError("manifest warnings must be an array of strings")
        return ArtifactParseResult(
            input_kind=self.input_kind,
            metadata=metadata,
            captures=captures,
            warnings=tuple(warnings_value),
            errors=errors,
            fragments=_fragments_from_captures(captures),
            parsed_capture_names=parsed_names,
        )

    def parse_manifest_payload(
        self,
        text: str,
        *,
        source_ref: str,
        metadata: ArtifactMetadata,
    ) -> ArtifactParseResult:
        """Parse a legacy payload selected by portable manifest metadata."""

        self._validate_metadata(metadata)
        selected = adapter_for_text(text)
        if selected.input_kind is not InputKind.LEGACY_SECTIONED_TEXT:
            raise NormalizationError(
                "portable text/plain raw_report must contain legacy sectioned text"
            )
        legacy = selected.parse(text, source_ref=source_ref)
        allowed = _ALLOWED_CAPTURE_NAMES[self.input_kind]
        available_captures = legacy.captures
        if self.input_kind is InputKind.HOST_COLLECTION_MANIFEST:
            available_captures = (*available_captures, *_legacy_host_captures(text))
        captures = tuple(
            capture for capture in available_captures if capture.name in allowed
        )
        parsed_names, _ = _parsed_capture_names(captures, fail_on_malformed=True)
        ignored = sorted(
            capture.name
            for capture in available_captures
            if capture.name not in allowed
            and capture.status in {CaptureStatus.OBSERVED, CaptureStatus.EMPTY}
        )
        warnings = (
            "portable collection manifest selected the observer-specific adapter; "
            "legacy payload has inferred per-command status",
            *(
                f"ignored observer-inapplicable legacy capture: {name}"
                for name in ignored
            ),
            *legacy.warnings[1:],
        )
        return replace(
            legacy,
            input_kind=self.input_kind,
            metadata=metadata,
            captures=captures,
            warnings=warnings,
            fragments=_fragments_from_captures(captures),
            parsed_capture_names=parsed_names,
        )


class AppProbeAdapter(ManifestAdapter):
    supported_schema_versions = frozenset({"1.0.0"})


ADAPTERS: dict[InputKind, ArtifactAdapter] = {
    InputKind.LEGACY_SECTIONED_TEXT: LegacySectionedTextAdapter(),
    InputKind.ADB_COLLECTION_MANIFEST: ManifestAdapter(
        InputKind.ADB_COLLECTION_MANIFEST
    ),
    InputKind.MAGISK_COLLECTION_MANIFEST: ManifestAdapter(
        InputKind.MAGISK_COLLECTION_MANIFEST
    ),
    InputKind.HOST_COLLECTION_MANIFEST: ManifestAdapter(
        InputKind.HOST_COLLECTION_MANIFEST
    ),
    InputKind.APP_PROBE_JSON: AppProbeAdapter(InputKind.APP_PROBE_JSON),
}


def _looks_like_json(text: str) -> bool:
    stripped = text.lstrip()
    if stripped.startswith(("\ufeff", "{", "[")):
        return True
    try:
        json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return False
    return True


def adapter_for_text(text: str, *, explicit_kind: str | None = None) -> ArtifactAdapter:
    """Select by declared metadata, with a deliberate non-JSON legacy fallback."""

    if explicit_kind and explicit_kind != "auto":
        try:
            kind = InputKind(explicit_kind)
        except ValueError as exc:
            raise NormalizationError("unsupported artifact kind") from exc
        if kind is InputKind.LEGACY_SECTIONED_TEXT and _looks_like_json(text):
            raise NormalizationError(
                "legacy sectioned text cannot contain a JSON document"
            )
        return ADAPTERS[kind]

    stripped = text.lstrip()
    if stripped.startswith("\ufeff"):
        raise InvalidJSONError("artifact JSON must not contain a UTF-8 BOM")
    if not _looks_like_json(text):
        return ADAPTERS[InputKind.LEGACY_SECTIONED_TEXT]
    document = _strict_json(text)
    declared_kind = document.get("artifact_kind")
    if not isinstance(declared_kind, str):
        raise NormalizationError("JSON artifact_kind is required for adapter selection")
    try:
        kind = InputKind(declared_kind)
    except ValueError as exc:
        raise NormalizationError("unsupported artifact kind") from exc
    if kind is InputKind.LEGACY_SECTIONED_TEXT:
        raise NormalizationError("legacy text cannot be selected by JSON metadata")
    return ADAPTERS[kind]


def parse_artifact_text(
    text: str,
    *,
    source_ref: str,
    artifact_kind: str | None = None,
) -> ArtifactParseResult:
    """Select and parse an already bounded, strictly decoded artifact snapshot."""

    adapter = adapter_for_text(text, explicit_kind=artifact_kind)
    return adapter.parse(text, source_ref=source_ref)


def parse_collection_payload_text(
    text: str,
    *,
    source_ref: str,
    metadata: ArtifactMetadata,
) -> ArtifactParseResult:
    """Select a collection adapter from validated portable-manifest metadata."""

    observer_type = metadata.observer_type
    if observer_type is None:
        raise NormalizationError("collection manifest observer type is required")
    input_kind = {
        "adb_shell": InputKind.ADB_COLLECTION_MANIFEST,
        "root_collector": InputKind.MAGISK_COLLECTION_MANIFEST,
        "host": InputKind.HOST_COLLECTION_MANIFEST,
        "unprivileged_app": InputKind.APP_PROBE_JSON,
    }.get(observer_type)
    if input_kind is None:
        raise NormalizationError("unsupported collection manifest observer type")
    adapter = ADAPTERS[input_kind]
    if not isinstance(adapter, ManifestAdapter):
        raise NormalizationError("collection manifest selected an invalid adapter")
    return adapter.parse_manifest_payload(
        text,
        source_ref=source_ref,
        metadata=metadata,
    )


def parse_artifact(
    path: str | Path, *, artifact_kind: str | None = None
) -> ArtifactParseResult:
    source = Path(path)
    label = safe_path_label(source)
    try:
        payload = read_bounded_regular_file(
            source,
            limit=MAX_CANONICAL_BYTES,
            subject="artifact adapter input",
        )
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CollectionError(f"input artifact is not valid UTF-8: {label}") from exc
    return parse_artifact_text(
        text,
        source_ref=label,
        artifact_kind=artifact_kind,
    )
