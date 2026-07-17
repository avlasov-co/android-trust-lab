"""Typed artifact-adapter boundary for untrusted collector output.

Adapters parse capture facts and provenance only. Trust-state interpretation belongs
to :mod:`trustlab.normalizer`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

from jsonschema import Draft202012Validator, FormatChecker

from .bounded_io import read_bounded_regular_file
from .compatibility import SchemaFamily, schema_resource_name
from .exceptions import (
    CollectionError,
    InvalidJSONError,
    NormalizationError,
    UnsupportedSchemaVersionError,
    safe_path_label,
)
from .identity import validate_relative_artifact_path
from .mounts import (
    MountFormat,
    MountSetParseStatus,
    MountSourceFormat,
    parse_mounts_with_diagnostics,
)
from .parser import (
    MAX_PARSER_WARNINGS,
    MAX_RAW_TEXT_BYTES,
    PARSER_WARNING_LIMIT_MESSAGE,
    ParsedIdentity,
    ParsedMount,
    ParsedProcesses,
    classify_shell_diagnostic,
    parse_getenforce,
    parse_getprop,
    parse_id,
    parse_key_values,
    parse_mounts,
    parse_paths,
    parse_processes,
    parse_raw_text,
    validate_parser_text,
)
from .privacy import semantic_capture_ref
from .security_evidence import (
    ParsedContext,
    ParsedProcessSet,
    ProcessScope,
    is_selected_process_capture,
    parse_selinux_context,
)
from .security_evidence import (
    parse_processes as parse_process_evidence,
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
class MountSourceAttempt:
    """Outcome of one mount-source capture, whether selected or not."""

    name: str
    format: MountSourceFormat
    capture_status: CaptureStatus
    parse_status: MountSetParseStatus | Literal["not_parsed"]
    source_ref: str
    record_count: int
    malformed_line_count: int
    warnings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ArtifactMetadata:
    schema_version: str
    collector_version: str
    observer_type: str | None = None
    collection_method: str | None = None
    experiment_id: str | None = None
    target_type: str | None = None
    collection_timestamp: str | None = None


@dataclass(frozen=True, slots=True)
class AppProbeEvidence:
    """One schema-validated v2 app probe projected into portable evidence."""

    probe_id: str
    status: CaptureStatus
    value: object | None
    source_ref: str


@dataclass(frozen=True, slots=True)
class AppProbeFragments:
    """Typed fields that may safely influence normalized app observations."""

    evidence: tuple[AppProbeEvidence, ...]
    android_version: str | None
    sdk: str | None
    selinux_context: ParsedContext
    emulator_indicators: tuple[str, ...] | None


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


def _empty_context() -> ParsedContext:
    return {
        "parse_status": "empty",
        "value": None,
        "evidence_refs": [],
        "warnings": [],
    }


def _empty_process_evidence() -> ParsedProcessSet:
    return {
        "format": "unknown",
        "scope": "unknown",
        "parse_status": "empty",
        "observations": [],
        "malformed_line_count": 0,
        "warnings": [],
    }


@dataclass(frozen=True, slots=True)
class EvidenceFragments:
    """Constrained syntactic fragments consumed by the normalizer."""

    sections: Mapping[str, str] = field(default_factory=dict)
    section_occurrences: Mapping[str, int] = field(default_factory=dict)
    properties: Mapping[str, str] = field(default_factory=dict)
    boot_state: Mapping[str, str] = field(default_factory=dict)
    mounts: tuple[ParsedMount, ...] = ()
    mount_attempts: tuple[MountSourceAttempt, ...] = ()
    mount_selected_source: str | None = None
    mount_selection_reason: str = "no mount capture was usable"
    identity: ParsedIdentity = field(default_factory=_unknown_identity)
    selinux_mode: str = "unknown"
    selinux_context: ParsedContext = field(default_factory=_empty_context)
    cmdline: str = ""
    su_paths: tuple[str, ...] = ()
    root_probe_text: str = ""
    magisk_text: str = ""
    processes: ParsedProcesses = field(default_factory=_empty_processes)
    process_evidence: ParsedProcessSet = field(default_factory=_empty_process_evidence)
    app_probe: AppProbeFragments | None = None


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


MAX_JSON_NESTING_DEPTH = 32
MAX_JSON_NODES = 100_000


def _validate_json_shape(value: object) -> tuple[str, ...]:
    """Bound nested JSON work after decoding and before schema traversal."""

    nodes = 0
    warnings: list[str] = []
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise NormalizationError("artifact JSON exceeds the node count limit")
        if isinstance(current, dict):
            if depth >= MAX_JSON_NESTING_DEPTH and current:
                raise NormalizationError(
                    "artifact JSON exceeds the nesting depth limit"
                )
            nodes += len(current)
            if nodes > MAX_JSON_NODES:
                raise NormalizationError("artifact JSON exceeds the node count limit")
            for key in current:
                for warning in validate_parser_text(key):
                    _append_decoded_json_warning(warnings, warning)
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            if depth >= MAX_JSON_NESTING_DEPTH and current:
                raise NormalizationError(
                    "artifact JSON exceeds the nesting depth limit"
                )
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            for warning in validate_parser_text(current):
                _append_decoded_json_warning(warnings, warning)
    return tuple(warnings)


def _append_decoded_json_warning(warnings: list[str], warning: str) -> None:
    message = f"decoded JSON string: {warning}"
    if message not in warnings:
        warnings.append(message)


def _strict_json(
    text: str,
    *,
    text_validated: bool = False,
    warning_sink: list[str] | None = None,
) -> Mapping[str, object]:
    if not text_validated:
        validate_parser_text(text)

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
    except RecursionError as exc:
        raise InvalidJSONError(
            "artifact JSON exceeds the decoder nesting limit"
        ) from exc
    if not isinstance(value, dict):
        raise NormalizationError("artifact JSON must be an object")
    decoded_warnings = _validate_json_shape(value)
    if warning_sink is not None:
        warning_sink.extend(decoded_warnings)
    return value


def _bounded_warnings(*groups: Sequence[str]) -> tuple[str, ...]:
    warnings: list[str] = []
    for group in groups:
        for warning in group:
            if warning in warnings or PARSER_WARNING_LIMIT_MESSAGE in warnings:
                continue
            if len(warnings) < MAX_PARSER_WARNINGS - 1:
                warnings.append(warning)
            elif len(warnings) < MAX_PARSER_WARNINGS:
                warnings.append(PARSER_WARNING_LIMIT_MESSAGE)
                return tuple(warnings)
    return tuple(warnings)


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
    "selinux_context": "selinux_context",
    "collector_context": "selinux_context",
    "app_context": "selinux_context",
    "selinux_denials": "selinux_denials",
    "kernel_cmdline": "cmdline",
    "su_paths": "su_paths",
    "root_probe": "root_probe",
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
            "selinux_context",
            "app_context",
            "selinux_denials",
            "su_paths",
            "root_probe",
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
        if semantic is not None and semantic != "mounts" and semantic in semantics:
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
        source_ref = (
            "captures/PS_SELECTED"
            if name == "processes" and is_selected_process_capture(name, source_ref)
            else semantic_capture_ref(name)
        )
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
    return classify_shell_diagnostic(text) is not None


def _is_legacy_negative_sentinel(capture: CommandCapture, semantic: str | None) -> bool:
    lowered_output = capture.stdout.lower()
    if semantic == "magisk":
        return (
            re.fullmatch(
                r"magisk:\s*not found(?:\s+in\s+path)?", lowered_output.strip()
            )
            is not None
        )
    if semantic == "su_paths":
        lines = [
            line.strip().lower() for line in capture.stdout.splitlines() if line.strip()
        ]
        return bool(lines) and all(line == "not found" for line in lines)
    return semantic == "selinux" and "permission denied" in lowered_output


def _infer_legacy_capture_status(
    capture: CommandCapture,
) -> tuple[CommandCapture, str | None]:
    if capture.status is not CaptureStatus.OBSERVED:
        return capture, None
    semantic = _CAPTURE_SEMANTICS.get(capture.name)
    if _is_legacy_negative_sentinel(capture, semantic):
        if semantic != "selinux":
            return capture, None
    diagnostic = classify_shell_diagnostic(capture.stdout)
    if diagnostic is None:
        return capture, None
    inferred_status = {
        "inaccessible": CaptureStatus.INACCESSIBLE,
        "timeout": CaptureStatus.TIMEOUT,
        "command_error": CaptureStatus.COMMAND_ERROR,
        "unsupported": CaptureStatus.UNSUPPORTED,
    }[diagnostic]
    return (
        replace(
            capture,
            status=inferred_status,
            timed_out=inferred_status is CaptureStatus.TIMEOUT,
            stdout="",
            stderr=(f"legacy {inferred_status.value} inferred from diagnostic output"),
        ),
        f"legacy capture {capture.name} inferred {inferred_status.value} "
        "from diagnostic output",
    )


def _magisk_capture_syntax_is_valid(text: str) -> bool:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if line.count("=") != 1:
            return False
        key, value = line.strip().split("=", 1)
        if key in values:
            return False
        if key in {"magisk_binary_visibility", "zygisk_visibility"}:
            if value not in {"observed", "observed_absent"}:
                return False
        elif key == "magisk_version_code":
            if re.fullmatch(r"[0-9]{1,12}", value) is None:
                return False
        elif key in {"magisk_version_name", "module_context"}:
            if re.fullmatch(r"[A-Za-z0-9._:+-]{1,128}", value) is None:
                return False
        else:
            return False
        values[key] = value
    return {"magisk_binary_visibility", "zygisk_visibility"} <= set(values)


def _root_capture_syntax_is_valid(text: str) -> bool:
    values: dict[str, str] = {}
    grammar = {
        "observer_effective_uid_is_root": {"observed", "observed_absent"},
        "root_shell_available": {"observed", "observed_absent"},
        "su_binary_observed": {"observed", "observed_absent"},
        "su_invocation_tested": {"observed", "observed_absent"},
        "su_invocation_result": {
            "succeeded",
            "non_root",
            "denied",
            "failed",
            "not_tested",
        },
        "root_management_artifact_observed": {"observed", "observed_absent"},
    }
    for line in text.splitlines():
        if line.count("=") != 1:
            return False
        key, value = line.strip().split("=", 1)
        if key in values or key not in grammar or value not in grammar[key]:
            return False
        values[key] = value
    if set(values) != set(grammar):
        return False
    tested = values["su_invocation_tested"] == "observed"
    has_result = values["su_invocation_result"] != "not_tested"
    return tested == has_result


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
        input_format: MountFormat | Literal["auto"] = _mount_source_format(capture.name)
        if capture.name == "mounts":
            input_format = "auto"
        result = parse_mounts_with_diagnostics(
            capture.stdout,
            input_format=input_format,
            evidence_path=capture.source_ref,
        )
        return bool(result["records"]) and all(
            isinstance(mount["mount_point"], str)
            and mount["mount_point"].startswith("/")
            and mount["fs_type"] is not None
            for mount in result["records"]
        )
    if semantic == "identity":
        return parse_id(capture.stdout)["uid"] != "unknown"
    if semantic == "selinux":
        return parse_getenforce(capture.stdout) != "unknown"
    if semantic == "selinux_context":
        return (
            parse_selinux_context(
                capture.stdout,
                evidence_path=capture.source_ref,
            )["parse_status"]
            == "parsed"
        )
    if semantic == "selinux_denials":
        return bool(capture.stdout.strip())
    if semantic == "magisk":
        return _magisk_capture_syntax_is_valid(capture.stdout)
    if semantic == "root_probe":
        return _root_capture_syntax_is_valid(capture.stdout)
    if semantic == "processes":
        scope: ProcessScope = (
            "selected"
            if is_selected_process_capture(capture.name, capture.source_ref)
            else "complete"
        )
        process_result = parse_process_evidence(
            capture.stdout,
            scope=scope,
            evidence_path=capture.source_ref,
        )
        return process_result["parse_status"] in {"complete", "partial"}
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
        return (
            semantic
            in {
                "su_paths",
                "root_probe",
                "magisk",
                "processes",
                "selinux_context",
                "selinux_denials",
            }
            or semantic is None
        )
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
            isinstance(mount["mount_point"], str)
            and mount["mount_point"].startswith("/")
            for mount in parse_mounts(capture.stdout)
        )
    return _observed_capture_syntax_is_valid(capture, semantic)


def _parsed_capture_names(
    captures: Sequence[CommandCapture], *, fail_on_malformed: bool
) -> tuple[frozenset[str], tuple[str, ...]]:
    parsed: set[str] = set()
    warnings: list[str] = []
    usable_mount_source_exists = any(
        _CAPTURE_SEMANTICS.get(candidate.name) == "mounts"
        and _capture_syntax_is_valid(candidate, reject_diagnostics=fail_on_malformed)
        for candidate in captures
    )
    for capture in captures:
        if _capture_syntax_is_valid(capture, reject_diagnostics=fail_on_malformed):
            parsed.add(capture.name)
        elif capture.status in {CaptureStatus.OBSERVED, CaptureStatus.EMPTY}:
            message = f"capture {capture.name} contained malformed observed output"
            is_mount_fallback_failure = (
                _CAPTURE_SEMANTICS.get(capture.name) == "mounts"
                and usable_mount_source_exists
            )
            if fail_on_malformed and not is_mount_fallback_failure:
                raise NormalizationError(message)
            if capture.status is CaptureStatus.OBSERVED or is_mount_fallback_failure:
                warnings.append(message)
    return frozenset(parsed), tuple(warnings)


def _capture_errors(captures: Sequence[CommandCapture]) -> tuple[str, ...]:
    return tuple(
        f"capture {capture.name} ended with {capture.status.value}"
        for capture in captures
        if capture.status
        in {
            CaptureStatus.COMMAND_ERROR,
            CaptureStatus.ERROR,
            CaptureStatus.TIMEOUT,
        }
    )


def _first_observed(captures: Sequence[CommandCapture], *names: str) -> str:
    name_set = frozenset(names)
    for capture in captures:
        if capture.name in name_set and capture.status in {
            CaptureStatus.OBSERVED,
            CaptureStatus.EMPTY,
        }:
            return capture.stdout
    return ""


_MOUNT_SOURCE_PRIORITY = ("mountinfo", "proc_mounts", "mounts")


def _mount_source_format(name: str) -> MountFormat:
    if name == "mountinfo":
        return "mountinfo"
    if name == "proc_mounts":
        return "proc_mounts"
    return "mount"


def _mount_fragments(
    captures: Sequence[CommandCapture],
) -> tuple[
    tuple[ParsedMount, ...],
    tuple[MountSourceAttempt, ...],
    str | None,
    str,
]:
    """Select the strongest usable mount source while preserving every attempt."""

    by_name = {
        capture.name: capture
        for capture in captures
        if capture.name in _MOUNT_SOURCE_PRIORITY
    }
    attempts: list[MountSourceAttempt] = []
    parsed_records: dict[str, tuple[ParsedMount, ...]] = {}
    for name in _MOUNT_SOURCE_PRIORITY:
        capture = by_name.get(name)
        if capture is None:
            continue
        input_format: MountFormat | Literal["auto"] = _mount_source_format(name)
        # The historical generic `mounts` capture accepted both common `mount`
        # output and /proc/mounts-shaped text.
        if name == "mounts":
            input_format = "auto"
        if capture.status is CaptureStatus.OBSERVED:
            result = parse_mounts_with_diagnostics(
                capture.stdout,
                input_format=input_format,
                evidence_path=capture.source_ref,
            )
            records = (
                tuple(
                    parse_mounts(
                        capture.stdout,
                        evidence_path=capture.source_ref,
                    )
                )
                if name == "mounts"
                else tuple(result["records"])
            )
            nonempty_line_count = sum(
                1 for line in capture.stdout.splitlines() if line.strip()
            )
            malformed_line_count = (
                nonempty_line_count - len(records)
                if name == "mounts"
                else result["malformed_line_count"]
            )
            parse_status = result["parse_status"]
            if name == "mounts":
                if not records:
                    parse_status = "malformed"
                elif malformed_line_count or any(
                    record["parse_status"] == "partial" for record in records
                ):
                    parse_status = "partial"
                else:
                    parse_status = "complete"
            record_formats = {record["format"] for record in records}
            attempt_format: MountSourceFormat = result["format"]
            if len(record_formats) > 1:
                attempt_format = "mixed"
            parsed_records[name] = records
            attempt = MountSourceAttempt(
                name=name,
                format=attempt_format,
                capture_status=capture.status,
                parse_status=parse_status,
                source_ref=capture.source_ref,
                record_count=len(records),
                malformed_line_count=malformed_line_count,
                warnings=(
                    (f"mount capture omitted {malformed_line_count} malformed line(s)",)
                    if name == "mounts" and malformed_line_count
                    else tuple(result["warnings"])
                ),
            )
        else:
            attempt = MountSourceAttempt(
                name=name,
                format=_mount_source_format(name),
                capture_status=capture.status,
                parse_status="empty"
                if capture.status is CaptureStatus.EMPTY
                else "not_parsed",
                source_ref=capture.source_ref,
                record_count=0,
                malformed_line_count=0,
                warnings=(),
            )
        attempts.append(attempt)

    selected = next(
        (name for name in _MOUNT_SOURCE_PRIORITY if parsed_records.get(name)),
        None,
    )
    if selected is None:
        reason = "no mount capture contained a usable record"
        return (), tuple(attempts), None, reason

    higher_priority = _MOUNT_SOURCE_PRIORITY[: _MOUNT_SOURCE_PRIORITY.index(selected)]
    if higher_priority:
        unavailable = (
            ", ".join(name for name in higher_priority if name in by_name)
            or "higher-priority sources"
        )
        reason = f"selected {selected} after {unavailable} was unavailable or unusable"
    else:
        reason = "selected preferred mountinfo source"
    return parsed_records[selected], tuple(attempts), selected, reason


def _fragments_from_captures(captures: Sequence[CommandCapture]) -> EvidenceFragments:
    properties_text = _first_observed(captures, "properties", "getprop_selected")
    boot_text = _first_observed(captures, "boot_state")
    mounts, mount_attempts, selected_mount_source, mount_selection_reason = (
        _mount_fragments(captures)
    )
    identity_text = _first_observed(captures, "identity", "id")
    selinux_text = _first_observed(captures, "selinux_mode", "getenforce")
    if any(
        capture.name in {"selinux_mode", "getenforce"}
        and capture.status is CaptureStatus.INACCESSIBLE
        for capture in captures
    ):
        selinux_text = "inaccessible"
    context_text = _first_observed(
        captures,
        "selinux_context",
        "collector_context",
        "app_context",
    )
    cmdline_text = _first_observed(captures, "kernel_cmdline")
    su_text = _first_observed(captures, "su_paths")
    root_probe_text = _first_observed(captures, "root_probe")
    magisk_text = _first_observed(captures, "magisk")
    process_capture = next(
        (
            capture
            for capture in captures
            if capture.name in {"processes", "ps_selected"}
            and capture.status in {CaptureStatus.OBSERVED, CaptureStatus.EMPTY}
        ),
        None,
    )
    process_text = process_capture.stdout if process_capture is not None else ""
    process_scope: ProcessScope = (
        "selected"
        if process_capture is not None
        and is_selected_process_capture(
            process_capture.name,
            process_capture.source_ref,
        )
        else "complete"
        if process_capture is not None
        else "unknown"
    )
    process_evidence = parse_process_evidence(
        process_text,
        scope=process_scope,
        evidence_path=process_capture.source_ref if process_capture else "unknown",
    )
    return EvidenceFragments(
        properties=parse_getprop(properties_text),
        boot_state=parse_key_values(boot_text),
        mounts=mounts,
        mount_attempts=mount_attempts,
        mount_selected_source=selected_mount_source,
        mount_selection_reason=mount_selection_reason,
        identity=parse_id(identity_text),
        selinux_mode=parse_getenforce(selinux_text),
        selinux_context=parse_selinux_context(
            context_text,
            evidence_path=next(
                (
                    capture.source_ref
                    for capture in captures
                    if capture.name
                    in {"selinux_context", "collector_context", "app_context"}
                    and capture.status is CaptureStatus.OBSERVED
                ),
                "unknown",
            ),
        ),
        cmdline=cmdline_text,
        su_paths=tuple(parse_paths(su_text)),
        root_probe_text=root_probe_text,
        magisk_text=magisk_text,
        processes=parse_processes(process_text),
        process_evidence=process_evidence,
    )


class LegacySectionedTextAdapter:
    input_kind = InputKind.LEGACY_SECTIONED_TEXT
    supported_schema_versions = frozenset({"legacy-sectioned-text-1"})
    supported_collector_versions = frozenset({"legacy"})

    def parse(self, text: str, *, source_ref: str) -> ArtifactParseResult:
        raw = parse_raw_text(text)
        captures: list[CommandCapture] = []
        inference_warnings: list[str] = []
        declared_sections = set(raw["section_names"])
        aliases = {
            "properties": ("GETPROP", "PROPS"),
            "boot_state": ("BOOT_STATE",),
            "mountinfo": ("MOUNTINFO",),
            "proc_mounts": ("PROC_MOUNTS",),
            "mounts": ("MOUNT", "MOUNTS"),
            "identity": ("ID",),
            "selinux_mode": ("GETENFORCE", "SELINUX"),
            "selinux_context": ("SELINUX_CONTEXT", "SELINUX_CONTEXTS"),
            "selinux_denials": ("SELINUX_DENIALS",),
            "kernel_cmdline": ("CMDLINE",),
            "su_paths": ("SU_PATHS",),
            "root_probe": ("ROOT_PROBE",),
            "magisk": ("MAGISK",),
            "processes": ("PS", "PROCESSES", "PS_SELECTED"),
        }
        for capture_name, section_names in aliases.items():
            selected_section = next(
                (name for name in section_names if name in raw["sections"]),
                next(
                    (name for name in section_names if name in declared_sections),
                    section_names[0],
                ),
            )
            content = raw["sections"].get(selected_section, "")
            present = any(name in declared_sections for name in section_names)
            status = (
                CaptureStatus.OBSERVED
                if content
                else CaptureStatus.EMPTY
                if present
                else CaptureStatus.NOT_COLLECTED
            )
            capture, inference_warning = _infer_legacy_capture_status(
                CommandCapture(
                    name=capture_name,
                    status=status,
                    exit_code=None,
                    timed_out=False,
                    stdout=content,
                    stderr="",
                    source_ref=f"legacy-sections/{selected_section}",
                )
            )
            _validate_capture_outcome(capture)
            captures.append(capture)
            if inference_warning is not None:
                inference_warnings.append(inference_warning)
        parsed_names, parse_warnings = _parsed_capture_names(
            captures, fail_on_malformed=False
        )
        sanitized_captures = tuple(
            capture
            for capture in captures
            if _legacy_capture_has_usable_fragments(capture)
            or _CAPTURE_SEMANTICS.get(capture.name) == "mounts"
            # The portable process model must retain a parser outcome even when
            # a legacy ps layout is unsupported.  The structured parser only
            # emits selected names, sanitized contexts, and source references;
            # it never carries the raw rows into the report.
            or _CAPTURE_SEMANTICS.get(capture.name) == "processes"
            or (
                capture.name in {"selinux_mode", "getenforce"}
                and capture.status is CaptureStatus.INACCESSIBLE
            )
        )
        fragments = replace(
            _fragments_from_captures(sanitized_captures),
            sections=raw["sections"],
            section_occurrences=raw["section_occurrences"],
        )
        return ArtifactParseResult(
            input_kind=self.input_kind,
            metadata=ArtifactMetadata("legacy-sectioned-text-1", "legacy"),
            captures=tuple(captures),
            warnings=_bounded_warnings(
                (
                    "legacy sectioned text has inferred command status and no collector manifest",
                ),
                raw["warnings"],
                inference_warnings,
                parse_warnings,
            ),
            errors=_capture_errors(captures),
            fragments=fragments,
            parsed_capture_names=parsed_names,
        )


def _legacy_host_captures(
    text: str,
) -> tuple[tuple[CommandCapture, ...], tuple[str, ...]]:
    raw = parse_raw_text(text)
    declared_sections = set(raw["section_names"])
    aliases = {
        "host_os": "HOST_OS",
        "adb_version": "ADB_VERSION",
        "emulator_version": "EMULATOR_VERSION",
        "python_version": "PYTHON_VERSION",
    }
    captures: list[CommandCapture] = []
    warnings: list[str] = []
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
        capture, warning = _infer_legacy_capture_status(
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
        _validate_capture_outcome(capture)
        captures.append(capture)
        if warning is not None:
            warnings.append(warning)
    return tuple(captures), tuple(warnings)


class ManifestAdapter:
    supported_schema_versions = frozenset({"1.0.0"})
    supported_collector_versions = frozenset({"0.3.0", "0.3.0-dev0", "1.0.0"})

    def __init__(self, input_kind: InputKind) -> None:
        self.input_kind = input_kind

    def parse(self, text: str, *, source_ref: str) -> ArtifactParseResult:
        parser_warnings = list(validate_parser_text(text))
        document = _strict_json(
            text,
            text_validated=True,
            warning_sink=parser_warnings,
        )
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
        first_error = next(
            Draft202012Validator(
                load_schema(schema_name), format_checker=FormatChecker()
            ).iter_errors(document),
            None,
        )
        if first_error is not None:
            raise NormalizationError(f"artifact JSON does not match {schema_name}")
        captures = _captures(document, input_kind=self.input_kind)
        parsed_names, parse_warnings = _parsed_capture_names(
            captures, fail_on_malformed=True
        )
        return self._result(
            document,
            metadata,
            captures,
            parsed_names,
            parser_warnings=(*parser_warnings, *parse_warnings),
        )

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
        *,
        parser_warnings: Sequence[str] = (),
    ) -> ArtifactParseResult:
        errors = _capture_errors(captures)
        warnings_value = document.get("warnings", [])
        if not isinstance(warnings_value, list) or not all(
            isinstance(item, str) for item in warnings_value
        ):
            raise NormalizationError("manifest warnings must be an array of strings")
        portable_source_warnings = tuple(
            f"source artifact warning {index + 1} withheld"
            for index, _warning in enumerate(warnings_value)
        )
        return ArtifactParseResult(
            input_kind=self.input_kind,
            metadata=metadata,
            captures=captures,
            warnings=_bounded_warnings(parser_warnings, portable_source_warnings),
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
        host_warnings: tuple[str, ...] = ()
        if self.input_kind is InputKind.HOST_COLLECTION_MANIFEST:
            host_captures, host_warnings = _legacy_host_captures(text)
            available_captures = (*available_captures, *host_captures)
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
        warnings = _bounded_warnings(
            (
                "portable collection manifest selected the observer-specific adapter; "
                "legacy payload has inferred per-command status",
            ),
            tuple(
                f"ignored observer-inapplicable legacy capture: {name}"
                for name in ignored
            ),
            legacy.warnings[1:],
            host_warnings,
        )
        return replace(
            legacy,
            input_kind=self.input_kind,
            metadata=metadata,
            captures=captures,
            warnings=warnings,
            errors=_capture_errors(captures),
            fragments=replace(
                _fragments_from_captures(captures),
                sections=legacy.fragments.sections,
                section_occurrences=legacy.fragments.section_occurrences,
            ),
            parsed_capture_names=parsed_names,
        )


APP_PROBE_V2_IDS = (
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

_APP_REDACTION_FIELDS = frozenset(
    {
        "build_fingerprint_hashed",
        "diagnostics_categorized",
        "file_paths_replaced",
        "installer_package_categorized",
        "mount_fields_allowlisted",
        "selinux_categories_removed",
    }
)


def _app_object(value: object, *, field_name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise NormalizationError(f"app probe field {field_name!r} must be an object")
    return value


def _app_probe_v2_metadata(document: Mapping[str, object]) -> ArtifactMetadata:
    collector = _app_object(document.get("collector"), field_name="collector")
    observer = _app_object(document.get("observer"), field_name="observer")
    target = _app_object(document.get("target"), field_name="target")
    return ArtifactMetadata(
        schema_version=_required_string(
            document.get("schema_version"), field_name="schema_version"
        ),
        collector_version=_required_string(
            collector.get("version"), field_name="collector.version"
        ),
        observer_type=_required_string(
            observer.get("observer_type"), field_name="observer.observer_type"
        ),
        collection_method=_required_string(
            observer.get("collection_method"),
            field_name="observer.collection_method",
        ),
        experiment_id=_required_string(
            document.get("experiment_id"), field_name="experiment_id"
        ),
        target_type=_required_string(
            target.get("target_type"), field_name="target.target_type"
        ),
        collection_timestamp=_required_string(
            document.get("ended_at"), field_name="ended_at"
        ),
    )


def _parse_rfc3339(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise NormalizationError(f"app probe field {field_name!r} must be a timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NormalizationError(
            f"app probe field {field_name!r} must be a timestamp"
        ) from exc


def _validate_app_probe_v2_semantics(  # noqa: C901 - closed cross-field contract stays auditable
    document: Mapping[str, object],
) -> None:
    probes_value = document.get("probes")
    if not isinstance(probes_value, list):
        raise NormalizationError("app probe results must be an array")
    probe_ids = tuple(
        probe.get("probe_id") if isinstance(probe, dict) else None
        for probe in probes_value
    )
    if probe_ids != APP_PROBE_V2_IDS:
        raise NormalizationError("app probe results must use the canonical probe order")

    started = _parse_rfc3339(document.get("started_at"), field_name="started_at")
    ended = _parse_rfc3339(document.get("ended_at"), field_name="ended_at")
    if ended < started:
        raise NormalizationError("app probe end timestamp precedes its start")

    redaction = _app_object(
        document.get("redaction_policy"), field_name="redaction_policy"
    )
    applied = redaction.get("applied_fields")
    if not isinstance(applied, list) or frozenset(applied) != _APP_REDACTION_FIELDS:
        raise NormalizationError("app probe redaction policy is incomplete")

    statuses = tuple(
        _capture_status(probe.get("status"), capture_name=str(probe.get("probe_id")))
        for probe in probes_value
        if isinstance(probe, dict)
    )
    expected_completion = (
        "partial"
        if any(
            status in {CaptureStatus.INACCESSIBLE, CaptureStatus.ERROR}
            for status in statuses
        )
        else "complete"
    )
    if document.get("completion_status") != expected_completion:
        raise NormalizationError(
            "app probe completion status does not match probe outcomes"
        )

    probes = {
        str(probe["probe_id"]): probe
        for probe in probes_value
        if isinstance(probe, dict)
    }
    install = probes["install_source"]
    if install.get("status") == "observed":
        install_value = _app_object(
            install.get("value"), field_name="install_source.value"
        )
        present = install_value.get("installer_present")
        category = install_value.get("source_category")
        if (present is False) != (category == "none"):
            raise NormalizationError(
                "app install-source category does not match source presence"
            )

    emulator = probes["emulator_indicators"]
    target = _app_object(document.get("target"), field_name="target")
    if emulator.get("status") == "observed":
        emulator_value = _app_object(
            emulator.get("value"), field_name="emulator_indicators.value"
        )
        indicators = emulator_value.get("indicators")
        outcome = emulator_value.get("outcome")
        if not isinstance(indicators, list) or (
            (outcome == "indicated") != bool(indicators)
        ):
            raise NormalizationError(
                "app emulator outcome does not match its selected indicators"
            )
        expected_target = "avd" if indicators else "unknown"
        if target.get("target_type") != expected_target:
            raise NormalizationError(
                "app target type does not match emulator indicator evidence"
            )
    elif target.get("target_type") != "unknown":
        raise NormalizationError(
            "app target type requires observed emulator indicator evidence"
        )

    expected_file_fields = {
        "file_system_shell": ("system_shell", "captures/file_system_shell.txt"),
        "file_system_su": ("system_su", "captures/file_system_su.txt"),
        "file_system_xbin_su": (
            "system_xbin_su",
            "captures/file_system_xbin_su.txt",
        ),
        "file_vendor_bin_su": (
            "vendor_bin_su",
            "captures/file_vendor_bin_su.txt",
        ),
        "file_sbin_su": ("sbin_su", "captures/file_sbin_su.txt"),
    }
    for probe_id, (path_id, source_ref) in expected_file_fields.items():
        probe = probes[probe_id]
        if probe.get("source_ref") != source_ref:
            raise NormalizationError("app file probe source reference is inconsistent")
        if probe.get("status") != "observed":
            continue
        value = _app_object(probe.get("value"), field_name=f"{probe_id}.value")
        if value.get("path_id") != path_id:
            raise NormalizationError("app file probe path identifier is inconsistent")
        readability = _app_object(
            value.get("read_access"), field_name=f"{probe_id}.read_access"
        )
        if value.get("exists") is False and not (
            readability.get("status") == "observed"
            and readability.get("value") is False
        ):
            raise NormalizationError(
                "an absent app file must have observed false readability"
            )


def _app_probe_v2_captures(
    document: Mapping[str, object],
) -> tuple[tuple[CommandCapture, ...], AppProbeFragments]:
    probes_value = document.get("probes")
    if not isinstance(probes_value, list):
        raise NormalizationError("app probe results must be an array")
    captures: list[CommandCapture] = []
    evidence: list[AppProbeEvidence] = []
    for raw_probe in probes_value:
        probe = _app_object(raw_probe, field_name="probes[]")
        probe_id = _required_string(probe.get("probe_id"), field_name="probe_id")
        status = _capture_status(probe.get("status"), capture_name=probe_id)
        source_ref = _required_string(
            probe.get("source_ref"), field_name=f"{probe_id}.source_ref"
        )
        value = probe.get("value")
        stdout = (
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            if status is CaptureStatus.OBSERVED
            else ""
        )
        capture = CommandCapture(
            name=probe_id,
            status=status,
            exit_code=None,
            timed_out=False,
            stdout=stdout,
            stderr="",
            source_ref=source_ref,
        )
        _validate_capture_outcome(capture)
        captures.append(capture)
        evidence.append(
            AppProbeEvidence(
                probe_id=probe_id,
                status=status,
                value=value,
                source_ref=source_ref,
            )
        )

    by_id = {item.probe_id: item for item in evidence}
    build = by_id["build_version"]
    build_value = (
        _app_object(build.value, field_name="build_version.value")
        if build.status is CaptureStatus.OBSERVED
        else None
    )
    selinux = by_id["selinux_self_context"]
    selinux_value = (
        _app_object(selinux.value, field_name="selinux_self_context.value")
        if selinux.status is CaptureStatus.OBSERVED
        else None
    )
    emulator = by_id["emulator_indicators"]
    emulator_value = (
        _app_object(emulator.value, field_name="emulator_indicators.value")
        if emulator.status is CaptureStatus.OBSERVED
        else None
    )
    indicators = emulator_value.get("indicators") if emulator_value else None
    if indicators is not None and not (
        isinstance(indicators, list)
        and all(isinstance(item, str) for item in indicators)
    ):
        raise NormalizationError("app emulator indicators must be strings")
    base_context = selinux_value.get("base_context") if selinux_value else None
    if base_context is not None and not isinstance(base_context, str):
        raise NormalizationError("app SELinux base context must be a string")
    app_fragments = AppProbeFragments(
        evidence=tuple(evidence),
        android_version=(
            str(build_value["release"]) if build_value is not None else None
        ),
        sdk=(str(build_value["sdk_int"]) if build_value is not None else None),
        selinux_context=(
            parse_selinux_context(base_context, evidence_path=selinux.source_ref)
            if base_context is not None
            else _empty_context()
        ),
        emulator_indicators=(
            tuple(str(item) for item in indicators) if indicators is not None else None
        ),
    )
    return tuple(captures), app_fragments


class AppProbeAdapter(ManifestAdapter):
    supported_schema_versions = frozenset({"1.0.0", "2.0.0"})

    def parse(self, text: str, *, source_ref: str) -> ArtifactParseResult:
        parser_warnings = list(validate_parser_text(text))
        document = _strict_json(
            text,
            text_validated=True,
            warning_sink=parser_warnings,
        )
        declared_kind = _required_string(
            document.get("artifact_kind"), field_name="artifact_kind"
        )
        if declared_kind != self.input_kind.value:
            raise NormalizationError("artifact kind does not match selected adapter")
        version = _required_string(
            document.get("schema_version"), field_name="schema_version"
        )
        if version == "1.0.0":
            return super().parse(text, source_ref=source_ref)
        if version not in self.supported_schema_versions:
            raise UnsupportedSchemaVersionError("unsupported app probe schema version")
        metadata = _app_probe_v2_metadata(document)
        self._validate_metadata(metadata)
        schema_name = schema_resource_name(SchemaFamily.APP_PROBE, version)
        first_error = next(
            Draft202012Validator(
                load_schema(schema_name), format_checker=FormatChecker()
            ).iter_errors(document),
            None,
        )
        if first_error is not None:
            raise NormalizationError(f"artifact JSON does not match {schema_name}")
        _validate_app_probe_v2_semantics(document)
        captures, app_fragments = _app_probe_v2_captures(document)
        parsed_names, parse_warnings = _parsed_capture_names(
            captures, fail_on_malformed=True
        )
        return ArtifactParseResult(
            input_kind=self.input_kind,
            metadata=metadata,
            captures=captures,
            warnings=_bounded_warnings(parser_warnings, parse_warnings),
            errors=_capture_errors(captures),
            fragments=EvidenceFragments(
                selinux_context=app_fragments.selinux_context,
                app_probe=app_fragments,
            ),
            parsed_capture_names=parsed_names,
        )

    def parse_manifest_payload(
        self,
        text: str,
        *,
        source_ref: str,
        metadata: ArtifactMetadata,
    ) -> ArtifactParseResult:
        """Parse the typed JSON bound by an app collection manifest."""

        if not _looks_like_json(text):
            return super().parse_manifest_payload(
                text,
                source_ref=source_ref,
                metadata=metadata,
            )
        result = self.parse(text, source_ref=source_ref)
        if result.metadata.schema_version != "2.0.0":
            raise NormalizationError(
                "app collection manifests require the typed v2 app probe"
            )
        declared = result.metadata
        comparisons = {
            "collector version": (
                declared.collector_version,
                metadata.collector_version,
            ),
            "observer type": (declared.observer_type, metadata.observer_type),
            "collection method": (
                declared.collection_method,
                metadata.collection_method,
            ),
            "experiment ID": (declared.experiment_id, metadata.experiment_id),
            "target type": (declared.target_type, metadata.target_type),
            "collection timestamp": (
                declared.collection_timestamp,
                metadata.collection_timestamp,
            ),
        }
        mismatch = next(
            (name for name, values in comparisons.items() if values[0] != values[1]),
            None,
        )
        if mismatch is not None:
            raise NormalizationError(
                f"app probe {mismatch} does not match its collection manifest"
            )
        return result


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

    validate_parser_text(text)
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
    document = _strict_json(text, text_validated=True)
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
            limit=MAX_RAW_TEXT_BYTES,
            subject="artifact adapter input",
        )
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CollectionError(
            f"input artifact is not valid UTF-8 at byte {exc.start}: {label}"
        ) from exc
    return parse_artifact_text(
        text,
        source_ref=label,
        artifact_kind=artifact_kind,
    )
