"""Modern Android mount parsing with source-preserving uncertainty."""

from __future__ import annotations

import re
from typing import Literal, TypedDict

MountFormat = Literal["mountinfo", "proc_mounts", "mount"]
MountSourceFormat = Literal["mountinfo", "proc_mounts", "mount", "mixed"]
MountParseStatus = Literal["parsed", "partial", "malformed"]
MountSetParseStatus = Literal["complete", "partial", "malformed", "empty"]
MountAccess = Literal["read_only", "writable", "unknown"]
MountDetectionState = Literal["detected", "not_detected", "unknown"]


class ParsedPropagation(TypedDict):
    kind: Literal["private", "shared", "slave", "shared_slave", "unbindable", "unknown"]
    shared_id: int | None
    master_id: int | None
    propagate_from_id: int | None
    unbindable: bool


class ParsedMount(TypedDict):
    """One source-ordered mount record before trust interpretation."""

    record_index: int
    source_line: int
    format: MountFormat
    mount_id: int | None
    parent_id: int | None
    major_minor: str | None
    root: str | None
    mount_point: str | None
    mount_options: list[str]
    optional_fields: list[str]
    fs_type: str | None
    source: str | None
    super_options: list[str]
    propagation: ParsedPropagation
    options: list[str]
    access: MountAccess
    overlay_state: MountDetectionState
    bind_state: MountDetectionState
    overlay: bool
    bind: bool
    classification: str
    parse_status: MountParseStatus
    raw: str
    evidence_path: str


class MountParseResult(TypedDict):
    format: MountFormat
    parse_status: MountSetParseStatus
    records: list[ParsedMount]
    malformed_line_count: int
    warnings: list[str]


_MOUNTINFO_DEVICE_RE = re.compile(r"^[0-9]+:[0-9]+$")
_MOUNT_ESCAPE_RE = re.compile(r"\\([0-7]{3})")
_COMMON_MOUNT_RE = re.compile(
    r"^(?P<source>.+?)\s+on\s+(?P<mount_point>.+?)\s+"
    r"type\s+(?P<fs_type>\S+)(?:\s+\((?P<options>[^)]*)\))?\s*$"
)
_STANDARD_MOUNT_ESCAPES = {
    "011": "\t",
    "012": "\n",
    "040": " ",
    "134": "\\",
}
_MAX_MOUNT_WARNINGS = 256
_MOUNT_WARNING_LIMIT_MESSAGE = "additional mount parser warnings omitted after limit"


def _bounded_warnings(messages: list[str]) -> list[str]:
    warnings: list[str] = []
    for message in messages:
        if message in warnings or _MOUNT_WARNING_LIMIT_MESSAGE in warnings:
            continue
        if len(warnings) < _MAX_MOUNT_WARNINGS - 1:
            warnings.append(message)
        else:
            warnings.append(_MOUNT_WARNING_LIMIT_MESSAGE)
            break
    return warnings


def decode_mount_field(value: str) -> str:
    """Decode exactly the escape sequences emitted by Linux mount interfaces."""

    cursor = 0
    parts: list[str] = []
    for match in _MOUNT_ESCAPE_RE.finditer(value):
        literal = value[cursor : match.start()]
        if "\\" in literal:
            raise ValueError("mount field contains an invalid escape")
        parts.append(literal)
        code = match.group(1)
        if code not in _STANDARD_MOUNT_ESCAPES:
            raise ValueError("mount field contains a non-standard escape")
        parts.append(_STANDARD_MOUNT_ESCAPES[code])
        cursor = match.end()
    remainder = value[cursor:]
    if "\\" in remainder:
        raise ValueError("mount field contains an invalid escape")
    parts.append(remainder)
    return "".join(parts)


def _options(value: str) -> list[str]:
    if not value:
        return []
    return list(
        dict.fromkeys(
            decode_mount_field(part.strip())
            for part in value.split(",")
            if part.strip()
        )
    )


def _empty_propagation() -> ParsedPropagation:
    return {
        "kind": "unknown",
        "shared_id": None,
        "master_id": None,
        "propagate_from_id": None,
        "unbindable": False,
    }


def _propagation(optional_fields: list[str]) -> tuple[ParsedPropagation, bool]:
    propagation = _empty_propagation()
    partial = False
    prefixes = {
        "shared:": "shared_id",
        "master:": "master_id",
        "propagate_from:": "propagate_from_id",
    }
    for field in optional_fields:
        if field == "unbindable":
            propagation["unbindable"] = True
            continue
        for prefix, key in prefixes.items():
            if not field.startswith(prefix):
                continue
            suffix = field.removeprefix(prefix)
            if suffix.isdigit():
                propagation[key] = int(suffix)  # type: ignore[literal-required]
            else:
                partial = True
            break

    if propagation["unbindable"]:
        propagation["kind"] = "unbindable"
    elif propagation["shared_id"] is not None and propagation["master_id"] is not None:
        propagation["kind"] = "shared_slave"
    elif propagation["shared_id"] is not None:
        propagation["kind"] = "shared"
    elif propagation["master_id"] is not None:
        propagation["kind"] = "slave"
    elif not optional_fields:
        propagation["kind"] = "private"
    return propagation, partial


def _access(options: list[str]) -> tuple[MountAccess, bool]:
    values = set(options)
    if {"ro", "rw"}.issubset(values):
        return "unknown", True
    if "ro" in values:
        return "read_only", False
    if "rw" in values:
        return "writable", False
    return "unknown", False


def _classification(
    fs_type: str | None,
    mount_options: list[str],
    *,
    bind_state: MountDetectionState,
) -> tuple[str, MountAccess, bool]:
    access, conflicting_access = _access(mount_options)
    if fs_type == "overlay":
        return "overlay", access, conflicting_access
    if bind_state == "detected":
        return "bind mount", access, conflicting_access
    if fs_type == "tmpfs":
        return "tmpfs", access, conflicting_access
    if access == "read_only":
        return "read-only", access, conflicting_access
    if access == "writable":
        return "read-write", access, conflicting_access
    return "unknown", access, conflicting_access


def classify_mount(fs_type: str, options: list[str]) -> str:
    """Compatibility wrapper for the legacy syntactic classifier."""

    classification, _, _ = _classification(
        fs_type,
        options,
        bind_state="detected" if {"bind", "rbind"} & set(options) else "unknown",
    )
    return classification


def _malformed_record(
    raw: str,
    *,
    record_index: int,
    source_line: int,
    input_format: MountFormat,
    evidence_path: str,
) -> ParsedMount:
    return {
        "record_index": record_index,
        "source_line": source_line,
        "format": input_format,
        "mount_id": None,
        "parent_id": None,
        "major_minor": None,
        "root": None,
        "mount_point": "unknown",
        "mount_options": [],
        "optional_fields": [],
        "fs_type": None,
        "source": None,
        "super_options": [],
        "propagation": _empty_propagation(),
        "options": [],
        "access": "unknown",
        "overlay_state": "unknown",
        "bind_state": "unknown",
        "overlay": False,
        "bind": False,
        "classification": "unknown",
        "parse_status": "malformed",
        "raw": raw,
        "evidence_path": f"{evidence_path}#L{source_line}",
    }


def _finalize_record(record: ParsedMount, *, partial: bool) -> ParsedMount:
    # For mountinfo, access is a property of this mount and therefore comes from
    # mount_options. super_options describe the superblock and can disagree.
    mount_options = record["mount_options"]
    all_options = list(dict.fromkeys((*mount_options, *record["super_options"])))
    explicit_bind = bool({"bind", "rbind"} & set(all_options))
    bind_state: MountDetectionState = "detected" if explicit_bind else "unknown"
    classification, access, conflicting_access = _classification(
        record["fs_type"],
        mount_options,
        bind_state=bind_state,
    )
    overlay_state: MountDetectionState = (
        "detected" if record["fs_type"] == "overlay" else "not_detected"
    )
    record["options"] = all_options
    record["access"] = access
    record["overlay_state"] = overlay_state
    record["bind_state"] = bind_state
    record["overlay"] = overlay_state == "detected"
    record["bind"] = bind_state == "detected"
    record["classification"] = classification
    record["parse_status"] = "partial" if partial or conflicting_access else "parsed"
    return record


def _parse_mountinfo_line(
    raw: str,
    *,
    record_index: int,
    source_line: int,
    evidence_path: str,
) -> ParsedMount:
    if raw.count(" - ") != 1:
        return _malformed_record(
            raw,
            record_index=record_index,
            source_line=source_line,
            input_format="mountinfo",
            evidence_path=evidence_path,
        )
    left_text, right_text = raw.split(" - ", 1)
    left = left_text.split()
    right = right_text.split()
    if (
        len(left) < 6
        or len(right) != 3
        or not left[0].isdigit()
        or not left[1].isdigit()
        or _MOUNTINFO_DEVICE_RE.fullmatch(left[2]) is None
    ):
        return _malformed_record(
            raw,
            record_index=record_index,
            source_line=source_line,
            input_format="mountinfo",
            evidence_path=evidence_path,
        )
    try:
        root = decode_mount_field(left[3])
        mount_point = decode_mount_field(left[4])
        mount_options = _options(left[5])
        optional_fields = [decode_mount_field(field) for field in left[6:]]
        fs_type = decode_mount_field(right[0])
        source = decode_mount_field(right[1])
        super_options = _options(right[2])
    except ValueError:
        return _malformed_record(
            raw,
            record_index=record_index,
            source_line=source_line,
            input_format="mountinfo",
            evidence_path=evidence_path,
        )
    propagation, partial = _propagation(optional_fields)
    return _finalize_record(
        {
            "record_index": record_index,
            "source_line": source_line,
            "format": "mountinfo",
            "mount_id": int(left[0]),
            "parent_id": int(left[1]),
            "major_minor": left[2],
            "root": root,
            "mount_point": mount_point,
            "mount_options": mount_options,
            "optional_fields": optional_fields,
            "fs_type": fs_type,
            "source": source,
            "super_options": super_options,
            "propagation": propagation,
            "options": [],
            "access": "unknown",
            "overlay_state": "unknown",
            "bind_state": "unknown",
            "overlay": False,
            "bind": False,
            "classification": "unknown",
            "parse_status": "parsed",
            "raw": raw,
            "evidence_path": f"{evidence_path}#L{source_line}",
        },
        partial=partial,
    )


def _parse_proc_mounts_line(
    raw: str,
    *,
    record_index: int,
    source_line: int,
    evidence_path: str,
) -> ParsedMount:
    fields = raw.split()
    if len(fields) < 4:
        return _malformed_record(
            raw,
            record_index=record_index,
            source_line=source_line,
            input_format="proc_mounts",
            evidence_path=evidence_path,
        )
    try:
        source = decode_mount_field(fields[0])
        mount_point = decode_mount_field(fields[1])
        fs_type = decode_mount_field(fields[2])
        mount_options = _options(fields[3])
    except ValueError:
        return _malformed_record(
            raw,
            record_index=record_index,
            source_line=source_line,
            input_format="proc_mounts",
            evidence_path=evidence_path,
        )
    return _finalize_record(
        {
            "record_index": record_index,
            "source_line": source_line,
            "format": "proc_mounts",
            "mount_id": None,
            "parent_id": None,
            "major_minor": None,
            "root": None,
            "mount_point": mount_point,
            "mount_options": mount_options,
            "optional_fields": [],
            "fs_type": fs_type,
            "source": source,
            "super_options": [],
            "propagation": _empty_propagation(),
            "options": [],
            "access": "unknown",
            "overlay_state": "unknown",
            "bind_state": "unknown",
            "overlay": False,
            "bind": False,
            "classification": "unknown",
            "parse_status": "parsed",
            "raw": raw,
            "evidence_path": f"{evidence_path}#L{source_line}",
        },
        partial=len(fields) not in {4, 6},
    )


def _parse_common_mount_line(
    raw: str,
    *,
    record_index: int,
    source_line: int,
    evidence_path: str,
) -> ParsedMount:
    match = _COMMON_MOUNT_RE.fullmatch(raw)
    if match is None:
        return _malformed_record(
            raw,
            record_index=record_index,
            source_line=source_line,
            input_format="mount",
            evidence_path=evidence_path,
        )
    try:
        source = decode_mount_field(match.group("source"))
        mount_point = decode_mount_field(match.group("mount_point"))
        fs_type = decode_mount_field(match.group("fs_type"))
        mount_options = _options(match.group("options") or "")
    except ValueError:
        return _malformed_record(
            raw,
            record_index=record_index,
            source_line=source_line,
            input_format="mount",
            evidence_path=evidence_path,
        )
    return _finalize_record(
        {
            "record_index": record_index,
            "source_line": source_line,
            "format": "mount",
            "mount_id": None,
            "parent_id": None,
            "major_minor": None,
            "root": None,
            "mount_point": mount_point,
            "mount_options": mount_options,
            "optional_fields": [],
            "fs_type": fs_type,
            "source": source,
            "super_options": [],
            "propagation": _empty_propagation(),
            "options": [],
            "access": "unknown",
            "overlay_state": "unknown",
            "bind_state": "unknown",
            "overlay": False,
            "bind": False,
            "classification": "unknown",
            "parse_status": "parsed",
            "raw": raw,
            "evidence_path": f"{evidence_path}#L{source_line}",
        },
        partial=match.group("options") is None,
    )


def _detect_format(lines: list[str]) -> MountFormat:
    if any(" - " in line for line in lines):
        return "mountinfo"
    if any(" on " in line and " type " in line for line in lines):
        return "mount"
    return "proc_mounts"


def parse_mounts_with_diagnostics(
    text: str,
    *,
    input_format: MountFormat | Literal["auto"] = "auto",
    evidence_path: str = "legacy-sections/MOUNT",
) -> MountParseResult:
    """Parse one complete capture without blending syntaxes across its lines."""

    source_lines = [
        (line_number, line.strip())
        for line_number, line in enumerate(text.splitlines(), start=1)
        if line.strip()
    ]
    lines = [line for _, line in source_lines]
    resolved_format = _detect_format(lines) if input_format == "auto" else input_format
    parsers = {
        "mountinfo": _parse_mountinfo_line,
        "proc_mounts": _parse_proc_mounts_line,
        "mount": _parse_common_mount_line,
    }
    parsed = [
        parsers[resolved_format](
            line,
            record_index=index,
            source_line=line_number,
            evidence_path=evidence_path,
        )
        for index, (line_number, line) in enumerate(source_lines)
    ]
    records = [record for record in parsed if record["parse_status"] != "malformed"]
    malformed_count = len(parsed) - len(records)
    if not parsed:
        parse_status: MountSetParseStatus = "empty"
    elif not records:
        parse_status = "malformed"
    elif malformed_count or any(
        record["parse_status"] == "partial" for record in records
    ):
        parse_status = "partial"
    else:
        parse_status = "complete"
    warnings = _bounded_warnings(
        [
            f"mount {resolved_format} line {record['source_line']} parsed as "
            f"{record['parse_status']}"
            for record in parsed
            if record["parse_status"] != "parsed"
        ]
    )
    return {
        "format": resolved_format,
        "parse_status": parse_status,
        "records": records,
        "malformed_line_count": malformed_count,
        "warnings": warnings,
    }


def parse_mount_line(line: str) -> ParsedMount:
    result = parse_mounts_with_diagnostics(line)
    if result["records"]:
        return result["records"][0]
    return _malformed_record(
        line.strip(),
        record_index=0,
        source_line=1,
        input_format=result["format"],
        evidence_path="legacy-sections/MOUNT",
    )


def parse_mounts(
    text: str,
    *,
    evidence_path: str = "legacy-sections/MOUNT",
) -> list[ParsedMount]:
    """Parse legacy section text, whose repeated MOUNT sections may mix formats."""

    records: list[ParsedMount] = []
    for source_line, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        result = parse_mounts_with_diagnostics(raw)
        if not result["records"]:
            continue
        record = result["records"][0]
        record["record_index"] = len(records)
        record["source_line"] = source_line
        record["evidence_path"] = f"{evidence_path}#L{source_line}"
        records.append(record)
    return records
