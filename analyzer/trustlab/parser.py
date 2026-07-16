"""Parsers for raw Android Trust Lab artifacts."""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Literal, TypedDict

from .bounded_io import read_bounded_regular_file
from .exceptions import CollectionError, NormalizationError, safe_path_label
from .mounts import (
    ParsedMount as ParsedMount,
)
from .mounts import (
    classify_mount as classify_mount,
)
from .mounts import (
    parse_mount_line as parse_mount_line,
)
from .mounts import (
    parse_mounts as parse_mounts,
)
from .security_evidence import parse_processes as parse_process_evidence

MAX_RAW_TEXT_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024
MAX_SECTION_COUNT = 64
MAX_SECTION_NAME_CHARS = 64
MAX_ENTRIES_PER_SECTION = 4096
MAX_PARSER_WARNINGS = 256
PARSER_WARNING_LIMIT_MESSAGE = "additional parser warnings omitted after limit"


class ParsedIdentity(TypedDict):
    uid: str
    user: str
    gid: str
    group: str
    raw: str


class ParsedProcesses(TypedDict):
    raw_line_count: int
    init_visible: bool
    adbd_visible: bool
    zygote_visible: bool
    system_server_visible: bool
    magisk_processes_visible: bool
    process_contexts_available: bool


class RawParsedArtifact(TypedDict):
    sections: dict[str, str]
    section_names: list[str]
    section_occurrences: dict[str, int]
    warnings: list[str]
    properties: dict[str, str]
    boot_state_raw: dict[str, str]
    mounts: list[ParsedMount]
    id: ParsedIdentity
    selinux_mode: str
    cmdline: str
    su_paths: list[str]
    magisk: str
    processes: ParsedProcesses


SECTION_RE = re.compile(
    r"^===\s*([A-Z0-9_. -]+)\s*===\s*$",
    flags=re.IGNORECASE | re.ASCII,
)
GETPROP_RE = re.compile(r"^\[([^\]]+)\]:\s*\[(.*)\]\s*$")
ID_RE = re.compile(r"uid=(\d+)\(([^)]*)\)\s+gid=(\d+)\(([^)]*)\)")

KNOWN_SECTION_NAMES = frozenset(
    {
        "GETPROP",
        "PROPS",
        "BOOT_STATE",
        "MOUNT",
        "MOUNTINFO",
        "MOUNTS",
        "PROC_MOUNTS",
        "ID",
        "GETENFORCE",
        "SELINUX",
        "SELINUX_CONTEXT",
        "SELINUX_CONTEXTS",
        "SELINUX_DENIALS",
        "CMDLINE",
        "SU_PATHS",
        "MAGISK",
        "PS",
        "PS_SELECTED",
        "PROCESSES",
        "HOST_OS",
        "ADB_VERSION",
        "EMULATOR_VERSION",
        "PYTHON_VERSION",
    }
)


class ParsedSections(TypedDict):
    sections: dict[str, str]
    section_names: list[str]
    section_occurrences: dict[str, int]
    warnings: list[str]


def _append_warning(warnings: list[str], message: str) -> None:
    if message in warnings or PARSER_WARNING_LIMIT_MESSAGE in warnings:
        return
    if len(warnings) < MAX_PARSER_WARNINGS - 1:
        warnings.append(message)
    elif len(warnings) < MAX_PARSER_WARNINGS:
        warnings.append(PARSER_WARNING_LIMIT_MESSAGE)


def validate_parser_text(text: str) -> tuple[str, ...]:
    """Enforce the shared decoded-text envelope before syntax parsing."""

    try:
        byte_size = len(text.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise NormalizationError(
            f"artifact text contains an invalid Unicode scalar at character {exc.start}"
        ) from exc
    if byte_size > MAX_RAW_TEXT_BYTES:
        raise NormalizationError("artifact text exceeds the total byte limit")

    line_number = 1
    column = 0
    previous_was_cr = False
    for character in text:
        if character == "\n":
            if not previous_was_cr:
                line_number += 1
            column = 0
            previous_was_cr = False
            continue
        if character == "\r":
            line_number += 1
            column = 0
            previous_was_cr = True
            continue
        previous_was_cr = False
        column += 1
        if character == "\x00":
            raise NormalizationError(
                f"artifact text contains NUL at line {line_number}, column {column}"
            )
        if unicodedata.category(character) == "Cc" and character not in {
            "\t",
            "\r",
        }:
            raise NormalizationError(
                "artifact text contains a control character "
                f"at line {line_number}, column {column}"
            )

    for index, line in enumerate(text.splitlines(), start=1):
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise NormalizationError(
                f"artifact line {index} exceeds the line byte limit"
            )
    warnings: list[str] = []
    if "\r" in text:
        warnings.append("CR/CRLF line endings normalized during parsing")
    return tuple(warnings)


def _parse_sections(text: str) -> ParsedSections:
    warnings = list(validate_parser_text(text))
    section_lines: dict[str, list[str]] = {"UNSECTIONED": []}
    section_entries: dict[str, int] = {"UNSECTIONED": 0}
    occurrences: dict[str, int] = {}
    names: list[str] = []
    current = "UNSECTIONED"
    header_count = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped_line = line.strip()
        match = SECTION_RE.fullmatch(stripped_line)
        if match:
            header_count += 1
            if header_count > MAX_SECTION_COUNT:
                raise NormalizationError("artifact exceeds the section count limit")
            current = match.group(1).strip().upper().replace(" ", "_")
            if not current:
                raise NormalizationError(
                    f"artifact has an empty section header at line {line_number}"
                )
            if len(current) > MAX_SECTION_NAME_CHARS:
                raise NormalizationError(
                    f"artifact section header at line {line_number} exceeds the name limit"
                )
            names.append(current)
            occurrences[current] = occurrences.get(current, 0) + 1
            section_lines.setdefault(current, [])
            section_entries.setdefault(current, 0)
            if occurrences[current] > 1:
                _append_warning(
                    warnings,
                    f"duplicate section {current} occurrence {occurrences[current]} concatenated",
                )
            if current not in KNOWN_SECTION_NAMES:
                _append_warning(
                    warnings,
                    f"unrecognized section {current} preserved for provenance only",
                )
            continue
        if stripped_line.startswith("==="):
            raise NormalizationError(
                f"artifact has a malformed section header at line {line_number}"
            )
        section_entries[current] = section_entries.get(current, 0) + 1
        if section_entries[current] > MAX_ENTRIES_PER_SECTION:
            raise NormalizationError(
                f"artifact section {current} exceeds the entry count limit"
            )
        section_lines.setdefault(current, []).append(line)

    sections = {
        key: "\n".join(value).strip()
        for key, value in section_lines.items()
        if "\n".join(value).strip()
    }
    return {
        "sections": sections,
        "section_names": names,
        "section_occurrences": occurrences,
        "warnings": warnings,
    }


def _select_section_alias(
    sections: dict[str, str],
    section_occurrences: dict[str, int],
    aliases: tuple[str, ...],
    *,
    semantic: str,
    warnings: list[str],
) -> str:
    declared = [name for name in aliases if name in section_occurrences]
    populated = [name for name in aliases if sections.get(name)]
    selected = populated[0] if populated else declared[0] if declared else aliases[0]
    if len(declared) > 1:
        bodies = [sections.get(name, "") for name in declared]
        kind = "duplicate" if len(set(bodies)) == 1 else "conflicting"
        _append_warning(
            warnings,
            f"{kind} aliases for {semantic}; {selected} takes precedence",
        )
    return sections.get(selected, "")


def split_sections(text: str) -> dict[str, str]:
    return _parse_sections(text)["sections"]


def section_names(text: str) -> frozenset[str]:
    """Return every declared section, including sections with empty output."""

    return frozenset(_parse_sections(text)["section_names"])


def parse_getprop(text: str) -> dict[str, str]:
    props, _ = _parse_getprop_with_diagnostics(text)
    return props


def _parse_getprop_with_diagnostics(
    text: str,
) -> tuple[dict[str, str], list[str]]:
    props: dict[str, str] = {}
    warnings: list[str] = []
    malformed_count = 0
    for entry_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        match = GETPROP_RE.match(line.strip())
        if not match:
            malformed_count += 1
            continue
        key, value = match.groups()
        if key in props:
            kind = "duplicate" if props[key] == value else "conflicting"
            _append_warning(
                warnings,
                f"{kind} GETPROP key at entry {entry_number}; last occurrence wins",
            )
        props[key] = value
    if malformed_count:
        _append_warning(
            warnings,
            f"ignored {malformed_count} malformed GETPROP entries",
        )
    return props, warnings


def parse_key_values(text: str) -> dict[str, str]:
    values, _ = _parse_key_values_with_diagnostics(text)
    return values


def _parse_key_values_with_diagnostics(
    text: str,
) -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {}
    warnings: list[str] = []
    malformed_count = 0
    for entry_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or "=" not in line:
            if line:
                malformed_count += 1
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            malformed_count += 1
            continue
        if key in values:
            kind = "duplicate" if values[key] == value else "conflicting"
            _append_warning(
                warnings,
                f"{kind} BOOT_STATE key at entry {entry_number}; last occurrence wins",
            )
        values[key] = value
    if malformed_count:
        _append_warning(
            warnings,
            f"ignored {malformed_count} malformed BOOT_STATE entries",
        )
    return values, warnings


def parse_id(text: str) -> ParsedIdentity:
    match = ID_RE.search(text.strip())
    if not match:
        return {
            "uid": "unknown",
            "user": "unknown",
            "gid": "unknown",
            "group": "unknown",
            "raw": text.strip(),
        }
    return {
        "uid": match.group(1),
        "user": match.group(2),
        "gid": match.group(3),
        "group": match.group(4),
        "raw": text.strip(),
    }


def parse_getenforce(text: str) -> str:
    value = text.strip().lower()
    if value in {"enforcing", "permissive", "disabled", "inaccessible"}:
        return value
    if "permission denied" in value:
        return "inaccessible"
    return "unknown"


def classify_shell_diagnostic(
    text: str,
) -> Literal["inaccessible", "timeout", "command_error", "unsupported"] | None:
    """Classify a recognizable shell/command diagnostic without echoing it."""

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if GETPROP_RE.fullmatch(line) or re.fullmatch(
            r"[A-Za-z0-9_.-]+\s*=.*", line, flags=re.ASCII
        ):
            continue
        if line.startswith("/") and not any(character.isspace() for character in line):
            continue
        lowered = line.lower()
        if lowered == "trustlab: inaccessible":
            return "inaccessible"
        if lowered == "trustlab: unsupported":
            return "unsupported"
        if lowered == "trustlab: command error":
            return "command_error"
        if re.search(
            r"(?:^|:\s)(?:permission denied|operation not permitted|access denied)(?:$|\s)",
            lowered,
        ) or re.search(r"(?:^|\s)inaccessible(?:$|\s)", lowered):
            return "inaccessible"
        if (
            re.search(r"(?:^|\s)timed out(?:$|\s)", lowered)
            or lowered == "timeout"
            or lowered.startswith("timeout:")
        ):
            return "timeout"
        if (
            lowered in {"not found", "unavailable"}
            or re.search(r"(?:^|\s)command not found(?:$|\s)", lowered)
            or re.search(r"(?:^|\s)no such file(?: or directory)?(?:$|\s)", lowered)
            or re.search(r":\s*not found(?:\s+in\s+path)?$", lowered)
            or re.search(r"(?:^|\s)unavailable$", lowered)
            or lowered.startswith(("error:", "failed:", "sh:"))
            or lowered.startswith("/system/bin/sh:")
        ):
            return "command_error"
    return None


def is_shell_diagnostic(text: str) -> bool:
    """Return whether captured text contains a shell/command failure diagnostic."""

    return classify_shell_diagnostic(text) is not None


def parse_paths(text: str) -> list[str]:
    values = []
    for line in text.splitlines():
        line = line.strip()
        if (
            line.startswith("/")
            and not any(character.isspace() for character in line)
            and not is_shell_diagnostic(line)
        ):
            values.append(line)
    return values


def parse_processes(text: str) -> ParsedProcesses:
    parsed = parse_process_evidence(
        text,
        scope="selected",
        evidence_path="legacy-sections/PS",
    )
    names = {observation["name"] for observation in parsed["observations"]}
    return {
        "raw_line_count": sum(1 for line in text.splitlines() if line.strip()),
        "init_visible": "init" in names,
        "adbd_visible": "adbd" in names,
        "zygote_visible": bool({"zygote", "zygote64"} & names),
        "system_server_visible": "system_server" in names,
        "magisk_processes_visible": bool({"magisk", "magiskd"} & names),
        "process_contexts_available": any(
            observation["contexts"] for observation in parsed["observations"]
        ),
    }


def parse_raw_text(text: str) -> RawParsedArtifact:
    """Parse one already-decoded raw report snapshot."""

    parsed_sections = _parse_sections(text)
    sections = parsed_sections["sections"]
    warnings = list(parsed_sections["warnings"])
    properties_text = _select_section_alias(
        sections,
        parsed_sections["section_occurrences"],
        ("GETPROP", "PROPS"),
        semantic="property sections",
        warnings=warnings,
    )
    mounts_text = _select_section_alias(
        sections,
        parsed_sections["section_occurrences"],
        ("MOUNT", "MOUNTS"),
        semantic="mount sections",
        warnings=warnings,
    )
    selinux_text = _select_section_alias(
        sections,
        parsed_sections["section_occurrences"],
        ("GETENFORCE", "SELINUX"),
        semantic="SELinux sections",
        warnings=warnings,
    )
    processes_text = _select_section_alias(
        sections,
        parsed_sections["section_occurrences"],
        ("PS", "PROCESSES"),
        semantic="process sections",
        warnings=warnings,
    )
    properties, property_warnings = _parse_getprop_with_diagnostics(properties_text)
    boot_state, boot_warnings = _parse_key_values_with_diagnostics(
        sections.get("BOOT_STATE", "")
    )
    for warning in (*property_warnings, *boot_warnings):
        _append_warning(warnings, warning)
    return {
        "sections": sections,
        "section_names": sorted(set(parsed_sections["section_names"])),
        "section_occurrences": parsed_sections["section_occurrences"],
        "warnings": warnings,
        "properties": properties,
        "boot_state_raw": boot_state,
        "mounts": parse_mounts(mounts_text),
        "id": parse_id(sections.get("ID", "")),
        "selinux_mode": parse_getenforce(selinux_text),
        "cmdline": sections.get("CMDLINE", ""),
        "su_paths": parse_paths(sections.get("SU_PATHS", "")),
        "magisk": sections.get("MAGISK", ""),
        "processes": parse_processes(processes_text),
    }


def parse_raw_report(path: str | Path) -> RawParsedArtifact:
    """Compatibility wrapper for callers that still pass a legacy text path."""

    source = Path(path)
    label = safe_path_label(source)
    payload = read_bounded_regular_file(
        source,
        limit=MAX_RAW_TEXT_BYTES,
        subject="raw parser input",
    )
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CollectionError(
            f"raw artifact is not valid UTF-8 at byte {exc.start}: {label}"
        ) from exc
    return parse_raw_text(text)
