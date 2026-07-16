"""Bounded parsers for portable SELinux and selected-process evidence."""

from __future__ import annotations

import re
from typing import Literal, TypedDict

MAX_PROCESS_LINES = 4096
MAX_SECURITY_WARNINGS = 256
WARNING_LIMIT_MESSAGE = "additional security parser warnings omitted after limit"

SelectedProcessName = Literal[
    "init",
    "adbd",
    "zygote",
    "zygote64",
    "system_server",
    "magisk",
    "magiskd",
]
SELECTED_PROCESS_NAMES: tuple[SelectedProcessName, ...] = (
    "init",
    "adbd",
    "zygote",
    "zygote64",
    "system_server",
    "magisk",
    "magiskd",
)
ProcessScope = Literal["complete", "selected", "app_sandbox", "unknown"]
SecurityParseStatus = Literal[
    "complete", "partial", "malformed", "empty", "unsupported"
]

_SELECTED_PROCESS_SET = frozenset(SELECTED_PROCESS_NAMES)
_CATEGORY = r"c[0-9]+(?:[.]c[0-9]+)?"
_CONTEXT_RE = re.compile(
    rf"^(?P<base>u:r:[a-z0-9_]+:s[0-9]+(?:-s[0-9]+)?)(?::(?:{_CATEGORY})(?:,(?:{_CATEGORY}))*)?$",
    flags=re.ASCII,
)
_HEADER_NAME_FIELDS = ("NAME", "CMD", "COMMAND")
_HEADER_CONTEXT_FIELDS = ("LABEL", "CONTEXT")


def is_selected_process_capture(name: str, source_ref: str) -> bool:
    """Classify the explicit selected-list capture profile once."""

    return name == "ps_selected" or source_ref.endswith(("/PS", "/PS_SELECTED"))


class ParsedContext(TypedDict):
    parse_status: Literal["parsed", "empty", "malformed"]
    value: str | None
    evidence_refs: list[str]
    warnings: list[str]


class ParsedSelectedProcess(TypedDict):
    name: SelectedProcessName
    contexts: list[str]
    evidence_refs: list[str]


class ParsedProcessSet(TypedDict):
    format: Literal["toybox", "toolbox", "selected", "unknown"]
    scope: ProcessScope
    parse_status: SecurityParseStatus
    observations: list[ParsedSelectedProcess]
    malformed_line_count: int
    warnings: list[str]


def _bounded_warnings(messages: list[str]) -> list[str]:
    warnings: list[str] = []
    for message in messages:
        if message in warnings or WARNING_LIMIT_MESSAGE in warnings:
            continue
        if len(warnings) < MAX_SECURITY_WARNINGS - 1:
            warnings.append(message)
        else:
            warnings.append(WARNING_LIMIT_MESSAGE)
            break
    return warnings


def sanitize_selinux_context(value: str) -> str | None:
    """Return one safe Android process context without retaining raw text."""

    context = value.strip()
    if len(context) > 255 or (match := _CONTEXT_RE.fullmatch(context)) is None:
        return None
    # MLS categories can correlate with Android app/user assignments. The
    # portable form keeps the policy domain and sensitivity level only.
    return match.group("base")


def parse_selinux_context(
    text: str, *, evidence_path: str = "unknown"
) -> ParsedContext:
    """Parse a current process context, ignoring filesystem-context rows."""

    lines = [
        (number, line.strip())
        for number, line in enumerate(text.splitlines(), start=1)
        if line.strip()
    ]
    if not lines:
        return {
            "parse_status": "empty",
            "value": None,
            "evidence_refs": [],
            "warnings": [],
        }
    context_refs: dict[str, set[str]] = {}
    for number, line in lines:
        context = sanitize_selinux_context(line)
        if context is not None:
            context_refs.setdefault(context, set()).add(f"{evidence_path}#L{number}")
    contexts = sorted(context_refs)
    if len(contexts) == 1:
        warnings = []
        if len(lines) > 1:
            warnings.append("ignored non-process SELinux context rows")
        return {
            "parse_status": "parsed",
            "value": contexts[0],
            "evidence_refs": sorted(context_refs[contexts[0]]),
            "warnings": warnings,
        }
    reason = (
        "SELinux context capture contains conflicting current contexts"
        if contexts
        else "SELinux context capture has no supported current context"
    )
    return {
        "parse_status": "malformed",
        "value": None,
        "evidence_refs": [],
        "warnings": [reason],
    }


def _process_name(value: str) -> SelectedProcessName | None:
    candidate = value.strip().rsplit("/", 1)[-1]
    if candidate in _SELECTED_PROCESS_SET:
        return candidate
    return None


def _looks_truncated(value: str) -> bool:
    candidate = value.strip().rsplit("/", 1)[-1]
    return candidate.endswith(("+", "...", "…"))


def _header_indices(
    tokens: list[str],
) -> tuple[int, int | None, int | None] | None:
    upper = [token.upper() for token in tokens]
    name_indices = [
        index for index, field in enumerate(upper) if field in _HEADER_NAME_FIELDS
    ]
    context_indices = [
        index for index, field in enumerate(upper) if field in _HEADER_CONTEXT_FIELDS
    ]
    pid_indices = [index for index, field in enumerate(upper) if field == "PID"]
    if (
        len(name_indices) != 1
        or len(context_indices) > 1
        or len(pid_indices) > 1
        or len(set(upper)) != len(upper)
    ):
        return None
    name_index = name_indices[0]
    # A trailing process-name field is required so command arguments can never
    # be mistaken for separate table columns or retained as evidence.
    if name_index != len(tokens) - 1:
        return None
    context_index = context_indices[0] if context_indices else None
    pid_index = pid_indices[0] if pid_indices else None
    return name_index, context_index, pid_index


def _looks_like_unsupported_header(tokens: list[str]) -> bool:
    """Recognize a table header without guessing where its process name lives."""

    upper = [token.upper() for token in tokens]
    return "PID" in upper and any(
        field in upper for field in ("USER", "UID", "ARGS", "CMDLINE")
    )


def _selected_line(tokens: list[str]) -> tuple[SelectedProcessName, str | None] | None:
    if len(tokens) == 1:
        name = _process_name(tokens[0])
        return (name, None) if name is not None else None
    if len(tokens) == 2:
        name = _process_name(tokens[1])
        context = sanitize_selinux_context(tokens[0])
        if name is not None and context is not None:
            return name, context
    if len(tokens) == 5 and tokens[2].isdigit() and tokens[3].isdigit():
        name = _process_name(tokens[4])
        context = sanitize_selinux_context(tokens[0])
        if name is not None and context is not None:
            return name, context
    return None


def _collect_process_rows(
    rows: list[tuple[int, list[str]]],
    *,
    table_format: Literal["toybox", "toolbox", "selected", "unknown"],
    name_index: int,
    context_index: int | None,
    pid_index: int | None,
    expected_fields: int | None,
    evidence_path: str,
) -> tuple[dict[SelectedProcessName, dict[str, set[str]]], list[int]]:
    observations: dict[SelectedProcessName, dict[str, set[str]]] = {}
    malformed_lines: list[int] = []
    for line_number, tokens in rows:
        if table_format == "selected":
            selected = _selected_line(tokens)
            if selected is None:
                malformed_lines.append(line_number)
                continue
            name, context = selected
        else:
            if (
                expected_fields is None
                or len(tokens) != expected_fields
                or name_index >= len(tokens)
                or (pid_index is not None and not tokens[pid_index].isdigit())
                or (context_index is not None and context_index >= len(tokens))
            ):
                malformed_lines.append(line_number)
                continue
            parsed_name = _process_name(tokens[name_index])
            if parsed_name is None:
                if _looks_truncated(tokens[name_index]):
                    malformed_lines.append(line_number)
                continue
            name = parsed_name
            context = (
                sanitize_selinux_context(tokens[context_index])
                if context_index is not None
                else None
            )
            if context_index is not None and context is None:
                malformed_lines.append(line_number)
        if name not in observations:
            observations[name] = {"contexts": set(), "evidence_refs": set()}
        if context is not None:
            observations[name]["contexts"].add(context)
        observations[name]["evidence_refs"].add(f"{evidence_path}#L{line_number}")
    return observations, malformed_lines


def parse_processes(
    text: str,
    *,
    scope: ProcessScope,
    evidence_path: str,
) -> ParsedProcessSet:
    """Parse supported ps tables or an explicitly selected process list."""

    source_lines = [
        (number, line.strip())
        for number, line in enumerate(text.splitlines(), start=1)
        if line.strip()
    ]
    if not source_lines:
        return {
            "format": "selected" if scope == "selected" else "unknown",
            "scope": scope,
            "parse_status": "empty",
            "observations": [],
            "malformed_line_count": 0,
            "warnings": [],
        }
    if len(source_lines) > MAX_PROCESS_LINES:
        source_lines = source_lines[:MAX_PROCESS_LINES]
        truncated = True
    else:
        truncated = False

    header = _header_indices(source_lines[0][1].split())
    table_format: Literal["toybox", "toolbox", "selected", "unknown"]
    rows: list[tuple[int, list[str]]]
    if header is not None:
        name_index, context_index, pid_index = header
        table_format = "toybox" if context_index is not None else "toolbox"
        rows = [(number, line.split()) for number, line in source_lines[1:]]
        expected_fields: int | None = len(source_lines[0][1].split())
    elif _looks_like_unsupported_header(source_lines[0][1].split()):
        return {
            "format": "unknown",
            "scope": scope,
            "parse_status": "unsupported",
            "observations": [],
            "malformed_line_count": len(source_lines),
            "warnings": ["process table has no supported header"],
        }
    elif scope in {"selected", "app_sandbox"}:
        name_index = 0
        context_index = None
        pid_index = None
        expected_fields = None
        table_format = "selected"
        rows = [(number, line.split()) for number, line in source_lines]
    else:
        return {
            "format": "unknown",
            "scope": scope,
            "parse_status": "unsupported",
            "observations": [],
            "malformed_line_count": len(source_lines),
            "warnings": ["process table has no supported header"],
        }

    observations, malformed_lines = _collect_process_rows(
        rows,
        table_format=table_format,
        name_index=name_index,
        context_index=context_index,
        pid_index=pid_index,
        expected_fields=expected_fields,
        evidence_path=evidence_path,
    )

    warnings = [
        f"process line {line_number} was not safely parseable"
        for line_number in malformed_lines
    ]
    if truncated:
        warnings.append(f"process input truncated after {MAX_PROCESS_LINES} lines")
    if not rows and header is not None:
        parse_status: SecurityParseStatus = "complete"
    elif malformed_lines or truncated:
        parse_status = "partial" if observations or header is not None else "malformed"
    else:
        parse_status = "complete"
    return {
        "format": table_format,
        "scope": scope,
        "parse_status": parse_status,
        "observations": [
            {
                "name": name,
                "contexts": sorted(observations[name]["contexts"]),
                "evidence_refs": sorted(observations[name]["evidence_refs"]),
            }
            for name in SELECTED_PROCESS_NAMES
            if name in observations
        ],
        "malformed_line_count": len(malformed_lines),
        "warnings": _bounded_warnings(warnings),
    }
