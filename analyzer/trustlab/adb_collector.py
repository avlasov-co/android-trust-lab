"""Read-only, allowlisted ADB collection with portable provenance."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Final, Literal

from ._version import __version__
from .exceptions import CollectionError, OutputWriteError, safe_path_label
from .host_collector import (
    _close_windows_job,
    _create_windows_job_for_process,
    _is_posix,
    _is_windows,
    _RunningProcess,
    _terminate_process_tree,
)
from .mounts import MountFormat, parse_mounts_with_diagnostics
from .privacy import (
    contains_sensitive_identifier,
    sanitize_mount_model,
    sanitize_property_value,
)
from .security_evidence import parse_processes, parse_selinux_context
from .validators import validate_collection_manifest

DEFAULT_COMMAND_TIMEOUT_SECONDS: Final = 10.0
PROCESS_CLEANUP_SECONDS: Final = 1.0
MAX_CAPTURE_BYTES: Final = 2 * 1024 * 1024
COMPLETION_MANIFEST_NAME: Final = "collector_manifest.json"
RAW_REPORT_NAME: Final = "adb_snapshot.txt"
ADB_PROVENANCE_NAME: Final = "adb_provenance.json"
LOCK_NAME: Final = ".trustlab-adb.lock"
PROJECT_SALT_NAME: Final = ".trustlab-adb-project-salt"
PROJECT_STATE_DIR_NAME: Final = ".trustlab-adb-private"
_PROJECT_SALT_BYTES: Final = 32
_TARGET_PLACEHOLDER: Final = "<selected-target>"

AdbStatus = Literal[
    "observed",
    "observed_absent",
    "inaccessible",
    "command_error",
    "unsupported",
]
AdbReason = Literal[
    "none",
    "command_error",
    "missing_command",
    "offline",
    "output_limit",
    "permission_denied",
    "projection_error",
    "timeout",
    "unauthorized",
]
OutputKind = Literal[
    "preflight",
    "property",
    "identity",
    "selinux_mode",
    "selinux_context",
    "mountinfo",
    "proc_mounts",
    "processes",
]


@dataclass(frozen=True, slots=True)
class AdbCommand:
    probe_id: str
    logical_name: str
    adb_args: tuple[str, ...]
    output_kind: OutputKind
    section_name: str | None
    sensitivity: Literal["internal", "sensitive", "restricted"]
    targeted: bool = True
    property_key: str | None = None

    def execution_argv(self, serial: str) -> tuple[str, ...]:
        selector = ("-s", serial) if self.targeted else ()
        return ("adb", *selector, *self.adb_args)

    def portable_argv(self, target_id: str) -> tuple[str, ...]:
        del target_id
        selector = ("-s", _TARGET_PLACEHOLDER) if self.targeted else ()
        return ("adb", *selector, *self.adb_args)


@dataclass(frozen=True, slots=True)
class AdbCommandResult:
    probe_id: str
    status: AdbStatus
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    reason: AdbReason = "none"


@dataclass(frozen=True, slots=True)
class ProjectedResult:
    command: AdbCommand
    status: AdbStatus
    exit_code: int | None
    timed_out: bool
    payload: str
    stdout_status: str
    stderr_status: str
    reason: AdbReason
    timeout_seconds: float

    def provenance(self, target_id: str) -> dict[str, Any]:
        return {
            "probe_id": self.command.probe_id,
            "argv": list(self.command.portable_argv(target_id)),
            "timeout_seconds": self.timeout_seconds,
            "status": self.status,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout_status": self.stdout_status,
            "stderr_status": self.stderr_status,
            "sensitivity": self.command.sensitivity,
            "redaction": "projected" if self.payload else "withheld",
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class AdbCollectionResult:
    collection_id: str
    target_id: str
    directory: Path
    manifest_path: Path


PROPERTY_KEYS: Final = (
    "ro.boot.verifiedbootstate",
    "ro.boot.flash.locked",
    "ro.boot.vbmeta.device_state",
    "ro.boot.veritymode",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.debuggable",
    "ro.secure",
    "ro.adb.secure",
    "sys.boot_completed",
    "ro.kernel.qemu",
)

PREFLIGHT_COMMAND: Final = AdbCommand(
    "adb.device_selection",
    "device_selection",
    ("devices",),
    "preflight",
    None,
    "restricted",
    targeted=False,
)
TARGET_STATE_COMMAND: Final = AdbCommand(
    "adb.target_state",
    "target_state",
    ("get-state",),
    "preflight",
    None,
    "restricted",
)
PROPERTY_COMMANDS: Final = tuple(
    AdbCommand(
        f"adb.property.{key.replace('.', '_')}",
        f"property_{key.replace('.', '_')}",
        ("shell", "getprop", key),
        "property",
        "GETPROP",
        "sensitive",
        property_key=key,
    )
    for key in PROPERTY_KEYS
)
IDENTITY_COMMAND: Final = AdbCommand(
    "adb.identity",
    "identity",
    ("shell", "id"),
    "identity",
    "ID",
    "sensitive",
)
SELINUX_MODE_COMMAND: Final = AdbCommand(
    "adb.getenforce",
    "getenforce",
    ("shell", "getenforce"),
    "selinux_mode",
    "GETENFORCE",
    "internal",
)
MOUNTINFO_COMMAND: Final = AdbCommand(
    "adb.mountinfo",
    "mountinfo",
    ("shell", "cat", "/proc/self/mountinfo"),
    "mountinfo",
    "MOUNTINFO",
    "sensitive",
)
PROC_MOUNTS_COMMAND: Final = AdbCommand(
    "adb.proc_mounts",
    "proc_mounts",
    ("shell", "cat", "/proc/mounts"),
    "proc_mounts",
    "PROC_MOUNTS",
    "sensitive",
)
SELINUX_CONTEXT_COMMAND: Final = AdbCommand(
    "adb.selinux_context",
    "selinux_context",
    ("shell", "id", "-Z"),
    "selinux_context",
    "SELINUX_CONTEXT",
    "sensitive",
)
PS_SELECTED_COMMAND: Final = AdbCommand(
    "adb.ps_selected",
    "ps_selected",
    ("shell", "ps", "-A", "-o", "LABEL,NAME"),
    "processes",
    "PS_SELECTED",
    "restricted",
)
PS_SELECTED_FALLBACK_COMMAND: Final = AdbCommand(
    "adb.ps_selected_fallback",
    "ps_selected_fallback",
    ("shell", "ps", "-A", "-o", "NAME"),
    "processes",
    "PS_SELECTED",
    "restricted",
)
ADB_COMMANDS: Final = (
    PREFLIGHT_COMMAND,
    TARGET_STATE_COMMAND,
    *PROPERTY_COMMANDS,
    IDENTITY_COMMAND,
    SELINUX_MODE_COMMAND,
    MOUNTINFO_COMMAND,
    PROC_MOUNTS_COMMAND,
    SELINUX_CONTEXT_COMMAND,
    PS_SELECTED_COMMAND,
    PS_SELECTED_FALLBACK_COMMAND,
)

_SERIAL_RE: Final = re.compile(r"(?!-)[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ID_RE: Final = re.compile(
    r"\buid=(?P<uid>[0-9]{1,10})\((?P<user>[A-Za-z0-9_]+)\)\s+"
    r"gid=(?P<gid>[0-9]{1,10})\((?P<group>[A-Za-z0-9_]+)\)"
)
_SAFE_ID_NAMES: Final = frozenset({"root", "shell", "system"})
_PERMISSION_RE: Final = re.compile(
    r"(?:permission denied|operation not permitted|access denied|no permissions)",
    flags=re.IGNORECASE,
)
_MISSING_COMMAND_RE: Final = re.compile(
    r"(?:command not found|not found|no such file or directory|unknown option)",
    flags=re.IGNORECASE,
)
_OFFLINE_RE: Final = re.compile(r"device\s+offline", flags=re.IGNORECASE)
_UNAUTHORIZED_RE: Final = re.compile(r"device\s+unauthorized", flags=re.IGNORECASE)
_ADB_STATUSES: Final = frozenset(
    {"observed", "observed_absent", "inaccessible", "command_error", "unsupported"}
)
_ADB_REASONS: Final = frozenset(
    {
        "none",
        "command_error",
        "missing_command",
        "offline",
        "output_limit",
        "permission_denied",
        "projection_error",
        "timeout",
        "unauthorized",
    }
)


def _validate_serial(serial: str) -> str:
    if _SERIAL_RE.fullmatch(serial) is None:
        raise CollectionError("ADB serial has an unsafe format")
    return serial


def _safe_environment(environment: Mapping[str, str]) -> dict[str, str]:
    allowed = (
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "HOME",
        "USERPROFILE",
        "ADB_VENDOR_KEYS",
    )
    # Home/key locations are needed for authorization but are never published.
    return {key: environment[key] for key in allowed if key in environment}


def _execution_argv(
    argv: tuple[str, ...], environment: Mapping[str, str]
) -> list[str] | None:
    if not _is_windows():
        return list(argv)
    executable = shutil.which("adb.exe", path=environment.get("PATH", ""))
    return [executable, *argv[1:]] if executable is not None else None


def _drain_bounded(stream: BinaryIO, retained: bytearray) -> None:
    try:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            remaining = MAX_CAPTURE_BYTES + 1 - len(retained)
            if remaining > 0:
                retained.extend(chunk[:remaining])
    except OSError:
        pass


def _join_readers(readers: Sequence[threading.Thread], deadline: float) -> None:
    for reader in readers:
        reader.join(timeout=max(0.0, deadline - time.monotonic()))


def _decode_output(value: bytes) -> str | None:
    try:
        text = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if any(
        (ord(character) < 32 and character not in "\n\r\t") or ord(character) == 127
        for character in text
    ):
        return None
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _classify_failure(stderr: str) -> tuple[AdbStatus, AdbReason]:
    if _PERMISSION_RE.search(stderr):
        return "inaccessible", "permission_denied"
    if _MISSING_COMMAND_RE.search(stderr):
        return "unsupported", "missing_command"
    if _OFFLINE_RE.search(stderr):
        return "command_error", "offline"
    if _UNAUTHORIZED_RE.search(stderr):
        return "command_error", "unauthorized"
    return "command_error", "command_error"


def _finish_adb_process(
    command: AdbCommand,
    running: _RunningProcess,
    *,
    timeout_seconds: float,
) -> AdbCommandResult:
    process = running.process
    if process.stdout is None or process.stderr is None:
        _terminate_process_tree(running)
        raise CollectionError("ADB command capture pipes were not created")
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    readers = (
        threading.Thread(
            target=_drain_bounded, args=(process.stdout, stdout_buffer), daemon=True
        ),
        threading.Thread(
            target=_drain_bounded, args=(process.stderr, stderr_buffer), daemon=True
        ),
    )
    for reader in readers:
        reader.start()
    timed_out = False
    deadline = time.monotonic() + timeout_seconds
    try:
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_tree(running)
    _join_readers(readers, deadline)
    if any(reader.is_alive() for reader in readers):
        timed_out = True
        _terminate_process_tree(running)
    cleanup_deadline = time.monotonic() + PROCESS_CLEANUP_SECONDS
    try:
        process.wait(timeout=max(0.0, cleanup_deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        raise CollectionError("ADB command did not terminate after timeout") from exc
    _join_readers(readers, cleanup_deadline)
    if any(reader.is_alive() for reader in readers):
        raise CollectionError("ADB command output capture did not terminate")
    process.stdout.close()
    process.stderr.close()
    if timed_out:
        return AdbCommandResult(
            command.probe_id, "command_error", None, True, "", "", "timeout"
        )
    if len(stdout_buffer) > MAX_CAPTURE_BYTES or len(stderr_buffer) > MAX_CAPTURE_BYTES:
        return AdbCommandResult(
            command.probe_id,
            "command_error",
            None,
            False,
            "",
            "",
            "output_limit",
        )
    stdout = _decode_output(bytes(stdout_buffer))
    stderr = _decode_output(bytes(stderr_buffer))
    if stdout is None or stderr is None:
        return AdbCommandResult(
            command.probe_id,
            "command_error",
            None,
            False,
            "",
            "",
            "projection_error",
        )
    if process.returncode != 0:
        status, reason = _classify_failure(stderr)
        exit_code = process.returncode if isinstance(process.returncode, int) else None
        return AdbCommandResult(
            command.probe_id,
            status,
            exit_code,
            False,
            "",
            stderr,
            reason,
        )
    if stderr:
        status, reason = _classify_failure(stderr)
        if reason != "command_error":
            return AdbCommandResult(
                command.probe_id, status, 0, False, "", stderr, reason
            )
    return AdbCommandResult(
        command.probe_id,
        "observed" if stdout else "observed_absent",
        0,
        False,
        stdout,
        stderr,
    )


def run_adb_command(  # noqa: C901 - explicit process-state handling stays local
    command: AdbCommand,
    serial: str,
    *,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    cwd: Path | None = None,
    environment: Mapping[str, str] = os.environ,
) -> AdbCommandResult:
    """Run one immutable reviewed ADB argument array with bounded capture."""

    if command not in ADB_COMMANDS:
        raise CollectionError("ADB command is not in the reviewed allowlist")
    serial = _validate_serial(serial)
    if timeout_seconds <= 0 or timeout_seconds > 60:
        raise CollectionError("ADB command timeout is outside the safe range")
    logical_argv = command.execution_argv(serial)
    safe_environment = _safe_environment(environment)
    execution_argv = _execution_argv(logical_argv, safe_environment)
    if execution_argv is None:
        return AdbCommandResult(
            command.probe_id,
            "unsupported",
            None,
            False,
            "",
            "",
            "missing_command",
        )
    try:
        creationflags = 0
        if _is_windows():
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x0200)
            creationflags |= getattr(subprocess, "CREATE_SUSPENDED", 0x0004)
        process = subprocess.Popen(
            execution_argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=safe_environment,
            start_new_session=_is_posix(),
            creationflags=creationflags,
        )
    except FileNotFoundError:
        return AdbCommandResult(
            command.probe_id,
            "unsupported",
            None,
            False,
            "",
            "",
            "missing_command",
        )
    except PermissionError:
        return AdbCommandResult(
            command.probe_id,
            "inaccessible",
            None,
            False,
            "",
            "",
            "permission_denied",
        )
    except OSError:
        return AdbCommandResult(
            command.probe_id,
            "command_error",
            None,
            False,
            "",
            "",
            "command_error",
        )
    running = _RunningProcess(process)
    if _is_windows():
        try:
            running.windows_job_handle = _create_windows_job_for_process(process)
        except OSError as exc:
            try:
                process.kill()
            except OSError:
                pass
            raise CollectionError(
                "Windows ADB process isolation could not be established"
            ) from exc
    try:
        return _finish_adb_process(command, running, timeout_seconds=timeout_seconds)
    except BaseException:
        _terminate_process_tree(running)
        raise
    finally:
        _close_windows_job(running)


def _validate_result(command: AdbCommand, result: AdbCommandResult) -> AdbCommandResult:
    if result.probe_id != command.probe_id:
        raise CollectionError("ADB command runner returned mismatched provenance")
    if result.status not in _ADB_STATUSES or result.reason not in _ADB_REASONS:
        raise CollectionError("ADB command runner returned an invalid status")
    if isinstance(result.exit_code, bool) or (
        result.exit_code is not None
        and (
            not isinstance(result.exit_code, int)
            or not -(2**31) <= result.exit_code < 2**32
        )
    ):
        raise CollectionError("ADB command runner returned an invalid exit code")
    if any(
        len(value.encode("utf-8")) > MAX_CAPTURE_BYTES
        or _decode_output(value.encode("utf-8")) is None
        for value in (result.stdout, result.stderr)
    ):
        raise CollectionError("ADB command runner returned unsafe output")
    if type(result.timed_out) is not bool:
        raise CollectionError("ADB command timeout provenance is not boolean")
    if result.timed_out and (
        result.status != "command_error"
        or result.exit_code is not None
        or result.reason != "timeout"
    ):
        raise CollectionError("timed-out ADB provenance is inconsistent")
    if result.status == "observed" and (
        result.exit_code != 0
        or result.timed_out
        or not result.stdout
        or result.reason != "none"
    ):
        raise CollectionError("observed ADB provenance is inconsistent")
    if result.status == "observed_absent" and (
        result.exit_code != 0
        or result.timed_out
        or result.stdout
        or result.reason != "none"
    ):
        raise CollectionError("empty ADB provenance is inconsistent")
    if result.status == "unsupported" and (
        result.timed_out or result.stdout or result.reason != "missing_command"
    ):
        raise CollectionError("unsupported ADB provenance is inconsistent")
    if result.status == "inaccessible" and (
        result.timed_out or result.stdout or result.reason != "permission_denied"
    ):
        raise CollectionError("inaccessible ADB provenance is inconsistent")
    if result.status == "command_error" and (
        (result.timed_out and result.exit_code is not None)
        or (
            not result.timed_out
            and result.exit_code == 0
            and result.reason != "projection_error"
        )
        or result.reason
        not in {
            "command_error",
            "offline",
            "output_limit",
            "projection_error",
            "timeout",
            "unauthorized",
        }
    ):
        raise CollectionError("failed ADB provenance is inconsistent")
    return result


def _preflight(result: AdbCommandResult, serial: str) -> None:
    result = _validate_result(PREFLIGHT_COMMAND, result)
    failures = {
        "missing_command": "missing command",
        "timeout": "timeout",
        "permission_denied": "permission denied",
    }
    if result.status not in {"observed", "observed_absent"}:
        reason = failures.get(result.reason, "command error")
        raise CollectionError(f"ADB preflight failed: {reason}")
    rows: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped == "List of devices attached":
            continue
        if stripped.startswith("* daemon "):
            continue
        fields = stripped.split()
        if len(fields) < 2:
            raise CollectionError("ADB preflight returned malformed device state")
        rows.append((fields[0], " ".join(fields[1:])))
    matching = [state for candidate, state in rows if candidate == serial]
    authorized = [candidate for candidate, state in rows if state == "device"]
    if len(rows) > 1 or len(matching) > 1 or len(authorized) > 1:
        raise CollectionError("ADB preflight failed: multiple devices")
    if len(rows) == 1 and rows[0][1].startswith("no permissions"):
        raise CollectionError("ADB preflight failed: permission denied")
    if not matching:
        raise CollectionError("ADB preflight failed: target not found")
    state = matching[0]
    if state == "offline":
        raise CollectionError("ADB preflight failed: offline")
    if state == "unauthorized":
        raise CollectionError("ADB preflight failed: unauthorized")
    if state.startswith("no permissions"):
        raise CollectionError("ADB preflight failed: permission denied")
    if state != "device":
        raise CollectionError("ADB preflight failed: target not authorized")
    if authorized != [serial]:
        raise CollectionError("ADB preflight failed: multiple devices")


def _confirm_target_state(result: AdbCommandResult) -> None:
    result = _validate_result(TARGET_STATE_COMMAND, result)
    if result.status not in {"observed", "observed_absent"}:
        reason = {
            "missing_command": "missing command",
            "timeout": "timeout",
            "permission_denied": "permission denied",
            "offline": "offline",
            "unauthorized": "unauthorized",
        }.get(result.reason, "command error")
        raise CollectionError(f"ADB target-state preflight failed: {reason}")
    if result.stdout.strip() != "device":
        raise CollectionError("ADB target-state preflight returned an invalid state")


def _stderr_status(result: AdbCommandResult) -> str:
    if result.timed_out:
        return "timeout"
    if not result.stderr:
        return "empty"
    if result.reason in {
        "missing_command",
        "offline",
        "permission_denied",
        "unauthorized",
    }:
        return result.reason
    return "withheld"


def _project_property(command: AdbCommand, text: str, *, scope: str) -> str | None:
    key = command.property_key
    if key is None or key not in PROPERTY_KEYS:
        raise CollectionError("ADB property is not in the reviewed allowlist")
    value = text.strip()
    if not value:
        return None
    if "\n" in value or len(value) > 512:
        raise ValueError("property output has an unsupported shape")
    sanitized = sanitize_property_value(key, value, scope=scope)
    if key == "ro.kernel.qemu" and value not in {"0", "1"}:
        sanitized = "unknown"
    return f"[{key}]: [{sanitized}]"


def _project_identity(text: str) -> str:
    match = _ID_RE.search(text.strip())
    if match is None:
        raise ValueError("identity output has an unsupported shape")
    user = match.group("user") if match.group("user") in _SAFE_ID_NAMES else "unknown"
    group = (
        match.group("group") if match.group("group") in _SAFE_ID_NAMES else "unknown"
    )
    return f"uid={match.group('uid')}({user}) gid={match.group('gid')}({group})"


def _project_selinux_mode(text: str) -> str:
    value = text.strip().lower()
    if value not in {"enforcing", "permissive", "disabled"}:
        raise ValueError("SELinux mode output has an unsupported shape")
    return value.capitalize()


def _project_selinux_context(text: str) -> str:
    parsed = parse_selinux_context(text, evidence_path="captures/selinux_context.txt")
    value = parsed["value"]
    if parsed["parse_status"] != "parsed" or value is None:
        raise ValueError("SELinux context output has an unsupported shape")
    return value


def _project_mounts(command: AdbCommand, text: str, *, scope: str) -> str:
    input_format: MountFormat = (
        "mountinfo" if command.output_kind == "mountinfo" else "proc_mounts"
    )
    parsed = parse_mounts_with_diagnostics(
        text,
        input_format=input_format,
        evidence_path=f"captures/{command.logical_name}.txt",
    )
    if parsed["parse_status"] in {"malformed", "partial"}:
        raise ValueError("mount output is incomplete or malformed")
    original_records = parsed["records"]
    records = sanitize_mount_model(
        {
            "records": parsed["records"],
            "observation": {},
            "dynamic_partitions": {},
            "apex_set": {},
        },
        scope=scope,
    )["records"]
    for original, record in zip(original_records, records, strict=True):
        source = str(original.get("source", ""))
        if re.fullmatch(r"/dev/block/dm-[0-9]+", source):
            record["source"] = "/dev/block/dm-0"
        elif source.startswith("/dev/block/mapper/"):
            record["source"] = "/dev/block/mapper/redacted"
    mount_ids = {
        value: index
        for index, value in enumerate(
            sorted(
                {
                    record["mount_id"]
                    for record in records
                    if isinstance(record.get("mount_id"), int)
                }
            ),
            start=1,
        )
    }
    propagation_ids = {
        value: index
        for index, value in enumerate(
            sorted(
                {
                    value
                    for record in records
                    for value in (
                        record["propagation"].get("shared_id"),
                        record["propagation"].get("master_id"),
                        record["propagation"].get("propagate_from_id"),
                    )
                    if isinstance(value, int)
                }
            ),
            start=1,
        )
    }

    def options(value: object) -> str:
        return ",".join(value) if isinstance(value, list) and value else "defaults"

    rows = []
    for index, record in enumerate(records, start=1):
        if input_format == "proc_mounts":
            rows.append(
                " ".join(
                    (
                        str(record["source"]),
                        str(record["mount_point"]),
                        str(record["fs_type"]),
                        options(record["mount_options"]),
                        "0",
                        "0",
                    )
                )
            )
            continue
        mount_id = mount_ids.get(record["mount_id"], index)
        parent_id = mount_ids.get(record["parent_id"], 0)
        propagation = record["propagation"]
        optional = []
        for field, prefix in (
            ("shared_id", "shared:"),
            ("master_id", "master:"),
            ("propagate_from_id", "propagate_from:"),
        ):
            value = propagation.get(field)
            if isinstance(value, int):
                optional.append(f"{prefix}{propagation_ids[value]}")
        if propagation.get("unbindable") is True:
            optional.append("unbindable")
        left = [
            str(mount_id),
            str(parent_id),
            f"0:{index}",
            str(record["root"]),
            str(record["mount_point"]),
            options(record["mount_options"]),
            *optional,
        ]
        right = [
            str(record["fs_type"]),
            str(record["source"]),
            options(record["super_options"]),
        ]
        rows.append(f"{' '.join(left)} - {' '.join(right)}")
    return "\n".join(rows)


def _project_processes(text: str) -> str | None:
    parsed = parse_processes(
        text, scope="selected", evidence_path="captures/ps_selected.txt"
    )
    if parsed["parse_status"] in {"malformed", "partial", "unsupported"}:
        raise ValueError("process output has an unsupported shape")
    rows = []
    for observation in parsed["observations"]:
        contexts = observation["contexts"]
        rows.append(
            f"{contexts[0]} {observation['name']}" if contexts else observation["name"]
        )
    return "\n".join(rows) or None


def _project_result(
    command: AdbCommand,
    result: AdbCommandResult,
    *,
    target_id: str,
    timeout_seconds: float,
) -> ProjectedResult:
    result = _validate_result(command, result)
    # Raw device-list rows and diagnostics are never published. Each successful
    # evidence kind below is parsed into a closed portable projection, so a
    # substring replacement cannot corrupt legitimate short values such as
    # `ro`, `1`, or an SELinux domain.
    stdout = result.stdout
    if result.status not in {"observed", "observed_absent"}:
        return ProjectedResult(
            command,
            result.status,
            result.exit_code,
            result.timed_out,
            "",
            "withheld",
            _stderr_status(result),
            result.reason,
            timeout_seconds,
        )
    if result.status == "observed_absent":
        return ProjectedResult(
            command,
            result.status,
            0,
            False,
            "",
            "empty",
            _stderr_status(result),
            "none",
            timeout_seconds,
        )
    try:
        if command is PREFLIGHT_COMMAND:
            payload = "authorized_target_count=1\nselected_state=device"
        elif command is TARGET_STATE_COMMAND:
            payload = "device"
        elif command.output_kind == "property":
            payload = _project_property(command, stdout, scope=target_id) or ""
        elif command.output_kind == "identity":
            payload = _project_identity(stdout)
        elif command.output_kind == "selinux_mode":
            payload = _project_selinux_mode(stdout)
        elif command.output_kind == "selinux_context":
            payload = _project_selinux_context(stdout)
        elif command.output_kind in {"mountinfo", "proc_mounts"}:
            payload = _project_mounts(command, stdout, scope=target_id)
        else:
            payload = _project_processes(stdout) or ""
    except ValueError:
        return ProjectedResult(
            command,
            "command_error",
            0,
            False,
            "",
            "withheld",
            _stderr_status(result),
            "projection_error",
            timeout_seconds,
        )
    if not payload:
        return ProjectedResult(
            command,
            "observed_absent",
            0,
            False,
            "",
            "empty" if command.output_kind != "preflight" else "withheld",
            _stderr_status(result),
            "none",
            timeout_seconds,
        )
    return ProjectedResult(
        command,
        "observed",
        0,
        False,
        f"{payload.rstrip()}\n",
        "projected",
        _stderr_status(result),
        "none",
        timeout_seconds,
    )


def _sentinel(result: ProjectedResult) -> str:
    if result.status == "inaccessible":
        return "trustlab: inaccessible"
    if result.status == "unsupported":
        return "trustlab: unsupported"
    if result.timed_out:
        return "timeout"
    if result.status == "command_error":
        return "trustlab: command error"
    return ""


def _raw_report(results: Sequence[ProjectedResult]) -> bytes:
    by_section: dict[str, list[ProjectedResult]] = {}
    for result in results:
        if result.command.section_name is not None:
            by_section.setdefault(result.command.section_name, []).append(result)
    sections = []
    for name in (
        "GETPROP",
        "MOUNTINFO",
        "PROC_MOUNTS",
        "ID",
        "GETENFORCE",
        "SELINUX_CONTEXT",
        "PS_SELECTED",
    ):
        candidates = by_section.get(name, [])
        payloads = [
            candidate.payload.rstrip() for candidate in candidates if candidate.payload
        ]
        if not payloads and candidates and name != "GETPROP":
            payloads = [
                value for value in (_sentinel(item) for item in candidates) if value
            ]
        sections.append(f"=== {name} ===")
        sections.extend(payloads[:1] if name == "PS_SELECTED" else payloads)
    return ("\n".join(sections).rstrip() + "\n").encode("utf-8")


def _collector_version() -> str:
    return re.sub(r"\.dev(?=[0-9])", "-dev", __version__, count=1)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _new_collection_token() -> str:
    return secrets.token_hex(8)


def _stable_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def _validate_provenance(
    document: dict[str, Any],
    *,
    collection_id: str,
    target_id: str,
    results: Sequence[ProjectedResult],
) -> None:
    if set(document) != {"schema_version", "collection_id", "target_id", "commands"}:
        raise CollectionError("ADB provenance has an invalid shape")
    if (
        document["schema_version"] != "1.0.0"
        or document["collection_id"] != collection_id
        or document["target_id"] != target_id
        or not isinstance(document["commands"], list)
        or len(document["commands"]) != len(results)
    ):
        raise CollectionError("ADB provenance does not match its collection")
    expected_fields = {
        "probe_id",
        "argv",
        "timeout_seconds",
        "status",
        "exit_code",
        "timed_out",
        "stdout_status",
        "stderr_status",
        "sensitivity",
        "redaction",
        "reason",
    }
    for item, result in zip(document["commands"], results, strict=True):
        expected = result.provenance(target_id)
        if (
            not isinstance(item, dict)
            or set(item) != expected_fields
            or item != expected
            or item["stdout_status"] not in {"empty", "projected", "withheld"}
            or item["stderr_status"]
            not in {
                "empty",
                "missing_command",
                "offline",
                "permission_denied",
                "timeout",
                "unauthorized",
                "withheld",
            }
            or item["redaction"] not in {"projected", "withheld"}
        ):
            raise CollectionError("ADB command provenance is inconsistent")


def _write_private_bytes(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)
    except OSError as exc:
        raise OutputWriteError(
            f"could not write private ADB collection output: {safe_path_label(path)}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _prepare_output_root(output_dir: str | Path) -> Path:
    if _is_windows() and sys.version_info < (3, 13):
        raise CollectionError(
            "ADB collection on Windows requires Python 3.13 or newer for private ACLs"
        )
    root = Path(output_dir)
    try:
        if root.is_symlink():
            raise CollectionError("collection output directory must not be a symlink")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not stat.S_ISDIR(root.stat().st_mode):
            raise CollectionError("collection output path must be a directory")
    except (CollectionError, OutputWriteError):
        raise
    except OSError as exc:
        raise OutputWriteError("could not prepare ADB collection output") from exc
    return root.resolve(strict=True)


def _acquire_lock(root: Path) -> tuple[int, Path]:
    path = root / LOCK_NAME
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        os.chmod(path, 0o600)
        return descriptor, path
    except FileExistsError as exc:
        raise CollectionError("another ADB collection holds the output lock") from exc
    except OSError as exc:
        raise OutputWriteError("could not acquire ADB collection lock") from exc


def _release_lock(descriptor: int, path: Path) -> None:
    failure: OSError | None = None
    try:
        os.close(descriptor)
    except OSError as exc:
        failure = exc
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        failure = failure or exc
    if failure is not None:
        raise OutputWriteError("could not release ADB collection lock") from failure


def _load_or_create_project_salt(
    root: Path, *, environment: Mapping[str, str] = os.environ
) -> bytes:
    if _is_windows():
        encoded = environment.get("TRUSTLAB_ADB_PROJECT_SALT", "")
        if re.fullmatch(r"[a-f0-9]{64}", encoded) is None:
            raise CollectionError(
                "Windows ADB collection requires a 64-hex project salt in "
                "TRUSTLAB_ADB_PROJECT_SALT"
            )
        return bytes.fromhex(encoded)
    state_dir = root / PROJECT_STATE_DIR_NAME
    try:
        if state_dir.is_symlink():
            raise CollectionError("project state directory must not be a symlink")
        state_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(state_dir, 0o700)
        state_metadata = state_dir.stat()
        if not stat.S_ISDIR(state_metadata.st_mode):
            raise CollectionError("project state path must be a private directory")
        if os.name == "posix" and (
            state_metadata.st_uid != os.getuid() or state_metadata.st_mode & 0o077
        ):
            raise CollectionError("project state directory is not private")
    except CollectionError:
        raise
    except OSError as exc:
        raise CollectionError("project state directory could not be secured") from exc
    path = state_dir / PROJECT_SALT_NAME
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        salt = secrets.token_bytes(_PROJECT_SALT_BYTES)
        _write_private_bytes(path, salt)
        return salt
    except OSError as exc:
        raise CollectionError("project salt could not be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise CollectionError("project salt must be a private regular file")
        if os.name == "posix" and metadata.st_uid != os.getuid():
            raise CollectionError("project salt must be owned by the current user")
        if os.name == "posix" and metadata.st_mode & 0o077:
            raise CollectionError("project salt permissions are not private")
        salt = os.read(descriptor, _PROJECT_SALT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(salt) != _PROJECT_SALT_BYTES:
        raise CollectionError("project salt has an invalid size")
    return salt


def _target_id(serial: str, salt: bytes) -> str:
    digest = hmac.new(salt, serial.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    return f"target-{digest}"


def _collection_paths(root: Path) -> tuple[str, Path, Path]:
    for _attempt in range(32):
        token = _new_collection_token()
        if re.fullmatch(r"[a-f0-9]{16}", token) is None:
            raise CollectionError("collection token source returned an invalid token")
        collection_id = f"atlcol-{token}"
        destination = root / collection_id
        if not destination.exists() and not destination.is_symlink():
            staging = Path(tempfile.mkdtemp(prefix=".trustlab-adb-", dir=root))
            os.chmod(staging, 0o700)
            (staging / "captures").mkdir(mode=0o700)
            return collection_id, destination, staging
    raise CollectionError("could not allocate a unique ADB collection directory")


def _artifact(
    result: ProjectedResult, payload: bytes | None, relative_path: str | None
) -> dict[str, Any]:
    portable_exit_code = (
        result.exit_code
        if isinstance(result.exit_code, int) and 0 <= result.exit_code <= 255
        else None
    )
    return {
        "logical_name": result.command.logical_name,
        "relative_path": relative_path,
        "media_type": "text/plain",
        "byte_size": len(payload) if payload is not None else None,
        "sha256": hashlib.sha256(payload).hexdigest() if payload is not None else None,
        "probe_id": result.command.probe_id,
        "status": result.status,
        "exit_code": portable_exit_code,
        "timed_out": result.timed_out,
        "sensitivity": result.command.sensitivity,
        "redaction_state": "redacted" if payload is not None else "withheld",
        "detail": None,
    }


def _completion_status(results: Sequence[ProjectedResult]) -> str:
    return (
        "partial"
        if any(
            result.status in {"inaccessible", "command_error", "unsupported"}
            for result in results
        )
        else "complete"
    )


def _target_type(results: Sequence[ProjectedResult]) -> str:
    qemu = next(
        (
            result
            for result in results
            if result.command.property_key == "ro.kernel.qemu"
        ),
        None,
    )
    if qemu is None or not qemu.payload:
        return "unknown"
    if qemu.payload.endswith("[1]\n"):
        return "avd"
    if qemu.payload.endswith("[0]\n"):
        return "physical"
    return "unknown"


def _manifest(
    *,
    collection_id: str,
    target_id: str,
    started_at: str,
    ended_at: str,
    raw_payload: bytes,
    provenance_payload: bytes,
    results: Sequence[ProjectedResult],
    artifacts: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "collection_id": collection_id,
        "schema_version": "1.0.0",
        "experiment_id": "E27_adb_collection",
        "collector": {"name": "trustlab-adb", "version": _collector_version()},
        "observer": {
            "observer_type": "adb_shell",
            "privilege_level": "shell",
            "collection_method": "adb_shell_snapshot",
        },
        "target": {
            "pseudonymous_id": target_id,
            "target_type": _target_type(results),
        },
        "started_at": started_at,
        "ended_at": ended_at,
        "completion_status": _completion_status(results),
        "tool_versions": {
            "adb": "unknown",
            "android_shell": "unknown",
            "ps": "unknown",
        },
        "environment": {
            "platform": "android",
            "transport": "adb",
            "execution_context": "adb_collector",
        },
        "warnings": [],
        "redaction_policy": {
            "policy_id": "atl_portable_v1",
            "redaction_state": "applied",
            "direct_identifiers_removed": True,
            "serials_removed": True,
            "secrets_removed": True,
        },
        "artifacts": [
            {
                "logical_name": "raw_report",
                "relative_path": RAW_REPORT_NAME,
                "media_type": "text/plain",
                "byte_size": len(raw_payload),
                "sha256": hashlib.sha256(raw_payload).hexdigest(),
                "probe_id": "adb.readonly_snapshot",
                "status": "observed",
                "exit_code": 0,
                "timed_out": False,
                "sensitivity": "sensitive",
                "redaction_state": "redacted",
                "detail": None,
            },
            {
                "logical_name": "command_results",
                "relative_path": ADB_PROVENANCE_NAME,
                "media_type": "application/json",
                "byte_size": len(provenance_payload),
                "sha256": hashlib.sha256(provenance_payload).hexdigest(),
                "probe_id": "adb.command_results",
                "status": "observed",
                "exit_code": 0,
                "timed_out": False,
                "sensitivity": "restricted",
                "redaction_state": "redacted",
                "detail": None,
            },
            *artifacts,
        ],
    }


def collect_adb(  # noqa: C901 - publication cleanup is one auditable transaction
    serial: str,
    output_dir: str | Path,
    *,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    command_runner: Callable[..., AdbCommandResult] = run_adb_command,
) -> AdbCollectionResult:
    """Collect one authorized ADB target without mutating device state."""

    serial = _validate_serial(serial)
    root = _prepare_output_root(output_dir)
    lock_descriptor, lock_path = _acquire_lock(root)
    staging: Path | None = None
    primary_failure = False
    try:
        salt = _load_or_create_project_salt(root)
        target_id = _target_id(serial, salt)
        collection_id, destination, staging = _collection_paths(root)
        started_at = _utc_now()
        preflight_raw = command_runner(
            PREFLIGHT_COMMAND,
            serial,
            timeout_seconds=timeout_seconds,
            cwd=staging,
        )
        _preflight(preflight_raw, serial)
        target_state_raw = command_runner(
            TARGET_STATE_COMMAND,
            serial,
            timeout_seconds=timeout_seconds,
            cwd=staging,
        )
        _confirm_target_state(target_state_raw)
        projected: list[ProjectedResult] = [
            _project_result(
                PREFLIGHT_COMMAND,
                preflight_raw,
                target_id=target_id,
                timeout_seconds=timeout_seconds,
            ),
            _project_result(
                TARGET_STATE_COMMAND,
                target_state_raw,
                target_id=target_id,
                timeout_seconds=timeout_seconds,
            ),
        ]

        def collect(command: AdbCommand) -> ProjectedResult:
            raw = command_runner(
                command,
                serial,
                timeout_seconds=timeout_seconds,
                cwd=staging,
            )
            return _project_result(
                command,
                raw,
                target_id=target_id,
                timeout_seconds=timeout_seconds,
            )

        projected.extend(collect(command) for command in PROPERTY_COMMANDS)
        projected.extend(
            (
                collect(IDENTITY_COMMAND),
                collect(SELINUX_MODE_COMMAND),
                collect(MOUNTINFO_COMMAND),
            )
        )
        if projected[-1].status not in {"observed"}:
            projected.append(collect(PROC_MOUNTS_COMMAND))
        projected.append(collect(SELINUX_CONTEXT_COMMAND))
        ps_result = collect(PS_SELECTED_COMMAND)
        projected.append(ps_result)
        if ps_result.status != "observed":
            projected.append(collect(PS_SELECTED_FALLBACK_COMMAND))

        artifact_documents: list[dict[str, Any]] = []
        for result in projected:
            payload = result.payload.encode("utf-8") if result.payload else None
            relative_path = (
                f"captures/{result.command.logical_name}.txt"
                if payload is not None
                else None
            )
            if payload is not None:
                if contains_sensitive_identifier(payload.decode("utf-8")):
                    raise CollectionError(
                        "ADB artifact did not pass privacy projection"
                    )
                if relative_path is None:
                    raise CollectionError("ADB artifact path was not allocated")
                _write_private_bytes(staging / relative_path, payload)
            artifact_documents.append(_artifact(result, payload, relative_path))

        raw_payload = _raw_report(projected)
        provenance = {
            "schema_version": "1.0.0",
            "collection_id": collection_id,
            "target_id": target_id,
            "commands": [result.provenance(target_id) for result in projected],
        }
        _validate_provenance(
            provenance,
            collection_id=collection_id,
            target_id=target_id,
            results=projected,
        )
        provenance_payload = _stable_json_bytes(provenance)
        _write_private_bytes(staging / RAW_REPORT_NAME, raw_payload)
        _write_private_bytes(staging / ADB_PROVENANCE_NAME, provenance_payload)
        manifest = _manifest(
            collection_id=collection_id,
            target_id=target_id,
            started_at=started_at,
            ended_at=_utc_now(),
            raw_payload=raw_payload,
            provenance_payload=provenance_payload,
            results=projected,
            artifacts=artifact_documents,
        )
        validate_collection_manifest(manifest)
        portable_manifest = _stable_json_bytes(manifest)
        if contains_sensitive_identifier(target_id):
            raise CollectionError("ADB target pseudonym is not portable")
        _write_private_bytes(staging / COMPLETION_MANIFEST_NAME, portable_manifest)
        os.replace(staging, destination)
        staging = None
        return AdbCollectionResult(
            collection_id,
            target_id,
            destination,
            destination / COMPLETION_MANIFEST_NAME,
        )
    except (CollectionError, OutputWriteError):
        primary_failure = True
        raise
    except OSError as exc:
        primary_failure = True
        raise OutputWriteError("could not publish ADB collection atomically") from exc
    except BaseException:
        primary_failure = True
        raise
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        try:
            _release_lock(lock_descriptor, lock_path)
        except OutputWriteError:
            if not primary_failure:
                raise
