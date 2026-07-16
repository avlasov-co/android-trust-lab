"""Bounded, privacy-preserving host provenance collection."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
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
from typing import Any, BinaryIO, Final

from ._version import __version__
from .exceptions import CollectionError, OutputWriteError, safe_path_label
from .privacy import contains_sensitive_identifier
from .validators import validate_collection_manifest

DEFAULT_COMMAND_TIMEOUT_SECONDS: Final = 5.0
PROCESS_CLEANUP_SECONDS: Final = 1.0
MAX_CAPTURE_BYTES: Final = 16 * 1024
HOST_PROVENANCE_NAME: Final = "host_provenance.json"
COMPLETION_MANIFEST_NAME: Final = "collector_manifest.json"
LOCK_NAME: Final = ".trustlab-host.lock"


@dataclass(frozen=True, slots=True)
class HostCommand:
    probe_id: str
    argv: tuple[str, ...]
    tool_name: str | None
    redact_avd_names: bool = False


@dataclass(frozen=True, slots=True)
class HostCommandResult:
    probe_id: str
    argv: tuple[str, ...]
    status: str
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "argv": list(self.argv),
            "status": self.status,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


@dataclass(frozen=True, slots=True)
class HostCollectionResult:
    collection_id: str
    directory: Path
    manifest_path: Path


@dataclass(slots=True)
class _RunningProcess:
    process: subprocess.Popen[bytes]
    windows_job_handle: int | None = None


HOST_COMMANDS: Final = (
    HostCommand("host.adb_version", ("adb", "version"), "adb"),
    HostCommand("host.sdkmanager_version", ("sdkmanager", "--version"), "sdkmanager"),
    HostCommand("host.avdmanager_version", ("avdmanager", "--version"), "avdmanager"),
    HostCommand("host.emulator_version", ("emulator", "-version"), "emulator"),
    HostCommand(
        "host.avd_metadata",
        ("emulator", "-list-avds"),
        None,
        redact_avd_names=True,
    ),
)

_SECRET_ASSIGNMENT_RE: Final = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?"
    r"(?:password|passwd|token|secret|api[_-]?key|authorization)[\"']?"
    r"\s*[:=]\s*(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_ENV_SECRET_ASSIGNMENT_RE: Final = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[A-Za-z0-9_]*"
    r"(?:password|passwd|token|secret|api_key|access_key|private_key)"
    r"[A-Za-z0-9_]*\s*[:=]"
)
_VERSION_RE: Final = re.compile(
    r"(?<![A-Za-z0-9])([0-9]+\.[0-9]+(?:\.[0-9]+){0,2}(?:[-+][0-9A-Za-z.-]+)?)"
)
_VERSION_TOKEN_PATTERN: Final = (
    r"[0-9]+\.[0-9]+(?:\.[0-9]+){0,2}(?:[-+][0-9A-Za-z.-]+)?"
)
_SAFE_VERSION_LINE_RES: Final = (
    re.compile(
        rf"^(?:Android Debug Bridge version|Version)\s+"
        rf"(?P<version>{_VERSION_TOKEN_PATTERN})$",
        flags=re.IGNORECASE,
    ),
    re.compile(
        rf"^(?:INFO\s*\|\s*)?Android emulator version\s+"
        rf"(?P<version>{_VERSION_TOKEN_PATTERN})"
        r"(?:\s+\(build_id\s+[0-9]+\))?(?:\s+\(CL:N/A\))?$",
        flags=re.IGNORECASE,
    ),
    re.compile(rf"^(?P<version>{_VERSION_TOKEN_PATTERN})$"),
)
_WINDOWS_EXECUTABLE_SUFFIXES: Final = {
    "adb": (".exe",),
    "sdkmanager": (".bat", ".cmd", ".exe"),
    "avdmanager": (".bat", ".cmd", ".exe"),
    "emulator": (".exe",),
}


def _is_windows() -> bool:
    return os.name == "nt"


def _is_posix() -> bool:
    return os.name == "posix"


def _portable_version_token(version: str) -> str:
    numeric_parts = version.split(".")
    if len(numeric_parts) == 4 and all(part.isdigit() for part in numeric_parts):
        # Four dotted numeric components are indistinguishable from an IPv4
        # address to the portable privacy scanner. Preserve every component in
        # the accepted vendor-build spelling.
        return f"{'.'.join(numeric_parts[:3])}-{numeric_parts[3]}"
    return version


def _safe_version_projection(line: str) -> str | None:
    if (
        _SECRET_ASSIGNMENT_RE.search(line) is not None
        or _ENV_SECRET_ASSIGNMENT_RE.search(line) is not None
    ):
        return None
    for index, pattern in enumerate(_SAFE_VERSION_LINE_RES):
        match = pattern.fullmatch(line)
        if match is not None:
            if index == len(
                _SAFE_VERSION_LINE_RES
            ) - 1 and contains_sensitive_identifier(line):
                return None
            return f"version {_portable_version_token(match.group('version'))}"
    return None


def _as_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", errors="replace")


def _redact_text(
    value: bytes | str | None,
    *,
    redact_avd_names: bool = False,
    project_versions: bool = False,
) -> str:
    payload = _as_bytes(value)
    truncated = len(payload) > MAX_CAPTURE_BYTES
    text = payload[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    lines: list[str] = []
    avd_index = 0
    for raw_line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = "".join(
            " " if ord(character) < 32 or ord(character) == 127 else character
            for character in raw_line
        ).strip()
        if not line:
            continue
        if redact_avd_names:
            avd_index += 1
            lines.append(f"avd-{avd_index:03d}")
            continue
        if project_versions:
            lines.append(_safe_version_projection(line) or "<redacted-line>")
            continue
        lines.append("<redacted-line>")
    if truncated:
        lines.append("[truncated]")
    return "\n".join(lines)


def _subprocess_environment(environment: Mapping[str, str]) -> dict[str, str]:
    allowed = (
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "ANDROID_HOME",
        "ANDROID_SDK_ROOT",
        "JAVA_HOME",
    )
    return {key: environment[key] for key in allowed if key in environment}


def _execution_argv(
    command: HostCommand, environment: Mapping[str, str]
) -> list[str] | None:
    if not _is_windows():
        return list(command.argv)
    suffixes = _WINDOWS_EXECUTABLE_SUFFIXES.get(command.argv[0], ())
    search_path = environment.get("PATH", "")
    for suffix in suffixes:
        executable = shutil.which(f"{command.argv[0]}{suffix}", path=search_path)
        if executable is not None:
            return [executable, *command.argv[1:]]
    return None


def _drain_bounded(stream: BinaryIO, retained: bytearray) -> None:
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            remaining = MAX_CAPTURE_BYTES + 1 - len(retained)
            if remaining > 0:
                retained.extend(chunk[:remaining])
    except OSError:
        # Process termination can close a pipe while a reader is draining it.
        pass


def _remaining_seconds(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _join_readers(readers: Sequence[threading.Thread], *, deadline: float) -> None:
    for reader in readers:
        reader.join(timeout=_remaining_seconds(deadline))


def _create_windows_job_for_process(process: subprocess.Popen[bytes]) -> int:
    """Assign a suspended Windows process to a kill-on-close Job Object."""

    import ctypes
    from ctypes import wintypes

    windows_ctypes: Any = ctypes

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = (
            ("per_process_user_time_limit", ctypes.c_int64),
            ("per_job_user_time_limit", ctypes.c_int64),
            ("limit_flags", wintypes.DWORD),
            ("minimum_working_set_size", ctypes.c_size_t),
            ("maximum_working_set_size", ctypes.c_size_t),
            ("active_process_limit", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority_class", wintypes.DWORD),
            ("scheduling_class", wintypes.DWORD),
        )

    class IoCounters(ctypes.Structure):
        _fields_ = tuple(
            (name, ctypes.c_uint64)
            for name in (
                "read_operation_count",
                "write_operation_count",
                "other_operation_count",
                "read_transfer_count",
                "write_transfer_count",
                "other_transfer_count",
            )
        )

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = (
            ("basic_limit_information", BasicLimitInformation),
            ("io_info", IoCounters),
            ("process_memory_limit", ctypes.c_size_t),
            ("job_memory_limit", ctypes.c_size_t),
            ("peak_process_memory_used", ctypes.c_size_t),
            ("peak_job_memory_used", ctypes.c_size_t),
        )

    kernel32 = windows_ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = windows_ctypes.WinDLL("ntdll", use_last_error=True)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    ntdll.NtResumeProcess.restype = wintypes.LONG
    job = kernel32.CreateJobObjectW(None, None)
    job_value = getattr(job, "value", job)
    if not isinstance(job_value, int) or job_value == 0:
        raise OSError(windows_ctypes.get_last_error(), "CreateJobObjectW failed")
    assigned = False
    try:
        limits = ExtendedLimitInformation()
        limits.basic_limit_information.limit_flags = 0x00002000
        if not kernel32.SetInformationJobObject(
            wintypes.HANDLE(job_value),
            9,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise OSError(
                windows_ctypes.get_last_error(), "SetInformationJobObject failed"
            )
        process_handle = getattr(process, "_handle", None)
        process_handle_value = getattr(process_handle, "value", process_handle)
        if not isinstance(
            process_handle_value, int
        ) or not kernel32.AssignProcessToJobObject(
            wintypes.HANDLE(job_value), wintypes.HANDLE(process_handle_value)
        ):
            raise OSError(
                windows_ctypes.get_last_error(), "AssignProcessToJobObject failed"
            )
        assigned = True
        # Resume only the retained child process handle. A system-wide thread
        # snapshot would cross the collector's explicit process-list boundary.
        if ntdll.NtResumeProcess(wintypes.HANDLE(process_handle_value)) != 0:
            raise OSError(windows_ctypes.get_last_error(), "NtResumeProcess failed")
        return job_value
    except BaseException:
        kernel32.CloseHandle(wintypes.HANDLE(job_value))
        if not assigned:
            try:
                process.kill()
            except OSError:
                pass
        raise


def _close_windows_job(running: _RunningProcess) -> None:
    handle = running.windows_job_handle
    if handle is None:
        return
    import ctypes
    from ctypes import wintypes

    windows_ctypes: Any = ctypes
    kernel32 = windows_ctypes.WinDLL("kernel32", use_last_error=True)
    if not kernel32.CloseHandle(wintypes.HANDLE(handle)):
        raise CollectionError("Windows host command Job Object could not close")
    running.windows_job_handle = None


def _terminate_process_tree(running: _RunningProcess) -> None:
    process = running.process
    pid = getattr(process, "pid", None)
    if _is_posix() and isinstance(pid, int):
        try:
            os.killpg(pid, signal.SIGKILL)
            return
        except OSError:
            pass
    if _is_windows() and running.windows_job_handle is not None:
        try:
            _close_windows_job(running)
            return
        except CollectionError:
            pass
    try:
        process.kill()
    except OSError:
        pass


def _unavailable_command_result(command: HostCommand) -> HostCommandResult:
    return HostCommandResult(
        probe_id=command.probe_id,
        argv=command.argv,
        status="unsupported",
        exit_code=None,
        timed_out=False,
        stdout="",
        stderr="",
    )


def _start_host_process(
    command: HostCommand,
    *,
    cwd: Path | None,
    environment: Mapping[str, str],
) -> _RunningProcess | HostCommandResult:
    execution_argv = _execution_argv(command, environment)
    if execution_argv is None:
        return _unavailable_command_result(command)
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
            env=dict(environment),
            start_new_session=_is_posix(),
            creationflags=creationflags,
        )
    except FileNotFoundError:
        return _unavailable_command_result(command)
    except OSError as exc:
        return HostCommandResult(
            probe_id=command.probe_id,
            argv=command.argv,
            status="command_error",
            exit_code=None,
            timed_out=False,
            stdout="",
            stderr=_redact_text(str(exc), project_versions=True),
        )
    if not _is_windows():
        return _RunningProcess(process)
    try:
        return _RunningProcess(process, _create_windows_job_for_process(process))
    except OSError as exc:
        try:
            process.wait(timeout=PROCESS_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=PROCESS_CLEANUP_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        raise CollectionError(
            "Windows host command process isolation could not be established"
        ) from exc


def _finish_host_process(
    running: _RunningProcess,
    command: HostCommand,
    *,
    timeout_seconds: float,
) -> HostCommandResult:
    process = running.process
    if process.stdout is None or process.stderr is None:
        _terminate_process_tree(running)
        try:
            process.wait(timeout=PROCESS_CLEANUP_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise CollectionError(
                "host command capture setup did not terminate"
            ) from exc
        raise CollectionError("host command capture pipes were not created")
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    readers = (
        threading.Thread(
            target=_drain_bounded,
            args=(process.stdout, stdout_buffer),
            daemon=True,
        ),
        threading.Thread(
            target=_drain_bounded,
            args=(process.stderr, stderr_buffer),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()
    timed_out = False
    command_deadline = time.monotonic() + timeout_seconds
    try:
        process.wait(timeout=_remaining_seconds(command_deadline))
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_tree(running)
    _join_readers(readers, deadline=command_deadline)
    if any(reader.is_alive() for reader in readers):
        timed_out = True
        _terminate_process_tree(running)
    cleanup_deadline = time.monotonic() + PROCESS_CLEANUP_SECONDS
    try:
        process.wait(timeout=_remaining_seconds(cleanup_deadline))
    except subprocess.TimeoutExpired as exc:
        raise CollectionError("host command did not terminate after timeout") from exc
    _join_readers(readers, deadline=cleanup_deadline)
    if any(reader.is_alive() for reader in readers):
        # Closing a buffered pipe while another thread is blocked in read() can
        # itself block. Leave the daemon reader to unwind and fail promptly.
        raise CollectionError("host command output capture did not terminate")
    try:
        process.stdout.close()
        process.stderr.close()
    except OSError as exc:
        raise CollectionError("host command output capture could not close") from exc

    stdout = _redact_text(
        bytes(stdout_buffer),
        redact_avd_names=command.redact_avd_names,
        project_versions=not command.redact_avd_names,
    )
    stderr = _redact_text(
        bytes(stderr_buffer),
        redact_avd_names=command.redact_avd_names,
        project_versions=not command.redact_avd_names,
    )
    if timed_out:
        status = "command_error"
        exit_code = None
    elif process.returncode != 0:
        status = "command_error"
        exit_code = process.returncode
    elif stdout or stderr:
        status = "observed"
        exit_code = process.returncode
    else:
        status = "observed_absent"
        exit_code = process.returncode
    return HostCommandResult(
        probe_id=command.probe_id,
        argv=command.argv,
        status=status,
        exit_code=exit_code,
        timed_out=timed_out,
        stdout=stdout,
        stderr=stderr,
    )


def run_host_command(
    command: HostCommand,
    *,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    cwd: Path | None = None,
    environment: Mapping[str, str] = os.environ,
) -> HostCommandResult:
    """Run one reviewed host-only argument array with bounded capture."""

    if command not in HOST_COMMANDS:
        raise CollectionError("host command is not in the reviewed allowlist")
    if timeout_seconds <= 0 or timeout_seconds > 60:
        raise CollectionError("host command timeout is outside the safe range")
    safe_environment = _subprocess_environment(environment)
    running_or_result = _start_host_process(
        command, cwd=cwd, environment=safe_environment
    )
    if isinstance(running_or_result, HostCommandResult):
        return running_or_result
    running = running_or_result
    primary_failure = False
    try:
        return _finish_host_process(running, command, timeout_seconds=timeout_seconds)
    except BaseException:
        primary_failure = True
        _terminate_process_tree(running)
        raise
    finally:
        try:
            _close_windows_job(running)
        except CollectionError:
            if not primary_failure:
                raise


def _platform_name() -> str:
    return {
        "darwin": "macos",
        "linux": "linux",
        "windows": "windows",
    }.get(platform.system().lower(), "unknown")


def _collector_version() -> str:
    return re.sub(r"\.dev(?=[0-9])", "-dev", __version__, count=1)


def _fact(value: str) -> dict[str, Any]:
    return {
        "status": "observed" if value else "observed_absent",
        "value": value,
    }


def _kernel_summary() -> str:
    match = re.match(r"^[0-9]{1,4}(?:\.[0-9]{1,4}){0,3}", platform.release())
    return match.group(0) if match is not None else "unknown"


def _architecture() -> str:
    aliases = {
        "amd64": "x86_64",
        "arm64": "aarch64",
    }
    machine = platform.machine().lower()
    machine = aliases.get(machine, machine)
    allowed = {
        "aarch64",
        "armv7l",
        "i386",
        "i686",
        "ppc64le",
        "riscv64",
        "s390x",
        "x86",
        "x86_64",
    }
    return machine if machine in allowed else "unknown"


def _extract_version(result: HostCommandResult) -> str:
    if result.status not in {"observed", "observed_absent"}:
        return "unknown"
    match = _VERSION_RE.search(f"{result.stdout}\n{result.stderr}")
    if match is None:
        return "unknown"
    return _portable_version_token(match.group(1)[:64])


def _validated_result(
    command: HostCommand, result: HostCommandResult
) -> HostCommandResult:
    if result.probe_id != command.probe_id or result.argv != command.argv:
        raise CollectionError("host command runner returned mismatched provenance")
    if result.status not in {
        "observed",
        "observed_absent",
        "unsupported",
        "command_error",
    }:
        raise CollectionError("host command runner returned an invalid status")
    if result.timed_out and result.status != "command_error":
        raise CollectionError("timed-out host commands must be command errors")
    if type(result.timed_out) is not bool:
        raise CollectionError("host command timeout provenance is not boolean")
    exit_code = result.exit_code
    if isinstance(exit_code, int) and not isinstance(exit_code, bool):
        exit_code_is_int = True
        if not -(2**31) <= exit_code < 2**32:
            raise CollectionError("host command exit status is outside the safe range")
    else:
        exit_code_is_int = False
    if result.status == "observed" and (
        not exit_code_is_int
        or result.exit_code != 0
        or result.timed_out
        or not (result.stdout or result.stderr)
    ):
        raise CollectionError("observed host command provenance is inconsistent")
    if result.status == "observed_absent" and (
        not exit_code_is_int
        or result.exit_code != 0
        or result.timed_out
        or result.stdout
        or result.stderr
    ):
        raise CollectionError("empty host command provenance is inconsistent")
    if result.status == "unsupported" and (
        result.exit_code is not None
        or result.timed_out
        or result.stdout
        or result.stderr
    ):
        raise CollectionError("unsupported host command provenance is inconsistent")
    if result.status == "command_error" and (
        (result.timed_out and result.exit_code is not None)
        or (
            not result.timed_out
            and result.exit_code is not None
            and (not exit_code_is_int or result.exit_code == 0)
        )
    ):
        raise CollectionError("failed host command provenance is inconsistent")
    sanitized = HostCommandResult(
        probe_id=result.probe_id,
        argv=result.argv,
        status=result.status,
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        stdout=_redact_text(
            result.stdout,
            redact_avd_names=command.redact_avd_names,
            project_versions=not command.redact_avd_names,
        ),
        stderr=_redact_text(
            result.stderr,
            redact_avd_names=command.redact_avd_names,
            project_versions=not command.redact_avd_names,
        ),
    )
    if sanitized.status == "observed" and not (sanitized.stdout or sanitized.stderr):
        raise CollectionError("observed host command output is empty after redaction")
    if contains_sensitive_identifier(f"{sanitized.stdout}\n{sanitized.stderr}"):
        raise CollectionError("host command output did not pass portable redaction")
    return sanitized


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _new_collection_token() -> str:
    return secrets.token_hex(8)


def _stable_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def _write_private_bytes(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
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
            f"could not write private collection output: {safe_path_label(path)}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _prepare_output_root(output_dir: str | Path) -> Path:
    if _is_windows() and sys.version_info < (3, 13):
        raise CollectionError(
            "host collection on Windows requires Python 3.13 or newer "
            "for private directory ACLs"
        )
    root = Path(output_dir)
    try:
        if root.is_symlink():
            raise CollectionError("collection output directory must not be a symlink")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = root.stat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise CollectionError("collection output path must be a directory")
    except CollectionError:
        raise
    except OSError as exc:
        raise OutputWriteError(
            f"could not prepare collection output: {safe_path_label(root)}"
        ) from exc
    return root.resolve(strict=True)


def _acquire_lock(root: Path) -> tuple[int, Path]:
    lock_path = root / LOCK_NAME
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
        os.chmod(lock_path, 0o600)
        return descriptor, lock_path
    except FileExistsError as exc:
        raise CollectionError("another host collection holds the output lock") from exc
    except OSError as exc:
        raise OutputWriteError("could not acquire host collection lock") from exc


def _release_lock(descriptor: int, path: Path) -> None:
    release_error: OSError | None = None
    try:
        os.close(descriptor)
    except OSError as exc:
        release_error = exc
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        release_error = release_error or exc
    if release_error is not None:
        raise OutputWriteError(
            "could not release host collection lock"
        ) from release_error


def _collection_paths(root: Path) -> tuple[str, Path, Path]:
    for _attempt in range(32):
        token = _new_collection_token()
        if re.fullmatch(r"[a-f0-9]{16}", token) is None:
            raise CollectionError("collection token source returned an invalid token")
        collection_id = f"atlcol-{token}"
        destination = root / collection_id
        if not destination.exists() and not destination.is_symlink():
            staging = Path(tempfile.mkdtemp(prefix=".trustlab-host-", dir=root))
            os.chmod(staging, 0o700)
            return collection_id, destination, staging
    raise CollectionError("could not allocate a unique collection directory")


def _host_provenance(
    collection_id: str,
    results: Sequence[HostCommandResult],
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "collection_id": collection_id,
        "facts": {
            "project_version": _fact(__version__),
            "python_version": _fact(platform.python_version()),
            "host_os": _fact(_platform_name()),
            "kernel_summary": _fact(_kernel_summary()),
            "architecture": _fact(_architecture()),
        },
        "commands": [result.to_dict() for result in results],
    }


def _manifest(
    *,
    collection_id: str,
    started_at: str,
    ended_at: str,
    provenance_payload: bytes,
    results: Sequence[HostCommandResult],
) -> dict[str, Any]:
    versions = {
        "trustlab_host": _collector_version(),
        "python": platform.python_version(),
    }
    for command, result in zip(HOST_COMMANDS, results, strict=True):
        if command.tool_name is not None:
            versions[command.tool_name] = _extract_version(result)
    target_digest = hashlib.sha256(collection_id.encode("ascii")).hexdigest()[:16]
    return {
        "collection_id": collection_id,
        "schema_version": "1.0.0",
        "experiment_id": "E26_host_collection",
        "collector": {"name": "trustlab-host", "version": _collector_version()},
        "observer": {
            "observer_type": "host",
            "privilege_level": "host",
            "collection_method": "host_snapshot",
        },
        "target": {
            "pseudonymous_id": f"target-{target_digest}",
            "target_type": "unknown",
        },
        "started_at": started_at,
        "ended_at": ended_at,
        "completion_status": "complete",
        "tool_versions": versions,
        "environment": {
            "platform": _platform_name(),
            "transport": "local",
            "execution_context": "host_collector",
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
                "logical_name": "command_results",
                "relative_path": HOST_PROVENANCE_NAME,
                "media_type": "application/json",
                "byte_size": len(provenance_payload),
                "sha256": hashlib.sha256(provenance_payload).hexdigest(),
                "probe_id": "host.command_results",
                "status": "observed",
                "exit_code": 0,
                "timed_out": False,
                "sensitivity": "sensitive",
                "redaction_state": "redacted",
                "detail": None,
            }
        ],
    }


def collect_host(
    output_dir: str | Path,
    *,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    command_runner: Callable[..., HostCommandResult] = run_host_command,
) -> HostCollectionResult:
    """Collect host provenance into one locked, atomic private directory."""

    root = _prepare_output_root(output_dir)
    lock_descriptor, lock_path = _acquire_lock(root)
    staging: Path | None = None
    primary_failure = False
    try:
        collection_id, destination, staging = _collection_paths(root)
        started_at = _utc_now()
        results = tuple(
            _validated_result(
                command,
                command_runner(
                    command,
                    timeout_seconds=timeout_seconds,
                    cwd=staging,
                ),
            )
            for command in HOST_COMMANDS
        )
        provenance = _host_provenance(collection_id, results)
        provenance_payload = _stable_json_bytes(provenance)
        _write_private_bytes(staging / HOST_PROVENANCE_NAME, provenance_payload)
        manifest = _manifest(
            collection_id=collection_id,
            started_at=started_at,
            ended_at=_utc_now(),
            provenance_payload=provenance_payload,
            results=results,
        )
        validate_collection_manifest(manifest)
        _write_private_bytes(
            staging / COMPLETION_MANIFEST_NAME, _stable_json_bytes(manifest)
        )
        os.replace(staging, destination)
        staging = None
        return HostCollectionResult(
            collection_id=collection_id,
            directory=destination,
            manifest_path=destination / COMPLETION_MANIFEST_NAME,
        )
    except (CollectionError, OutputWriteError):
        primary_failure = True
        raise
    except OSError as exc:
        primary_failure = True
        raise OutputWriteError("could not publish host collection atomically") from exc
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
