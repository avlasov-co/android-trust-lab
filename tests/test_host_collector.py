from __future__ import annotations

import ctypes
import io
import os
import stat
import subprocess
import sys
import time

import pytest

import trustlab.host_collector as host_collector
from trustlab import cli
from trustlab.collection_manifest import (
    CollectionManifest,
    verify_collection_artifacts,
)
from trustlab.exceptions import CollectionError, OutputWriteError
from trustlab.host_collector import (
    COMPLETION_MANIFEST_NAME,
    HOST_COMMANDS,
    HOST_PROVENANCE_NAME,
    LOCK_NAME,
    MAX_CAPTURE_BYTES,
    HostCollectionResult,
    HostCommand,
    HostCommandResult,
    collect_host,
    run_host_command,
)
from trustlab.privacy import contains_sensitive_identifier
from trustlab.report_writer import load_json
from trustlab.validators import validate_collection_manifest


class FakeProcess:
    def __init__(
        self,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
        times_out: bool = False,
    ) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = returncode
        self.times_out = times_out
        self.killed = False
        self.wait_count = 0

    def wait(self, timeout=None):
        self.wait_count += 1
        if self.times_out and not self.killed:
            raise subprocess.TimeoutExpired(["tool"], timeout)
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


def successful_result(command: HostCommand, **_kwargs) -> HostCommandResult:
    outputs = {
        "host.adb_version": "Android Debug Bridge version 1.0.41",
        "host.sdkmanager_version": "19.0",
        "host.avdmanager_version": "19.0",
        "host.emulator_version": "Android emulator version 36.2.1.0",
        "host.avd_metadata": "Personal_Device\nWork_Device",
    }
    return HostCommandResult(
        probe_id=command.probe_id,
        argv=command.argv,
        status="observed",
        exit_code=0,
        timed_out=False,
        stdout=outputs[command.probe_id],
        stderr="",
    )


def fixed_collection(monkeypatch) -> None:
    monkeypatch.setattr(
        host_collector, "_new_collection_token", lambda: "0123456789abcdef"
    )
    timestamps = iter(("2026-07-16T10:00:00Z", "2026-07-16T10:00:01Z"))
    monkeypatch.setattr(host_collector, "_utc_now", lambda: next(timestamps))


def test_host_command_inventory_is_exact_and_never_targets_an_adb_device():
    assert [command.argv for command in HOST_COMMANDS] == [
        ("adb", "version"),
        ("sdkmanager", "--version"),
        ("avdmanager", "--version"),
        ("emulator", "-version"),
        ("emulator", "-list-avds"),
    ]
    forbidden = {
        "devices",
        "shell",
        "-s",
        "root",
        "remount",
        "reboot",
        "bootloader",
        "su",
        "mount",
        "setprop",
    }
    for command in HOST_COMMANDS:
        assert not forbidden.intersection(command.argv)
    assert [command.argv for command in HOST_COMMANDS if command.argv[0] == "adb"] == [
        ("adb", "version")
    ]


def test_run_host_command_uses_argument_array_private_cwd_and_safe_environment(
    tmp_path, monkeypatch
):
    captured = {}
    process = FakeProcess(
        stdout=(
            b"Android Debug Bridge version 1.0.41\n"
            b"Installed as /Users/alice/Library/Android/sdk/platform-tools/adb\n"
        )
    )

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return process

    monkeypatch.setattr(host_collector.subprocess, "Popen", fake_popen)
    result = run_host_command(
        HOST_COMMANDS[0],
        cwd=tmp_path,
        environment={
            "PATH": "/safe/bin",
            "ANDROID_SERIAL": "private-serial",
            "API_TOKEN": "host-test-secret",  # pragma: allowlist secret
        },
    )

    assert captured["argv"] == ["adb", "version"]
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL
    assert captured["kwargs"]["cwd"] == tmp_path
    assert captured["kwargs"]["env"] == {"PATH": "/safe/bin"}
    assert result.status == "observed"
    assert result.exit_code == 0
    assert "/Users/alice" not in result.stdout
    assert "<redacted-line>" in result.stdout


@pytest.mark.parametrize(
    ("process", "status", "exit_code", "timed_out"),
    [
        (FakeProcess(), "observed_absent", 0, False),
        (FakeProcess(stderr=b"failed", returncode=7), "command_error", 7, False),
        (FakeProcess(stdout=b"partial", times_out=True), "command_error", None, True),
    ],
)
def test_run_host_command_models_empty_nonzero_and_timeout(
    monkeypatch, process, status, exit_code, timed_out
):
    monkeypatch.setattr(
        host_collector.subprocess, "Popen", lambda *_args, **_kwargs: process
    )

    result = run_host_command(HOST_COMMANDS[0], timeout_seconds=0.1)

    assert result.status == status
    assert result.exit_code == exit_code
    assert result.timed_out is timed_out
    if timed_out:
        assert process.killed
        assert process.wait_count == 2


def test_run_host_command_models_missing_and_os_errors(monkeypatch):
    monkeypatch.setattr(
        host_collector.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError()),
    )
    missing = run_host_command(HOST_COMMANDS[0])
    assert (missing.status, missing.exit_code, missing.timed_out) == (
        "unsupported",
        None,
        False,
    )

    monkeypatch.setattr(
        host_collector.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("cannot open /home/alice/private-tool")
        ),
    )
    failed = run_host_command(HOST_COMMANDS[0])
    assert failed.status == "command_error"
    assert "/home/alice" not in failed.stderr


def test_windows_tool_resolution_uses_reviewed_suffix_without_recording_path(
    monkeypatch,
):
    process = FakeProcess(stdout=b"19.0\n")
    lookups = []

    def fake_which(name, *, path):
        lookups.append((name, path))
        if name == "sdkmanager.bat":
            return r"C:\Android\cmdline-tools\bin\sdkmanager.bat"
        return None

    captured = {}

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return process

    monkeypatch.setattr(host_collector, "_is_windows", lambda: True)
    monkeypatch.setattr(host_collector, "_is_posix", lambda: False)
    monkeypatch.setattr(host_collector.shutil, "which", fake_which)
    monkeypatch.setattr(host_collector.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        host_collector, "_create_windows_job_for_process", lambda _process: 9001
    )

    def fake_close_job(running):
        running.windows_job_handle = None

    monkeypatch.setattr(host_collector, "_close_windows_job", fake_close_job)

    result = run_host_command(
        HOST_COMMANDS[1],
        environment={"PATH": r"C:\Android\cmdline-tools\bin", "PATHEXT": ".BAT;.EXE"},
    )

    assert lookups == [("sdkmanager.bat", r"C:\Android\cmdline-tools\bin")]
    assert captured["argv"] == [
        r"C:\Android\cmdline-tools\bin\sdkmanager.bat",
        "--version",
    ]
    assert captured["kwargs"]["creationflags"] & 0x0004
    assert result.argv == ("sdkmanager", "--version")
    assert result.stdout == "version 19.0"


def test_windows_process_tree_cleanup_closes_job_object_handle(monkeypatch):
    process = FakeProcess()
    process.pid = 4242
    running = host_collector._RunningProcess(process, 7001)
    closed = []

    def fake_close_job(value):
        closed.append(value.windows_job_handle)
        value.windows_job_handle = None

    monkeypatch.setattr(host_collector, "_is_windows", lambda: True)
    monkeypatch.setattr(host_collector, "_close_windows_job", fake_close_job)
    host_collector._terminate_process_tree(running)

    assert closed == [7001]
    assert not process.killed


def test_windows_job_object_assigns_suspended_process_and_resumes_thread(monkeypatch):
    process = FakeProcess()
    process.pid = 4242
    process._handle = 5151
    closed = []
    resumed = []

    class FakeFunction:
        def __init__(self, implementation):
            self.implementation = implementation
            self.restype = None

        def __call__(self, *args):
            return self.implementation(*args)

    class FakeKernel32:
        def __init__(self):
            self.CreateJobObjectW = FakeFunction(lambda *_args: 101)
            self.SetInformationJobObject = FakeFunction(lambda *_args: True)
            self.AssignProcessToJobObject = FakeFunction(lambda *_args: True)
            self.CloseHandle = FakeFunction(self.close_handle)

        def close_handle(self, handle):
            closed.append(handle.value)
            return True

    class FakeNtdll:
        def __init__(self):
            self.NtResumeProcess = FakeFunction(self.resume_process)

        def resume_process(self, handle):
            resumed.append(handle.value)
            return 0

    kernel32 = FakeKernel32()
    ntdll = FakeNtdll()

    def fake_windll(name, **_kwargs):
        return kernel32 if name == "kernel32" else ntdll

    monkeypatch.setattr(ctypes, "WinDLL", fake_windll, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 0, raising=False)

    handle = host_collector._create_windows_job_for_process(process)

    assert handle == 101
    assert resumed == [5151]
    assert closed == []

    running = host_collector._RunningProcess(process, handle)
    host_collector._close_windows_job(running)
    assert running.windows_job_handle is None
    assert closed == [101]


def test_run_host_command_bounds_output_and_redacts_avd_names(monkeypatch):
    oversized = FakeProcess(stdout=b"x" * (MAX_CAPTURE_BYTES * 2))
    monkeypatch.setattr(
        host_collector.subprocess, "Popen", lambda *_args, **_kwargs: oversized
    )
    result = run_host_command(HOST_COMMANDS[0])
    assert result.stdout.endswith("[truncated]")
    assert len(result.stdout) < 2048

    avds = FakeProcess(stdout=b"Personal_Device\nWork_Profile\n")
    monkeypatch.setattr(
        host_collector.subprocess, "Popen", lambda *_args, **_kwargs: avds
    )
    result = run_host_command(HOST_COMMANDS[-1])
    assert result.stdout == "avd-001\navd-002"


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group regression")
def test_run_host_command_bounds_descendants_that_inherit_capture_pipes(
    tmp_path, monkeypatch
):
    child_code = "import time; time.sleep(10)"
    parent_code = (
        "import subprocess, sys; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}])"
    )
    command = HostCommand(
        "host.descendant_timeout",
        (sys.executable, "-c", parent_code),
        None,
    )
    monkeypatch.setattr(host_collector, "HOST_COMMANDS", (command,))

    started = time.monotonic()
    result = run_host_command(command, timeout_seconds=0.2, cwd=tmp_path)

    assert time.monotonic() - started < 2.0
    assert result.status == "command_error"
    assert result.exit_code is None
    assert result.timed_out is True


def test_unreviewed_command_and_unsafe_timeout_fail_closed():
    unreviewed = HostCommand("host.unreviewed", ("tool", "--version"), None)
    with pytest.raises(CollectionError, match="allowlist"):
        run_host_command(unreviewed)
    with pytest.raises(CollectionError, match="timeout"):
        run_host_command(HOST_COMMANDS[0], timeout_seconds=0)


@pytest.mark.parametrize(
    "result",
    [
        HostCommandResult(
            "host.adb_version",
            ("adb", "version"),
            "observed",
            None,
            False,
            "1.0.41",
            "",
        ),
        HostCommandResult(
            "host.adb_version",
            ("adb", "version"),
            "observed_absent",
            0,
            False,
            "unexpected",
            "",
        ),
        HostCommandResult(
            "host.adb_version",
            ("adb", "version"),
            "unsupported",
            7,
            False,
            "",
            "",
        ),
        HostCommandResult(
            "host.adb_version",
            ("adb", "version"),
            "command_error",
            0,
            False,
            "",
            "failed",
        ),
        HostCommandResult(
            "host.adb_version",
            ("adb", "version"),
            "command_error",
            7,
            True,
            "",
            "",
        ),
        HostCommandResult(
            "host.adb_version",
            ("adb", "version"),
            "observed",
            0,
            False,
            "   \n\t",
            "",
        ),
    ],
)
def test_injected_command_results_reject_contradictory_provenance(result):
    with pytest.raises(CollectionError, match="inconsistent|empty after redaction"):
        host_collector._validated_result(HOST_COMMANDS[0], result)


def test_windows_dword_command_error_exit_status_is_nonfatal():
    result = HostCommandResult(
        "host.adb_version",
        ("adb", "version"),
        "command_error",
        0xC0000005,
        False,
        "",
        "failed",
    )
    validated = host_collector._validated_result(HOST_COMMANDS[0], result)
    assert validated.exit_code == 0xC0000005
    assert validated.stderr == "<redacted-line>"


def test_collect_host_publishes_valid_private_manifest_last(tmp_path, monkeypatch):
    fixed_collection(monkeypatch)
    writes = []
    original_write = host_collector._write_private_bytes

    def recording_write(path, payload):
        writes.append(path.name)
        original_write(path, payload)

    monkeypatch.setattr(host_collector, "_write_private_bytes", recording_write)
    result = collect_host(tmp_path, command_runner=successful_result)

    assert result.collection_id == "atlcol-0123456789abcdef"
    assert result.directory == tmp_path / result.collection_id
    assert result.manifest_path.name == COMPLETION_MANIFEST_NAME
    assert writes == [HOST_PROVENANCE_NAME, COMPLETION_MANIFEST_NAME]
    manifest_document = load_json(result.manifest_path)
    validate_collection_manifest(manifest_document)
    assert manifest_document["completion_status"] == "complete"
    assert manifest_document["tool_versions"] == {
        "adb": "1.0.41",
        "avdmanager": "19.0",
        "emulator": "36.2.1-0",
        "python": host_collector.platform.python_version(),
        "sdkmanager": "19.0",
        "trustlab_host": "0.3.0-dev0",
    }
    manifest = CollectionManifest.from_dict(manifest_document)
    verified = verify_collection_artifacts(manifest, result.manifest_path)
    assert set(verified) == {"command_results"}

    provenance = load_json(result.directory / HOST_PROVENANCE_NAME)
    assert [item["argv"] for item in provenance["commands"]] == [
        list(command.argv) for command in HOST_COMMANDS
    ]
    assert provenance["commands"][-1]["stdout"] == "avd-001\navd-002"
    assert provenance["commands"][-2]["stdout"] == "version 36.2.1-0"
    if os.name == "posix":
        assert stat.S_IMODE(result.directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(result.manifest_path.stat().st_mode) == 0o600
        assert (
            stat.S_IMODE((result.directory / HOST_PROVENANCE_NAME).stat().st_mode)
            == 0o600
        )
    assert not (tmp_path / LOCK_NAME).exists()
    assert not list(tmp_path.glob(".trustlab-host-*"))


def test_missing_tools_are_explicit_nonfatal_statuses(tmp_path, monkeypatch):
    fixed_collection(monkeypatch)

    def missing_runner(command, **_kwargs):
        return HostCommandResult(
            command.probe_id,
            command.argv,
            "unsupported",
            None,
            False,
            "",
            "",
        )

    result = collect_host(tmp_path, command_runner=missing_runner)
    provenance = load_json(result.directory / HOST_PROVENANCE_NAME)
    assert {item["status"] for item in provenance["commands"]} == {"unsupported"}
    assert all(item["exit_code"] is None for item in provenance["commands"])
    validate_collection_manifest(load_json(result.manifest_path))


def test_collection_redacts_hostile_runner_output_before_writing(tmp_path, monkeypatch):
    fixed_collection(monkeypatch)

    def hostile_runner(command, **_kwargs):
        if command.redact_avd_names:
            stdout = "Personal_Device\nWork_Device"
            stderr = "Secret_AVD_From_Stderr"
        else:
            stdout = (
                "Authorization: Bearer super-secret-jwt-value\n"
                '"token": "super-secret-json-value"\n'
                "AWS_SECRET_ACCESS_KEY=aws-test-secret\n"
                "AWS_SECRET_ACCESS_KEY=10.20.30.40\n"
                "password=12.34.56\n"
                "serial=12.34.56\n"
                "alice@example.com 9.8.7\n"
                "10.20.30.40\n"
                "username=alice\n"
                "-----BEGIN PRIVATE KEY-----\n"  # pragma: allowlist secret
                "private-key-material\n"
                "-----END PRIVATE KEY-----\n"
                "/root/Android/Sdk/private-tool\n"
                "alice@example.com /Users/alice/private"
            )
            stderr = "serial=PRIVATE-SERIAL-12345"
        return HostCommandResult(
            command.probe_id,
            command.argv,
            "observed",
            0,
            False,
            stdout,
            stderr,
        )

    result = collect_host(tmp_path, command_runner=hostile_runner)
    portable_tree = "\n".join(
        path.read_text(encoding="utf-8") for path in result.directory.iterdir()
    )
    for sensitive in (
        "alice@example.com",
        "/Users/alice",
        "/root/Android",
        "super-secret-jwt-value",
        "super-secret-json-value",
        "aws-test-secret",
        "10.20.30",
        "12.34.56",
        "9.8.7",
        "username=alice",
        "BEGIN PRIVATE KEY",  # pragma: allowlist secret
        "private-key-material",
        "PRIVATE-SERIAL-12345",
        "Personal_Device",
        "Secret_AVD_From_Stderr",
    ):
        assert sensitive not in portable_tree
    assert not contains_sensitive_identifier(portable_tree)


def test_collection_rejects_runner_provenance_mismatch(tmp_path, monkeypatch):
    fixed_collection(monkeypatch)

    def mismatched_runner(command, **_kwargs):
        return HostCommandResult(
            "host.different",
            command.argv,
            "observed",
            0,
            False,
            "1.0.0",
            "",
        )

    with pytest.raises(CollectionError, match="mismatched provenance"):
        collect_host(tmp_path, command_runner=mismatched_runner)
    assert not list(tmp_path.glob("atlcol-*"))
    assert not list(tmp_path.glob(".trustlab-host-*"))
    assert not (tmp_path / LOCK_NAME).exists()


def test_atomic_publication_failure_cleans_staging_and_lock(tmp_path, monkeypatch):
    fixed_collection(monkeypatch)
    monkeypatch.setattr(
        host_collector.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("rename failed")),
    )

    with pytest.raises(OutputWriteError, match="publish"):
        collect_host(tmp_path, command_runner=successful_result)

    assert not list(tmp_path.glob("atlcol-*"))
    assert not list(tmp_path.glob(".trustlab-host-*"))
    assert not (tmp_path / LOCK_NAME).exists()


def test_output_root_permission_failure_has_no_partial_collection(
    tmp_path, monkeypatch
):
    output_root = tmp_path / "denied"
    original_mkdir = host_collector.Path.mkdir

    def denied_mkdir(path, *args, **kwargs):
        if path == output_root:
            raise PermissionError("denied")
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(host_collector.Path, "mkdir", denied_mkdir)
    with pytest.raises(OutputWriteError, match="prepare collection output"):
        collect_host(output_root, command_runner=successful_result)
    assert not output_root.exists()


def test_windows_private_acl_runtime_guard_precedes_output_creation(
    tmp_path, monkeypatch
):
    output_root = tmp_path / "windows-denied"
    monkeypatch.setattr(host_collector, "_is_windows", lambda: True)
    monkeypatch.setattr(host_collector.sys, "version_info", (3, 12, 9))

    with pytest.raises(CollectionError, match="Windows requires Python 3.13"):
        collect_host(output_root, command_runner=successful_result)
    assert not output_root.exists()


def test_artifact_permission_failure_cleans_staging_and_lock(tmp_path, monkeypatch):
    fixed_collection(monkeypatch)
    original_open = host_collector.os.open

    def denied_open(path, flags, mode=0o777, **kwargs):
        if host_collector.Path(path).name == HOST_PROVENANCE_NAME:
            raise PermissionError("denied")
        return original_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(host_collector.os, "open", denied_open)
    with pytest.raises(OutputWriteError, match="private collection output"):
        collect_host(tmp_path, command_runner=successful_result)
    assert not list(tmp_path.glob("atlcol-*"))
    assert not list(tmp_path.glob(".trustlab-host-*"))
    assert not (tmp_path / LOCK_NAME).exists()


def test_lock_release_failure_does_not_mask_primary_error(tmp_path, monkeypatch):
    original_unlink = host_collector.Path.unlink

    def denied_unlink(path, *args, **kwargs):
        if path.name == LOCK_NAME:
            raise PermissionError("denied")
        return original_unlink(path, *args, **kwargs)

    def mismatched_runner(command, **_kwargs):
        return HostCommandResult(
            "host.different",
            command.argv,
            "observed",
            0,
            False,
            "1.0.0",
            "",
        )

    monkeypatch.setattr(host_collector.Path, "unlink", denied_unlink)
    with pytest.raises(CollectionError, match="mismatched provenance"):
        collect_host(tmp_path, command_runner=mismatched_runner)
    original_unlink(tmp_path / LOCK_NAME)


def test_output_lock_and_symlink_fail_closed(tmp_path):
    lock = tmp_path / LOCK_NAME
    lock.write_bytes(b"")
    with pytest.raises(CollectionError, match="output lock"):
        collect_host(tmp_path, command_runner=successful_result)

    target = tmp_path / "target"
    target.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError):
        return
    with pytest.raises(CollectionError, match="symlink"):
        collect_host(alias, command_runner=successful_result)


@pytest.mark.parametrize(
    ("system_name", "expected"),
    [
        ("Darwin", "macos"),
        ("Linux", "linux"),
        ("Windows", "windows"),
        ("Other", "unknown"),
    ],
)
def test_platform_mapping_is_portable(monkeypatch, system_name, expected):
    monkeypatch.setattr(host_collector.platform, "system", lambda: system_name)
    assert host_collector._platform_name() == expected


def test_kernel_and_architecture_facts_drop_host_labels(monkeypatch):
    monkeypatch.setattr(
        host_collector.platform, "release", lambda: "6.8.0-alice-laptop"
    )
    monkeypatch.setattr(host_collector.platform, "machine", lambda: "alice-workstation")
    assert host_collector._kernel_summary() == "6.8.0"
    assert host_collector._architecture() == "unknown"


def test_cli_collect_host_is_silent_after_atomic_publication(
    tmp_path, monkeypatch, capsys
):
    result = HostCollectionResult(
        "atlcol-0123456789abcdef",
        tmp_path / "atlcol-0123456789abcdef",
        tmp_path / "atlcol-0123456789abcdef" / COMPLETION_MANIFEST_NAME,
    )
    calls = []
    monkeypatch.setattr(
        cli,
        "collect_host",
        lambda output: calls.append(output) or result,
    )

    assert cli.main(["collect", "host", "--output", str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert calls == [str(tmp_path)]
    assert captured.out == ""
    assert captured.err == ""
