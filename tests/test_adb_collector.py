from __future__ import annotations

import io
import os
import stat
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import trustlab.adb_collector as adb_collector
from trustlab import cli
from trustlab.adb_collector import (
    ADB_COMMANDS,
    ADB_PROVENANCE_NAME,
    COMPLETION_MANIFEST_NAME,
    IDENTITY_COMMAND,
    LOCK_NAME,
    MOUNTINFO_COMMAND,
    PREFLIGHT_COMMAND,
    PROC_MOUNTS_COMMAND,
    PROJECT_SALT_NAME,
    PROJECT_STATE_DIR_NAME,
    PROPERTY_COMMANDS,
    PROPERTY_KEYS,
    PS_SELECTED_COMMAND,
    RAW_REPORT_NAME,
    SELINUX_CONTEXT_COMMAND,
    SELINUX_MODE_COMMAND,
    TARGET_STATE_COMMAND,
    AdbCommand,
    AdbCommandResult,
    collect_adb,
    run_adb_command,
)
from trustlab.collection_manifest import (
    CollectionManifest,
    verify_collection_artifacts,
)
from trustlab.exceptions import CollectionError, OutputWriteError, SchemaValidationError
from trustlab.normalizer import normalize_collection_manifest
from trustlab.privacy import validate_portable_collection_manifest
from trustlab.report_writer import load_json
from trustlab.validators import validate_collection_manifest, validate_report

SERIAL = "emulator-5554"


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
        self.pid = 4242

    def wait(self, timeout=None):
        if self.times_out and not self.killed:
            raise subprocess.TimeoutExpired(["adb"], timeout)
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


PROPERTY_VALUES = {
    "ro.boot.verifiedbootstate": "green",
    "ro.boot.flash.locked": "1",
    "ro.boot.vbmeta.device_state": "locked",
    "ro.boot.veritymode": "enforcing",
    "ro.build.version.release": "16",
    "ro.build.version.sdk": "36",
    "ro.debuggable": "0",
    "ro.secure": "1",
    "ro.adb.secure": "1",
    "sys.boot_completed": "1",
    "ro.kernel.qemu": "1",
}


def successful_result(command: AdbCommand, serial: str, **_kwargs) -> AdbCommandResult:
    if command is PREFLIGHT_COMMAND:
        output = f"List of devices attached\n{serial}\tdevice\n"
    elif command is TARGET_STATE_COMMAND:
        output = "device\n"
    elif command.property_key is not None:
        output = f"{PROPERTY_VALUES[command.property_key]}\n"
    elif command is IDENTITY_COMMAND:
        output = "uid=2000(shell) gid=2000(shell) groups=2000(shell)\n"
    elif command is SELINUX_MODE_COMMAND:
        output = "Enforcing\n"
    elif command is MOUNTINFO_COMMAND:
        output = (
            "36 25 0:32 / /system ro,relatime shared:1 - "
            "ext4 /dev/block/dm-0 ro,seclabel\n"
        )
    elif command is PROC_MOUNTS_COMMAND:
        output = "/dev/block/dm-0 /system ext4 ro,seclabel 0 0\n"
    elif command is SELINUX_CONTEXT_COMMAND:
        output = "u:r:shell:s0:c1,c2\n"
    elif command is PS_SELECTED_COMMAND:
        output = (
            "LABEL NAME\n"
            "u:r:init:s0 init\n"
            "u:r:zygote:s0 zygote64\n"
            "u:r:untrusted_app:s0 com.private.customer\n"
        )
    else:
        output = "NAME\ninit\nzygote64\n"
    return AdbCommandResult(command.probe_id, "observed", 0, False, output, "")


def fixed_collection(monkeypatch) -> None:
    monkeypatch.setattr(
        adb_collector, "_new_collection_token", lambda: "0123456789abcdef"
    )
    timestamps = iter(("2026-07-16T10:00:00Z", "2026-07-16T10:00:01Z"))
    monkeypatch.setattr(adb_collector, "_utc_now", lambda: next(timestamps))
    monkeypatch.setattr(adb_collector.secrets, "token_bytes", lambda _size: b"s" * 32)


def expected_success_commands() -> tuple[AdbCommand, ...]:
    return (
        PREFLIGHT_COMMAND,
        TARGET_STATE_COMMAND,
        *PROPERTY_COMMANDS,
        IDENTITY_COMMAND,
        SELINUX_MODE_COMMAND,
        MOUNTINFO_COMMAND,
        SELINUX_CONTEXT_COMMAND,
        PS_SELECTED_COMMAND,
    )


def test_allowlist_is_exact_read_only_and_properties_are_individual():
    assert tuple(command.property_key for command in PROPERTY_COMMANDS) == PROPERTY_KEYS
    assert [command.execution_argv(SERIAL) for command in ADB_COMMANDS] == [
        ("adb", "devices"),
        ("adb", "-s", SERIAL, "get-state"),
        *[("adb", "-s", SERIAL, "shell", "getprop", key) for key in PROPERTY_KEYS],
        ("adb", "-s", SERIAL, "shell", "id"),
        ("adb", "-s", SERIAL, "shell", "getenforce"),
        ("adb", "-s", SERIAL, "shell", "cat", "/proc/self/mountinfo"),
        ("adb", "-s", SERIAL, "shell", "cat", "/proc/mounts"),
        ("adb", "-s", SERIAL, "shell", "id", "-Z"),
        ("adb", "-s", SERIAL, "shell", "ps", "-A", "-o", "LABEL,NAME"),
        ("adb", "-s", SERIAL, "shell", "ps", "-A", "-o", "NAME"),
    ]
    forbidden = {
        "root",
        "remount",
        "reboot",
        "su",
        "mount",
        "setprop",
        "push",
        "pull",
        "install",
        "uninstall",
        "shell",
    }
    # `shell` is permitted only as the fixed selector at index 3.
    for command in ADB_COMMANDS:
        argv = command.execution_argv(SERIAL)
        assert not (forbidden - {"shell"}).intersection(argv)
        if "shell" in argv:
            assert argv[3] == "shell"
        assert not any(
            token in part for part in argv for token in (";", "&&", "|", ">", "`", "$(")
        )
    assert all(command.adb_args != ("shell", "getprop") for command in ADB_COMMANDS)
    assert all("/proc/cmdline" not in command.adb_args for command in ADB_COMMANDS)


def test_unreviewed_command_and_property_fail_before_popen(monkeypatch):
    calls = []
    monkeypatch.setattr(
        adb_collector.subprocess, "Popen", lambda *_args, **_kwargs: calls.append(1)
    )
    unreviewed = AdbCommand(
        "adb.unreviewed",
        "unreviewed",
        ("shell", "reboot"),
        "identity",
        None,
        "restricted",
    )
    with pytest.raises(CollectionError, match="allowlist"):
        run_adb_command(unreviewed, SERIAL)
    forged_property = AdbCommand(
        "adb.property.ro_serialno",
        "property_ro_serialno",
        ("shell", "getprop", "ro.serialno"),
        "property",
        "GETPROP",
        "restricted",
        property_key="ro.serialno",
    )
    with pytest.raises(CollectionError, match="allowlist"):
        run_adb_command(forged_property, SERIAL)
    assert calls == []


def test_run_command_uses_exact_array_private_cwd_and_safe_environment(
    tmp_path, monkeypatch
):
    captured = {}
    process = FakeProcess(stdout=b"Enforcing\n")

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return process

    monkeypatch.setattr(adb_collector.subprocess, "Popen", fake_popen)
    result = run_adb_command(
        SELINUX_MODE_COMMAND,
        SERIAL,
        cwd=tmp_path,
        environment={
            "PATH": "/safe/bin",
            "HOME": "/private/home",
            "ADB_VENDOR_KEYS": "/private/key",
            "ANDROID_SERIAL": "wrong-target",
            "API_TOKEN": "secret",  # pragma: allowlist secret
        },
    )
    assert captured["argv"] == [
        "adb",
        "-s",
        SERIAL,
        "shell",
        "getenforce",
    ]
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL
    assert captured["kwargs"]["cwd"] == tmp_path
    assert captured["kwargs"]["env"] == {
        "PATH": "/safe/bin",
        "HOME": "/private/home",
        "ADB_VENDOR_KEYS": "/private/key",
    }
    assert result.status == "observed"


def test_windows_resolution_and_missing_executable_are_explicit(monkeypatch):
    monkeypatch.setattr(adb_collector, "_is_windows", lambda: True)
    monkeypatch.setattr(
        adb_collector.shutil,
        "which",
        lambda name, *, path: r"C:\sdk\adb.exe" if path == r"C:\sdk" else None,
    )
    argv = SELINUX_MODE_COMMAND.execution_argv(SERIAL)
    assert adb_collector._execution_argv(argv, {"PATH": r"C:\sdk"}) == [
        r"C:\sdk\adb.exe",
        *argv[1:],
    ]
    assert adb_collector._execution_argv(argv, {"PATH": r"C:\missing"}) is None


@pytest.mark.parametrize(
    ("error", "status", "reason"),
    [
        (FileNotFoundError(), "unsupported", "missing_command"),
        (PermissionError(), "inaccessible", "permission_denied"),
        (OSError(), "command_error", "command_error"),
    ],
)
def test_process_start_failures_are_structured(monkeypatch, error, status, reason):
    monkeypatch.setattr(
        adb_collector.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(error),
    )
    result = run_adb_command(SELINUX_MODE_COMMAND, SERIAL)
    assert (result.status, result.reason) == (status, reason)


def test_output_decoder_and_failure_classifier_are_closed():
    assert adb_collector._decode_output(b"line\r\nnext\r") == "line\nnext\n"
    assert adb_collector._decode_output(b"\xff") is None
    assert adb_collector._decode_output(b"bad\x00value") is None
    assert adb_collector._classify_failure("device offline") == (
        "command_error",
        "offline",
    )
    assert adb_collector._classify_failure("device unauthorized") == (
        "command_error",
        "unauthorized",
    )
    assert adb_collector._classify_failure("unrecognized failure") == (
        "command_error",
        "command_error",
    )


@pytest.mark.parametrize("timeout", (0, 61))
def test_unsafe_command_timeout_fails_before_process_start(monkeypatch, timeout):
    calls = []
    monkeypatch.setattr(
        adb_collector.subprocess, "Popen", lambda *_args, **_kwargs: calls.append(1)
    )
    with pytest.raises(CollectionError, match="timeout"):
        run_adb_command(SELINUX_MODE_COMMAND, SERIAL, timeout_seconds=timeout)
    assert calls == []


@pytest.mark.parametrize(
    ("process", "status", "reason", "timed_out"),
    [
        (FakeProcess(), "observed_absent", "none", False),
        (
            FakeProcess(stderr=b"permission denied\n", returncode=1),
            "inaccessible",
            "permission_denied",
            False,
        ),
        (
            FakeProcess(stderr=b"/system/bin/sh: ps: not found\n", returncode=127),
            "unsupported",
            "missing_command",
            False,
        ),
        (FakeProcess(times_out=True), "command_error", "timeout", True),
    ],
)
def test_run_command_models_empty_permission_missing_and_timeout(
    monkeypatch, process, status, reason, timed_out
):
    monkeypatch.setattr(
        adb_collector.subprocess, "Popen", lambda *_args, **_kwargs: process
    )
    result = run_adb_command(SELINUX_MODE_COMMAND, SERIAL, timeout_seconds=0.1)
    assert (result.status, result.reason, result.timed_out) == (
        status,
        reason,
        timed_out,
    )
    if timed_out:
        assert process.killed


def test_run_command_rejects_oversized_capture_without_publishing_prefix(monkeypatch):
    process = FakeProcess(stdout=b"x" * (adb_collector.MAX_CAPTURE_BYTES + 1))
    monkeypatch.setattr(
        adb_collector.subprocess, "Popen", lambda *_args, **_kwargs: process
    )
    result = run_adb_command(MOUNTINFO_COMMAND, SERIAL)
    assert (result.status, result.reason, result.exit_code) == (
        "command_error",
        "output_limit",
        None,
    )
    assert result.stdout == ""


def test_windows_dword_exit_is_retained_in_bound_provenance_and_outer_schema_maps_null(
    tmp_path, monkeypatch
):
    fixed_collection(monkeypatch)

    def runner(command, serial, **kwargs):
        if command is SELINUX_MODE_COMMAND:
            return AdbCommandResult(
                command.probe_id,
                "command_error",
                0xC0000005,
                False,
                "",
                "",
                "command_error",
            )
        return successful_result(command, serial, **kwargs)

    result = collect_adb(SERIAL, tmp_path, command_runner=runner)
    provenance = load_json(result.directory / ADB_PROVENANCE_NAME)
    getenforce = next(
        item for item in provenance["commands"] if item["probe_id"] == "adb.getenforce"
    )
    assert getenforce["exit_code"] == 0xC0000005
    manifest = load_json(result.manifest_path)
    outer = next(
        item for item in manifest["artifacts"] if item["probe_id"] == "adb.getenforce"
    )
    assert outer["exit_code"] is None


@pytest.mark.parametrize(
    "result",
    (
        AdbCommandResult(
            SELINUX_MODE_COMMAND.probe_id,
            "observed",
            0,
            False,
            "Enforcing\n",
            "",
            "offline",
        ),
        AdbCommandResult(
            SELINUX_MODE_COMMAND.probe_id,
            "unsupported",
            None,
            False,
            "",
            "",
            "none",
        ),
        AdbCommandResult(
            SELINUX_MODE_COMMAND.probe_id,
            "inaccessible",
            1,
            False,
            "",
            "",
            "none",
        ),
        AdbCommandResult(
            SELINUX_MODE_COMMAND.probe_id,
            "command_error",
            None,
            False,
            "",
            "",
            "unreviewed",  # type: ignore[arg-type]
        ),
    ),
)
def test_injected_command_results_fail_closed(result):
    with pytest.raises(CollectionError, match="invalid|inconsistent"):
        adb_collector._validate_result(SELINUX_MODE_COMMAND, result)


@pytest.mark.parametrize(
    "result",
    (
        AdbCommandResult("adb.wrong", "observed", 0, False, "x", ""),
        AdbCommandResult(
            SELINUX_MODE_COMMAND.probe_id, "observed", True, False, "x", ""
        ),
        AdbCommandResult(
            SELINUX_MODE_COMMAND.probe_id, "observed", 2**32, False, "x", ""
        ),
        AdbCommandResult(
            SELINUX_MODE_COMMAND.probe_id,
            "observed",
            0,
            False,
            "bad\x00value",
            "",
        ),
        AdbCommandResult(
            SELINUX_MODE_COMMAND.probe_id,
            "observed",
            0,
            1,  # type: ignore[arg-type]
            "x",
            "",
        ),
        AdbCommandResult(
            SELINUX_MODE_COMMAND.probe_id,
            "observed_absent",
            0,
            False,
            "unexpected",
            "",
        ),
    ),
)
def test_additional_injected_result_invariants(result):
    with pytest.raises(
        CollectionError, match="mismatched|invalid|unsafe|inconsistent|not boolean"
    ):
        adb_collector._validate_result(SELINUX_MODE_COMMAND, result)


def test_projection_helpers_fail_closed_and_preserve_safe_variants():
    with pytest.raises(CollectionError, match="property"):
        adb_collector._project_property(
            IDENTITY_COMMAND, "value", scope="target-0123456789abcdef"
        )
    assert (
        adb_collector._project_property(
            PROPERTY_COMMANDS[0], "", scope="target-0123456789abcdef"
        )
        is None
    )
    with pytest.raises(ValueError, match="property"):
        adb_collector._project_property(
            PROPERTY_COMMANDS[0], "green\nred", scope="target-0123456789abcdef"
        )
    qemu = next(
        command
        for command in PROPERTY_COMMANDS
        if command.property_key == "ro.kernel.qemu"
    )
    assert adb_collector._project_property(
        qemu, "2", scope="target-0123456789abcdef"
    ) == ("[ro.kernel.qemu]: [unknown]")
    with pytest.raises(ValueError, match="identity"):
        adb_collector._project_identity("not-an-id")
    assert adb_collector._project_identity("uid=1234(alice) gid=5678(staff)") == (
        "uid=1234(unknown) gid=5678(unknown)"
    )
    with pytest.raises(ValueError, match="SELinux mode"):
        adb_collector._project_selinux_mode("Unknown")
    with pytest.raises(ValueError, match="SELinux context"):
        adb_collector._project_selinux_context("not-a-context")
    with pytest.raises(ValueError, match="process"):
        adb_collector._project_processes("USER PID ARGS\nroot 1 init")


def test_sentinel_and_target_type_cover_every_closed_outcome():
    base = adb_collector.ProjectedResult(
        IDENTITY_COMMAND,
        "observed_absent",
        0,
        False,
        "",
        "empty",
        "empty",
        "none",
        10.0,
    )
    assert adb_collector._sentinel(replace(base, status="inaccessible")) == (
        "trustlab: inaccessible"
    )
    assert adb_collector._sentinel(replace(base, status="unsupported")) == (
        "trustlab: unsupported"
    )
    assert (
        adb_collector._sentinel(replace(base, status="command_error", timed_out=True))
        == "timeout"
    )
    assert adb_collector._sentinel(replace(base, status="command_error")) == (
        "trustlab: command error"
    )
    assert adb_collector._sentinel(base) == ""
    assert adb_collector._target_type([]) == "unknown"
    qemu = next(
        command
        for command in PROPERTY_COMMANDS
        if command.property_key == "ro.kernel.qemu"
    )
    qemu_result = replace(
        base, command=qemu, status="observed", payload="[ro.kernel.qemu]: [0]\n"
    )
    assert adb_collector._target_type([qemu_result]) == "physical"
    assert adb_collector._target_type([replace(qemu_result, payload="unknown\n")]) == (
        "unknown"
    )


@pytest.mark.parametrize(
    ("output", "message"),
    [
        ("List of devices attached\nemulator-5554\toffline\n", "offline"),
        ("List of devices attached\nemulator-5554\tunauthorized\n", "unauthorized"),
        (
            "List of devices attached\nemulator-5554\tdevice\nother\tdevice\n",
            "multiple devices",
        ),
        (
            "List of devices attached\nemulator-5554\tdevice\nother\toffline\n",
            "multiple devices",
        ),
        ("List of devices attached\nother\tdevice\n", "target not found"),
        ("List of devices attached\nbroken-row\n", "malformed"),
    ],
)
def test_preflight_state_matrix_fails_before_shell(tmp_path, output, message):
    calls = []

    def runner(command, _serial, **_kwargs):
        calls.append(command)
        return AdbCommandResult(command.probe_id, "observed", 0, False, output, "")

    with pytest.raises(CollectionError, match=message):
        collect_adb(SERIAL, tmp_path, command_runner=runner)
    assert calls == [PREFLIGHT_COMMAND]
    assert not list(tmp_path.glob("atlcol-*"))


def test_preflight_no_permissions_row_is_not_misreported_as_missing(tmp_path):
    output = "List of devices attached\n????????????\tno permissions (udev rules)\n"

    def runner(command, _serial, **_kwargs):
        return AdbCommandResult(command.probe_id, "observed", 0, False, output, "")

    with pytest.raises(CollectionError, match="permission denied"):
        collect_adb(SERIAL, tmp_path, command_runner=runner)


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (
            AdbCommandResult(
                PREFLIGHT_COMMAND.probe_id,
                "unsupported",
                None,
                False,
                "",
                "",
                "missing_command",
            ),
            "missing command",
        ),
        (
            AdbCommandResult(
                PREFLIGHT_COMMAND.probe_id,
                "command_error",
                None,
                True,
                "",
                "",
                "timeout",
            ),
            "timeout",
        ),
        (
            AdbCommandResult(
                PREFLIGHT_COMMAND.probe_id,
                "inaccessible",
                None,
                False,
                "",
                "",
                "permission_denied",
            ),
            "permission denied",
        ),
    ],
)
def test_preflight_tool_failures_are_distinct_and_serial_free(
    tmp_path, result, message
):
    with pytest.raises(CollectionError, match=message) as raised:
        collect_adb(SERIAL, tmp_path, command_runner=lambda *_args, **_kwargs: result)
    assert SERIAL not in str(raised.value)


def test_target_state_confirmation_precedes_every_shell_command(tmp_path):
    calls = []

    def runner(command, serial, **kwargs):
        calls.append(command)
        result = successful_result(command, serial, **kwargs)
        if command is TARGET_STATE_COMMAND:
            return AdbCommandResult(
                command.probe_id, "observed", 0, False, "offline\n", ""
            )
        return result

    with pytest.raises(CollectionError, match="invalid state"):
        collect_adb(SERIAL, tmp_path, command_runner=runner)
    assert calls == [PREFLIGHT_COMMAND, TARGET_STATE_COMMAND]


def test_complete_collection_validates_verifies_normalizes_and_is_private(
    tmp_path, monkeypatch
):
    fixed_collection(monkeypatch)
    calls = []

    def runner(command, serial, **kwargs):
        calls.append(command)
        return successful_result(command, serial, **kwargs)

    result = collect_adb(SERIAL, tmp_path, command_runner=runner)
    assert tuple(calls) == expected_success_commands()
    manifest_document = load_json(result.manifest_path)
    validate_collection_manifest(manifest_document)
    validate_portable_collection_manifest(manifest_document)
    assert manifest_document["completion_status"] == "complete"
    assert manifest_document["target"] == {
        "pseudonymous_id": result.target_id,
        "target_type": "avd",
    }
    manifest = CollectionManifest.from_dict(manifest_document)
    verified = verify_collection_artifacts(manifest, result.manifest_path)
    assert {"raw_report", "command_results", "mountinfo", "ps_selected"} <= set(
        verified
    )
    report = normalize_collection_manifest(result.manifest_path)
    validate_report(report)
    assert report["boot_state"]["boot_completed"]["value"] == "1"
    assert report["target"]["target_type"] == "avd"
    assert report["process_state"]["selected_processes"]
    if os.name == "posix":
        assert stat.S_IMODE(result.directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(result.manifest_path.stat().st_mode) == 0o600
        state_dir = tmp_path / PROJECT_STATE_DIR_NAME
        assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE((state_dir / PROJECT_SALT_NAME).stat().st_mode) == 0o600
        assert all(
            stat.S_IMODE(path.stat().st_mode) == 0o600
            for path in result.directory.rglob("*")
            if path.is_file()
        )
    assert not (tmp_path / LOCK_NAME).exists()
    assert not list(tmp_path.glob(".trustlab-adb-????????"))


def test_portable_provenance_records_exact_logical_arguments_without_serial(
    tmp_path, monkeypatch
):
    fixed_collection(monkeypatch)
    result = collect_adb(SERIAL, tmp_path, command_runner=successful_result)
    provenance = load_json(result.directory / ADB_PROVENANCE_NAME)
    assert provenance["commands"][0]["argv"] == ["adb", "devices"]
    assert provenance["commands"][1]["argv"] == [
        "adb",
        "-s",
        "<selected-target>",
        "get-state",
    ]
    assert provenance["commands"][2]["argv"] == [
        "adb",
        "-s",
        "<selected-target>",
        "shell",
        "getprop",
        PROPERTY_KEYS[0],
    ]
    assert set(provenance["commands"][2]) == {
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
    tree = b"".join(
        path.read_bytes() for path in result.directory.rglob("*") if path.is_file()
    )
    assert SERIAL.encode() not in tree
    assert b"com.private.customer" not in tree
    assert b"c1,c2" not in tree


def test_adb_manifest_privacy_bindings_are_collector_specific(tmp_path, monkeypatch):
    fixed_collection(monkeypatch)
    result = collect_adb(SERIAL, tmp_path, command_runner=successful_result)
    manifest = load_json(result.manifest_path)
    manifest["artifacts"][0]["relative_path"] = "unreviewed.txt"
    with pytest.raises(SchemaValidationError, match="artifact binding"):
        validate_portable_collection_manifest(manifest)

    manifest = load_json(result.manifest_path)
    manifest["artifacts"][1]["relative_path"] = "host_provenance.json"
    with pytest.raises(SchemaValidationError, match="artifact binding"):
        validate_portable_collection_manifest(manifest)

    manifest = load_json(result.manifest_path)
    manifest["artifacts"][2]["logical_name"] = "unreviewed_capture"
    with pytest.raises(SchemaValidationError, match="artifact binding"):
        validate_portable_collection_manifest(manifest)


def test_process_projection_keeps_only_selected_names_and_domains(
    tmp_path, monkeypatch
):
    fixed_collection(monkeypatch)
    result = collect_adb(SERIAL, tmp_path, command_runner=successful_result)
    output = (result.directory / "captures/ps_selected.txt").read_text()
    assert output == "u:r:init:s0 init\nu:r:zygote:s0 zygote64\n"
    assert "customer" not in output


def test_mount_and_process_fallbacks_are_ordered_and_partial(tmp_path, monkeypatch):
    fixed_collection(monkeypatch)
    calls = []

    def runner(command, serial, **kwargs):
        calls.append(command)
        if command in {MOUNTINFO_COMMAND, PS_SELECTED_COMMAND}:
            return AdbCommandResult(
                command.probe_id,
                "inaccessible",
                1,
                False,
                "",
                "permission denied",
                "permission_denied",
            )
        return successful_result(command, serial, **kwargs)

    result = collect_adb(SERIAL, tmp_path, command_runner=runner)
    assert calls.index(PROC_MOUNTS_COMMAND) == calls.index(MOUNTINFO_COMMAND) + 1
    assert calls[-2:] == [
        PS_SELECTED_COMMAND,
        adb_collector.PS_SELECTED_FALLBACK_COMMAND,
    ]
    manifest = load_json(result.manifest_path)
    assert manifest["completion_status"] == "partial"
    statuses = {item["logical_name"]: item["status"] for item in manifest["artifacts"]}
    assert statuses["mountinfo"] == "inaccessible"
    assert statuses["proc_mounts"] == "observed"
    assert statuses["ps_selected"] == "inaccessible"
    report = normalize_collection_manifest(result.manifest_path)
    validate_report(report)
    assert (
        "collection manifest completion status: partial"
        in report["limitations"]["collection_errors"]
    )


def test_required_missing_command_makes_collection_partial(tmp_path, monkeypatch):
    fixed_collection(monkeypatch)

    def runner(command, serial, **kwargs):
        if command is IDENTITY_COMMAND:
            return AdbCommandResult(
                command.probe_id,
                "unsupported",
                127,
                False,
                "",
                "not found",
                "missing_command",
            )
        return successful_result(command, serial, **kwargs)

    result = collect_adb(SERIAL, tmp_path, command_runner=runner)
    manifest = load_json(result.manifest_path)
    assert manifest["completion_status"] == "partial"
    identity = next(
        item for item in manifest["artifacts"] if item["probe_id"] == "adb.identity"
    )
    assert identity["status"] == "unsupported"
    report = normalize_collection_manifest(result.manifest_path)
    validate_report(report)


def test_short_serial_does_not_corrupt_projected_evidence(tmp_path, monkeypatch):
    fixed_collection(monkeypatch)
    result = collect_adb("ro", tmp_path, command_runner=successful_result)
    mountinfo = (result.directory / "captures/mountinfo.txt").read_text()
    assert "relatime,ro" in mountinfo
    provenance = load_json(result.directory / ADB_PROVENANCE_NAME)
    selectors = [
        item["argv"][2]
        for item in provenance["commands"]
        if len(item["argv"]) > 2 and item["argv"][1] == "-s"
    ]
    assert selectors and set(selectors) == {"<selected-target>"}


def test_serial_is_removed_from_hostile_capture_and_exception_text(
    tmp_path, monkeypatch
):
    fixed_collection(monkeypatch)

    def runner(command, serial, **kwargs):
        result = successful_result(command, serial, **kwargs)
        if command is MOUNTINFO_COMMAND:
            return AdbCommandResult(
                command.probe_id,
                "observed",
                0,
                False,
                f"36 25 0:32 / /{serial} ro - ext4 /dev/block/dm-0 ro\n",
                f"device {serial} warning",
            )
        return result

    result = collect_adb(SERIAL, tmp_path, command_runner=runner)
    tree = b"".join(
        path.read_bytes() for path in result.directory.rglob("*") if path.is_file()
    )
    assert SERIAL.encode() not in tree


def test_project_salt_is_stable_private_and_not_an_unsalted_hash(tmp_path, monkeypatch):
    monkeypatch.setattr(adb_collector.secrets, "token_bytes", lambda _size: b"a" * 32)
    root = adb_collector._prepare_output_root(tmp_path)
    salt = adb_collector._load_or_create_project_salt(root)
    assert adb_collector._load_or_create_project_salt(root) == salt
    first = adb_collector._target_id(SERIAL, salt)
    second = adb_collector._target_id(SERIAL, b"b" * 32)
    assert first != second
    assert (
        first
        != f"target-{adb_collector.hashlib.sha256(SERIAL.encode()).hexdigest()[:16]}"
    )
    assert (
        len((tmp_path / PROJECT_STATE_DIR_NAME / PROJECT_SALT_NAME).read_bytes()) == 32
    )


def test_project_salt_rejects_symlinks_hardlinks_and_public_modes(tmp_path):
    state_dir = tmp_path / PROJECT_STATE_DIR_NAME
    state_dir.mkdir()
    external = tmp_path / "external"
    external.write_bytes(b"a" * 32)
    salt_path = state_dir / PROJECT_SALT_NAME
    salt_path.symlink_to(external)
    with pytest.raises(CollectionError, match="safely"):
        adb_collector._load_or_create_project_salt(tmp_path)
    salt_path.unlink()

    os.link(external, salt_path)
    with pytest.raises(CollectionError, match="regular file"):
        adb_collector._load_or_create_project_salt(tmp_path)
    salt_path.unlink()
    external.unlink()

    salt_path.write_bytes(b"a" * 32)
    salt_path.chmod(0o644)
    with pytest.raises(CollectionError, match="permissions"):
        adb_collector._load_or_create_project_salt(tmp_path)


def test_windows_project_salt_requires_external_fixed_length_secret(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(adb_collector, "_is_windows", lambda: True)
    with pytest.raises(CollectionError, match="64-hex project salt"):
        adb_collector._load_or_create_project_salt(tmp_path, environment={})
    with pytest.raises(CollectionError, match="64-hex project salt"):
        adb_collector._load_or_create_project_salt(
            tmp_path, environment={"TRUSTLAB_ADB_PROJECT_SALT": "A" * 64}
        )
    salt = adb_collector._load_or_create_project_salt(
        tmp_path, environment={"TRUSTLAB_ADB_PROJECT_SALT": "ab" * 32}
    )
    assert salt == bytes.fromhex("ab" * 32)
    assert not (tmp_path / PROJECT_STATE_DIR_NAME).exists()


def test_completion_manifest_is_written_last(tmp_path, monkeypatch):
    fixed_collection(monkeypatch)
    writes = []
    original = adb_collector._write_private_bytes

    def recording_write(path: Path, payload: bytes):
        writes.append(path.name)
        original(path, payload)

    monkeypatch.setattr(adb_collector, "_write_private_bytes", recording_write)
    result = collect_adb(SERIAL, tmp_path, command_runner=successful_result)
    assert result.manifest_path.name == COMPLETION_MANIFEST_NAME
    assert writes[-1] == COMPLETION_MANIFEST_NAME
    assert writes[-3:-1] == [RAW_REPORT_NAME, ADB_PROVENANCE_NAME]


def test_atomic_publication_failure_cleans_staging_and_lock(tmp_path, monkeypatch):
    fixed_collection(monkeypatch)
    monkeypatch.setattr(
        adb_collector.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("rename failed")),
    )
    with pytest.raises(OutputWriteError, match="publish"):
        collect_adb(SERIAL, tmp_path, command_runner=successful_result)
    assert not list(tmp_path.glob("atlcol-*"))
    assert not list(tmp_path.glob(".trustlab-adb-????????"))
    assert not (tmp_path / LOCK_NAME).exists()


def test_lock_contention_fails_without_target_command(tmp_path):
    (tmp_path / LOCK_NAME).write_text("held")
    calls = []
    with pytest.raises(CollectionError, match="another ADB collection"):
        collect_adb(
            SERIAL,
            tmp_path,
            command_runner=lambda *args, **kwargs: calls.append((args, kwargs)),
        )
    assert calls == []


def test_cli_collect_adb_is_silent_and_passes_exact_options(
    tmp_path, monkeypatch, capsys
):
    calls = []
    monkeypatch.setattr(
        cli,
        "collect_adb",
        lambda serial, output: calls.append((serial, output)),
    )
    assert (
        cli.main(["collect", "adb", "--serial", SERIAL, "--output", str(tmp_path)]) == 0
    )
    assert calls == [(SERIAL, str(tmp_path))]
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "serial",
    ("", "-serial", "serial with space", "serial/path", "serial\nnext"),
)
def test_unsafe_serial_is_rejected_without_echo_or_output(tmp_path, serial):
    with pytest.raises(CollectionError, match="unsafe format") as raised:
        collect_adb(serial, tmp_path)
    if serial:
        assert serial not in str(raised.value)
    assert list(tmp_path.iterdir()) == []
