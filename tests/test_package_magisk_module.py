import hashlib
import importlib.util
import io
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

import pytest

from trustlab.normalizer import normalize_raw_file
from trustlab.validators import validate_report

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "package_magisk_module", ROOT / "tools" / "package_magisk_module.py"
)
package_magisk_module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(package_magisk_module)


def test_module_structural_validation_passes_for_checked_in_module():
    package_magisk_module.validate_module(ROOT / "module" / "trustlab-magisk")


def test_module_structural_validation_rejects_overlay_payload(tmp_path):
    module_copy = tmp_path / "trustlab-magisk"
    shutil.copytree(ROOT / "module" / "trustlab-magisk", module_copy)
    forbidden = module_copy / "system" / "etc" / "hosts"
    forbidden.parent.mkdir(parents=True)
    forbidden.write_text("127.0.0.1 example.invalid\n", encoding="utf-8")

    errors = package_magisk_module.validate_payload_structure(module_copy)
    assert any("system/etc/hosts" in error for error in errors)


def module_copy(tmp_path):
    target = tmp_path / "trustlab-magisk"
    shutil.copytree(ROOT / "module" / "trustlab-magisk", target)
    return target


def test_module_guardrails_require_private_output_permissions(tmp_path):
    copied = module_copy(tmp_path)
    script = copied / "scripts/write_report.sh"
    script.write_text(
        script.read_text(encoding="utf-8").replace("umask 077", "umask 022"),
        encoding="utf-8",
    )
    errors = package_magisk_module.validate_collector_guardrails(copied)
    assert any("umask 077" in error for error in errors)


def test_module_guardrails_ignore_commented_guard_text(tmp_path):
    copied = module_copy(tmp_path)
    script = copied / "scripts/write_report.sh"
    script.write_text(
        script.read_text(encoding="utf-8").replace("umask 077", ": # umask 077"),
        encoding="utf-8",
    )
    errors = package_magisk_module.validate_collector_guardrails(copied)
    assert any("umask 077" in error for error in errors)


def test_module_guardrails_reject_shell_writable_output_path(tmp_path):
    copied = module_copy(tmp_path)
    script = copied / "scripts/write_report.sh"
    script.write_text(
        script.read_text(encoding="utf-8").replace(
            "/data/adb/android-trust-lab", "/data/local/tmp/android-trust-lab"
        ),
        encoding="utf-8",
    )
    errors = package_magisk_module.validate_collector_guardrails(copied)
    assert any("under /data/adb" in error for error in errors)
    assert any("/data/local/tmp" in error for error in errors)


def test_module_guardrails_reject_broad_property_collection(tmp_path):
    copied = module_copy(tmp_path)
    script = copied / "scripts/collect_props.sh"
    script.write_text(
        script.read_text(encoding="utf-8") + "\ngetprop 2>/dev/null\n",
        encoding="utf-8",
    )
    errors = package_magisk_module.validate_collector_guardrails(copied)
    assert any("only individual allowlisted properties" in error for error in errors)


@pytest.mark.parametrize(
    "command",
    [
        "mount",
        "setprop ro.debuggable 1",
        "su -c id",
        "reboot bootloader",
        "adb root",
        "adb remount",
        "fastboot reboot",
        "/system/bin/mount -o rw,remount /system",
        "toybox mount -o rw,remount /system",
        "resetprop ro.debuggable 1",
        "setenforce 0",
        "magisk --install boot.img",
        "dd if=boot.img of=/dev/block/by-name/boot",
    ],
)
def test_module_guardrails_reject_forbidden_runtime_commands(tmp_path, command):
    copied = module_copy(tmp_path)
    script = copied / "scripts/collect_root_state.sh"
    script.write_text(
        script.read_text(encoding="utf-8") + f"\n{command}\n",
        encoding="utf-8",
    )

    errors = package_magisk_module.validate_collector_guardrails(copied)

    assert "collector must not invoke privileged mutation commands" in errors


def test_module_runtime_keeps_phase_six_safety_and_publication_boundaries():
    module = ROOT / "module/trustlab-magisk"
    writer = (module / "scripts/write_report.sh").read_text(encoding="utf-8")
    service = (module / "service.sh").read_text(encoding="utf-8")
    mounts = (module / "scripts/collect_mounts.sh").read_text(encoding="utf-8")

    assert (module / "skip_mount").read_bytes() == b""
    assert ">/dev/null2>&1" not in service.replace(" ", "")
    assert 'mkdir "$LOCK_DIR"' in writer
    assert "trap 'on_interrupt' HUP INT TERM" in writer
    assert 'ln "$MANIFEST" "$FINAL_DIR/collector_manifest.json"' in writer
    assert 'for PUBLISH_FILE in "$CAPTURE_DIR"/*.txt' not in writer
    assert "collector.log" in writer
    assert not any(
        line.strip().startswith("mount ") or line.strip() == "mount"
        for line in mounts.splitlines()
    )


def test_module_guardrails_require_portable_integrity_bound_manifest(tmp_path):
    copied = module_copy(tmp_path)
    script = copied / "scripts/write_report.sh"
    content = script.read_text(encoding="utf-8")
    content = content.replace('"schema_version": "1.0.0"', '"schema_version": "0.1"')
    content = content.replace('"relative_path": "raw.txt"', '"relative_path": "$RAW"')
    content = content.replace('sha256sum "$RAW"', "printf missing-digest")
    script.write_text(content, encoding="utf-8")

    errors = package_magisk_module.validate_collector_guardrails(copied)
    assert any("schema 1.0.0" in error for error in errors)
    assert any("portable and relative" in error for error in errors)
    assert any("bind the raw artifact digest" in error for error in errors)


def test_module_metadata_rejects_json_unsafe_collector_version(tmp_path):
    copied = module_copy(tmp_path)
    metadata = copied / "module.prop"
    metadata.write_text(
        metadata.read_text(encoding="utf-8").replace(
            "version=0.3.0-dev0", 'version=0.3.0-quote"\\escape'
        ),
        encoding="utf-8",
    )

    errors = package_magisk_module.validate_module_metadata(copied)
    assert errors == ["module.prop version must be one schema-safe collector version"]
    with pytest.raises(SystemExit, match="schema-safe collector version"):
        package_magisk_module.validate_module(copied)


def test_magisk_emitter_uses_stable_random_target_pseudonym():
    script = (ROOT / "module/trustlab-magisk/scripts/write_report.sh").read_text(
        encoding="utf-8"
    )
    assert 'TARGET_TOKEN_FILE="$BASE_DIR/target_pseudonym"' in script
    assert "dd if=/dev/urandom" in script
    assert 'TARGET_TOKEN="$(printf \'%s\' "$RAW_SHA256"' not in script


def test_module_guardrails_reject_kernel_command_line_capture(tmp_path):
    copied = module_copy(tmp_path)
    script = copied / "scripts/collect_boot_state.sh"
    script.write_text(
        script.read_text(encoding="utf-8") + "\ncat /proc/cmdline\n",
        encoding="utf-8",
    )
    errors = package_magisk_module.validate_collector_guardrails(copied)
    assert any("kernel command line" in error for error in errors)


def test_module_guardrails_scan_every_collector_for_sensitive_sources(tmp_path):
    copied = module_copy(tmp_path)
    process_script = copied / "scripts/collect_process_state.sh"
    process_script.write_text(
        process_script.read_text(encoding="utf-8")
        + "\ncat /proc/cmdline\nps -AZ\nLEAK=$(ps -ef)\n",
        encoding="utf-8",
    )
    boot_script = copied / "scripts/collect_boot_state.sh"
    boot_script.write_text(
        boot_script.read_text(encoding="utf-8") + "\ngetprop ro.serialno\n",
        encoding="utf-8",
    )

    errors = package_magisk_module.validate_collector_guardrails(copied)
    assert any("kernel command line" in error for error in errors)
    assert any("raw process command lines" in error for error in errors)
    assert any("only individual allowlisted properties" in error for error in errors)


def test_process_collector_does_not_publish_command_arguments(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_ps = fake_bin / "ps"
    fake_ps.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "-AZ" ]; then\n'
        "  printf '%s\\n' 'u:r:init:s0 root 1 0 init'\n"
        "  printf '%s\\n' 'u:r:shell:s0 root 9 1 init PRIVATE_COMMAND_TOKEN'\n"
        "else\n"
        "  printf '%s\\n' 'root 1 0 init'\n"
        "  printf '%s\\n' 'root 9 1 init PRIVATE_COMMAND_TOKEN'\n"
        "fi\n",
        encoding="utf-8",
    )
    fake_ps.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
    result = subprocess.run(
        ["sh", ROOT / "module/trustlab-magisk/scripts/collect_process_state.sh"],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "u:r:init:s0 init" in result.stdout
    assert "PRIVATE_COMMAND_TOKEN" not in result.stdout


def test_security_collectors_emit_safe_classifiable_failure_markers(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    commands = {
        "getenforce": "printf '%s\\n' 'getenforce: Permission denied' >&2\nexit 1\n",
        "id": "printf '%s\\n' 'id: not found' >&2\nexit 127\n",
        "ps": "printf '%s\\n' 'ps: not found' >&2\nexit 127\n",
    }
    for name, body in commands.items():
        executable = fake_bin / name
        executable.write_text(f"#!/bin/sh\n{body}", encoding="utf-8")
        executable.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"

    selinux = subprocess.run(
        ["sh", ROOT / "module/trustlab-magisk/scripts/collect_selinux.sh"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    processes = subprocess.run(
        ["sh", ROOT / "module/trustlab-magisk/scripts/collect_process_state.sh"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert selinux.returncode == 10
    assert processes.returncode == 11
    assert "Permission denied" not in selinux.stdout
    assert "not found" not in selinux.stdout
    assert "not found" not in processes.stdout
    assert "trustlab: inaccessible" in selinux.stdout
    assert "trustlab: unsupported" in selinux.stdout
    assert "trustlab: unsupported" in processes.stdout

    raw = tmp_path / "collector-failures.txt"
    raw.write_text(selinux.stdout + processes.stdout, encoding="utf-8")
    report = normalize_raw_file(
        raw,
        collection_timestamp="2026-07-16T20:00:00Z",
        raw_artifact_ref="tests/generated/collector-failures.txt",
    )

    assert report["selinux"]["policy_mode"]["status"] == "inaccessible"
    assert report["selinux"]["current_context"]["status"] == "unsupported"
    assert report["process_state"]["capture_status"] == "unsupported"
    validate_report(report)


def test_security_collectors_fail_closed_on_malformed_success(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    commands = {
        "getenforce": "printf '%s\\n' 'MALFORMED_PRIVATE_MODE'\n",
        "id": (
            "if [ \"$1\" = -Z ]; then printf '%s\\n' 'u:r:magisk:s0'; "
            "else printf '%s\\n' malformed; fi\n"
        ),
    }
    for name, body in commands.items():
        executable = fake_bin / name
        executable.write_text(f"#!/bin/sh\n{body}", encoding="utf-8")
        executable.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"

    selinux = subprocess.run(
        ["sh", ROOT / "module/trustlab-magisk/scripts/collect_selinux.sh"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    root = subprocess.run(
        ["sh", ROOT / "module/trustlab-magisk/scripts/collect_root_state.sh"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert selinux.returncode == 12
    assert root.returncode == 12
    assert "MALFORMED_PRIVATE_MODE" not in selinux.stdout
    assert "trustlab: command error" in selinux.stdout


def test_module_structure_rejects_symlinks_without_reading_target(tmp_path):
    copied = module_copy(tmp_path)
    external = tmp_path / "sensitive.txt"
    external.write_text("host-sensitive-sentinel\n", encoding="utf-8")
    (copied / "leak.txt").symlink_to(external)

    errors = package_magisk_module.validate_payload_structure(copied)
    assert any("module symlink is not allowed: leak.txt" in error for error in errors)
    output = tmp_path / "unsafe.zip"
    with pytest.raises(ValueError, match="module symlink is not allowed"):
        package_magisk_module.write_zip(output, copied)
    assert not output.exists()


def test_missing_required_script_has_clean_validation_error(tmp_path):
    copied = module_copy(tmp_path)
    (copied / "scripts/collect_props.sh").unlink()
    with pytest.raises(SystemExit, match="missing required module file"):
        package_magisk_module.validate_module(copied)


def test_package_zip_contains_module_root_files(tmp_path):
    out = tmp_path / "androidtrustlab-magisk.zip"
    package_magisk_module.validate_module(ROOT / "module" / "trustlab-magisk")
    package_magisk_module.write_zip(out, ROOT / "module" / "trustlab-magisk")

    with zipfile.ZipFile(out) as archive:
        names = set(archive.namelist())
    assert "module.prop" in names
    assert "scripts/write_report.sh" in names
    assert "META-INF/com/google/android/update-binary" in names
    assert "META-INF/com/google/android/updater-script" in names
    assert "customize.sh" in names


def test_package_bytes_ignore_checkout_modes_and_mtimes(tmp_path):
    first_module = tmp_path / "first-module"
    second_module = tmp_path / "second-module"
    shutil.copytree(ROOT / "module" / "trustlab-magisk", first_module)
    shutil.copytree(ROOT / "module" / "trustlab-magisk", second_module)
    for path in first_module.rglob("*"):
        if path.is_file():
            path.chmod(0o600)
            os.utime(path, (1_700_000_000, 1_700_000_000))
    for path in second_module.rglob("*"):
        if path.is_file():
            path.chmod(0o777)
            os.utime(path, (1_800_000_000, 1_800_000_000))
    first_archive = tmp_path / "first.zip"
    second_archive = tmp_path / "second.zip"

    first_digest = package_magisk_module.build_reproducible_archive(
        first_archive, first_module
    )
    second_digest = package_magisk_module.build_reproducible_archive(
        second_archive, second_module
    )

    assert first_archive.read_bytes() == second_archive.read_bytes()
    assert first_digest == second_digest
    assert first_digest == hashlib.sha256(first_archive.read_bytes()).hexdigest()
    assert first_digest == package_magisk_module.sha256_file(first_archive)
    if os.name != "nt":
        assert stat.S_IMODE(first_archive.stat().st_mode) == 0o644


def test_package_zip_metadata_modes_order_and_payload_are_canonical(tmp_path):
    output = tmp_path / "canonical.zip"
    timestamp = package_magisk_module.DEFAULT_ZIP_TIMESTAMP
    package_magisk_module.write_zip(
        output,
        ROOT / "module" / "trustlab-magisk",
        timestamp=timestamp,
    )

    assert (
        package_magisk_module.validate_archive_structure(output, timestamp=timestamp)
        == []
    )
    with zipfile.ZipFile(output) as archive:
        infos = archive.infolist()
        assert archive.comment == b""
        assert [info.filename for info in infos] == sorted(
            package_magisk_module.ALLOWED_FILES
            | package_magisk_module.ARCHIVE_DIRECTORY_ENTRIES
        )
    for info in infos:
        if info.filename.endswith("/"):
            assert stat.S_ISDIR(info.external_attr >> 16)
            assert stat.S_IMODE(info.external_attr >> 16) == 0o755
            continue
        expected_mode = 0o755 if info.filename.endswith(".sh") else 0o644
        unix_mode = info.external_attr >> 16
        assert stat.S_ISREG(unix_mode)
        assert stat.S_IMODE(unix_mode) == expected_mode
        assert stat.S_IMODE(unix_mode) & 0o022 == 0
        assert info.create_system == 3
        assert info.create_version == 20
        assert info.extract_version == 20
        assert info.compress_type == zipfile.ZIP_STORED
        assert info.date_time == timestamp
        assert info.extra == b""
        assert info.comment == b""


def test_source_date_epoch_is_utc_zip_safe_and_two_second_normalized():
    assert package_magisk_module.canonical_zip_timestamp({}) == (
        1980,
        1,
        1,
        0,
        0,
        0,
    )
    assert package_magisk_module.canonical_zip_timestamp(
        {"SOURCE_DATE_EPOCH": "315532801"}
    ) == (1980, 1, 1, 0, 0, 0)
    assert package_magisk_module.canonical_zip_timestamp(
        {"SOURCE_DATE_EPOCH": "1784203201"}
    ) == (*time.gmtime(1_784_203_201)[:5], 0)


@pytest.mark.parametrize(
    "source_date_epoch",
    ["", "-1", "1.5", "not-a-time", "0", "9999999999999"],
)
def test_source_date_epoch_rejects_malformed_or_non_zip_safe_values(
    source_date_epoch,
):
    with pytest.raises(ValueError, match="SOURCE_DATE_EPOCH"):
        package_magisk_module.canonical_zip_timestamp(
            {"SOURCE_DATE_EPOCH": source_date_epoch}
        )


def test_archive_path_validation_rejects_nonportable_and_duplicate_names():
    errors = package_magisk_module.validate_archive_paths(
        [
            "/absolute",
            "../traversal",
            "C:/drive-path",
            "//server/share",
            "scripts\\write_report.sh",
            "scripts/write_report.sh",
            "scripts//collect.sh",
        ]
    )

    assert any("must be relative" in error for error in errors)
    assert any("must be normalized" in error for error in errors)
    assert any("forward separators" in error for error in errors)
    assert any("duplicate normalized archive path" in error for error in errors)


def test_payload_allowlist_rejects_unexpected_files_directories_and_archives(
    tmp_path,
):
    copied = module_copy(tmp_path)
    (copied / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    (copied / "empty-directory").mkdir()
    (copied / "payload.ZIP").write_bytes(b"PK\x03\x04embedded")

    errors = package_magisk_module.validate_payload_structure(copied)

    assert any("unexpected module payload: unexpected.txt" in error for error in errors)
    assert any(
        "unexpected module directory: empty-directory" in error for error in errors
    )
    assert any(
        "embedded archive is not allowed: payload.ZIP" in error for error in errors
    )


def test_payload_allowlist_rejects_archive_magic_under_allowed_name(tmp_path):
    copied = module_copy(tmp_path)
    (copied / "README.md").write_bytes(b"PK\x03\x04renamed-archive")

    errors = package_magisk_module.validate_payload_structure(copied)

    assert "embedded archive signature is not allowed: README.md" in errors


def test_payload_allowlist_rejects_zip_with_preamble_under_allowed_name(tmp_path):
    copied = module_copy(tmp_path)
    embedded = io.BytesIO()
    with zipfile.ZipFile(embedded, "w") as archive:
        archive.writestr("payload.txt", b"embedded" * 512)
    (copied / "README.md").write_bytes(b"harmless-preamble\n" + embedded.getvalue())

    errors = package_magisk_module.validate_payload_structure(copied)

    assert "embedded archive signature is not allowed: README.md" in errors


def test_payload_limits_fail_closed(tmp_path, monkeypatch):
    copied = module_copy(tmp_path)
    monkeypatch.setattr(package_magisk_module, "MAX_ENTRIES", 1)

    errors = package_magisk_module.validate_payload_structure(copied)

    assert "module entry count exceeds 1" in errors

    monkeypatch.setattr(package_magisk_module, "MAX_ENTRIES", 32)
    monkeypatch.setattr(package_magisk_module, "MAX_FILES", 1)

    errors = package_magisk_module.validate_payload_structure(copied)

    assert "module file count exceeds 1" in errors

    monkeypatch.setattr(package_magisk_module, "MAX_FILES", 24)
    monkeypatch.setattr(package_magisk_module, "MAX_FILE_BYTES", 1)

    errors = package_magisk_module.validate_payload_structure(copied)

    assert any("module file exceeds 1 bytes" in error for error in errors)

    monkeypatch.setattr(package_magisk_module, "MAX_FILE_BYTES", 2 * 1024 * 1024)
    monkeypatch.setattr(package_magisk_module, "MAX_TOTAL_BYTES", 1)

    errors = package_magisk_module.validate_payload_structure(copied)

    assert "module payload exceeds 1 bytes" in errors


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO requires POSIX")
def test_payload_structure_rejects_fifo(tmp_path):
    copied = module_copy(tmp_path)
    os.mkfifo(copied / "unexpected-pipe")

    errors = package_magisk_module.validate_payload_structure(copied)

    assert "module FIFO is not allowed: unexpected-pipe" in errors


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix sockets unavailable")
def test_payload_structure_rejects_socket():
    with tempfile.TemporaryDirectory(prefix="atl-", dir="/tmp") as short_temp:
        copied = Path(short_temp) / "module"
        shutil.copytree(ROOT / "module" / "trustlab-magisk", copied)
        socket_path = copied / "unexpected-socket"
        listener = socket.socket(socket.AF_UNIX)
        try:
            listener.bind(os.fspath(socket_path))
            errors = package_magisk_module.validate_payload_structure(copied)
        finally:
            listener.close()

    assert "module socket is not allowed: unexpected-socket" in errors


def test_special_file_mode_classification_covers_devices():
    assert package_magisk_module._entry_kind(stat.S_IFCHR) == "character device"
    assert package_magisk_module._entry_kind(stat.S_IFBLK) == "block device"


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        (
            "id=Android Trust Lab\n",
            "module.prop id must be one safe Magisk module identifier",
        ),
        (
            "versionCode=0\n",
            "module.prop versionCode must be one positive decimal integer",
        ),
        (
            "name=Android Trust Lab Collector\nname=duplicate\n",
            "module.prop contains duplicate key: name",
        ),
        (
            "author=Aleksander Vlasov\nunknown=value\n",
            "module.prop contains unknown key: unknown",
        ),
    ],
)
def test_module_prop_rejects_malformed_duplicate_and_unknown_fields(
    tmp_path, replacement, message
):
    copied = module_copy(tmp_path)
    metadata = copied / "module.prop"
    source = metadata.read_text(encoding="utf-8")
    key = replacement.split("=", 1)[0]
    original_line = next(
        line for line in source.splitlines() if line.startswith(f"{key}=")
    )
    metadata.write_text(
        source.replace(f"{original_line}\n", replacement), encoding="utf-8"
    )

    errors = package_magisk_module.validate_module_metadata(copied)

    assert message in errors


def test_module_prop_requires_every_field_and_canonical_order(tmp_path):
    copied = module_copy(tmp_path)
    metadata = copied / "module.prop"
    lines = metadata.read_text(encoding="utf-8").splitlines()
    metadata.write_text("\n".join([lines[1], *lines[2:-1]]) + "\n", encoding="utf-8")

    errors = package_magisk_module.validate_module_metadata(copied)

    assert "module.prop is missing required key: id" in errors
    assert "module.prop is missing required key: description" in errors


def test_shell_contract_rejects_wrong_shebang_syntax_and_nonempty_skip_mount(
    tmp_path,
):
    copied = module_copy(tmp_path)
    action = copied / "action.sh"
    action.write_text(
        action.read_text(encoding="utf-8").replace(
            "#!/system/bin/sh", "#!/bin/bash", 1
        ),
        encoding="utf-8",
    )
    service = copied / "service.sh"
    service.write_text(
        service.read_text(encoding="utf-8") + "\nif then\n", encoding="utf-8"
    )
    (copied / "skip_mount").write_text("not-empty\n", encoding="utf-8")

    errors = package_magisk_module.validate_shell_contract(copied)

    assert "module script has invalid shebang: action.sh" in errors
    assert "module shell syntax is invalid: service.sh" in errors
    assert "skip_mount must be one empty regular file" in errors


def test_archive_validator_rejects_hostile_paths_duplicates_and_types(tmp_path):
    archive_path = tmp_path / "hostile.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escape", b"escape")
        archive.writestr("scripts\\same.sh", b"one")
        link = zipfile.ZipInfo("scripts/same.sh")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, b"target")

    errors = package_magisk_module.validate_archive_structure(archive_path)

    assert any("must be normalized" in error for error in errors)
    assert any("forward separators" in error for error in errors)
    assert any("duplicate normalized archive path" in error for error in errors)
    assert any("archive member must be regular" in error for error in errors)


def test_archive_output_must_be_outside_module_tree(tmp_path):
    copied = module_copy(tmp_path)
    output = copied / "self-ingesting.zip"

    with pytest.raises(ValueError, match="outside the module source tree"):
        package_magisk_module.write_zip(output, copied)

    assert not output.exists()


def test_archive_output_symlink_is_rejected_without_touching_target(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"preserve-target")
    output = tmp_path / "archive.zip"
    output.symlink_to(target)

    with pytest.raises(ValueError, match="absent or one regular file"):
        package_magisk_module.build_reproducible_archive(
            output,
            ROOT / "module" / "trustlab-magisk",
        )

    assert output.is_symlink()
    assert target.read_bytes() == b"preserve-target"


def test_cli_rejects_symlinked_module_root(tmp_path):
    module_link = tmp_path / "module-link"
    module_link.symlink_to(
        ROOT / "module" / "trustlab-magisk", target_is_directory=True
    )

    with pytest.raises(SystemExit, match="module root must be one real directory"):
        package_magisk_module.main(
            ["--check-only", "--module-dir", os.fspath(module_link)]
        )


def test_cli_rejects_output_symlink_without_touching_target(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"preserve-cli-target")
    output = tmp_path / "archive.zip"
    output.symlink_to(target)

    with pytest.raises(SystemExit, match="absent or one regular file"):
        package_magisk_module.main(["--output", os.fspath(output)])

    assert output.is_symlink()
    assert target.read_bytes() == b"preserve-cli-target"


def test_reproducibility_mismatch_preserves_existing_output(tmp_path, monkeypatch):
    output = tmp_path / "archive.zip"
    output.write_bytes(b"preserve-existing-output")
    calls = 0

    def write_different_archives(path, _module_dir, *, timestamp):
        nonlocal calls
        calls += 1
        path.write_bytes(f"build-{calls}-{timestamp!r}".encode())

    monkeypatch.setattr(package_magisk_module, "write_zip", write_different_archives)

    with pytest.raises(ValueError, match="not byte-identical"):
        package_magisk_module.build_reproducible_archive(
            output,
            ROOT / "module" / "trustlab-magisk",
        )

    assert output.read_bytes() == b"preserve-existing-output"
    assert list(tmp_path.glob(".archive.zip.*.tmp")) == []
