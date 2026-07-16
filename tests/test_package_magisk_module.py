import importlib.util
import os
import shutil
import subprocess
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


def test_module_safety_validation_passes_for_checked_in_module():
    package_magisk_module.validate_module(ROOT / "module" / "trustlab-magisk")


def test_module_safety_validation_rejects_overlay_payload(tmp_path):
    module_copy = tmp_path / "trustlab-magisk"
    shutil.copytree(ROOT / "module" / "trustlab-magisk", module_copy)
    forbidden = module_copy / "system" / "etc" / "hosts"
    forbidden.parent.mkdir(parents=True)
    forbidden.write_text("127.0.0.1 example.invalid\n", encoding="utf-8")

    errors = package_magisk_module.validate_no_mutating_payloads(module_copy)
    assert any("system/etc/hosts" in error for error in errors)


def module_copy(tmp_path):
    target = tmp_path / "trustlab-magisk"
    shutil.copytree(ROOT / "module" / "trustlab-magisk", target)
    return target


def test_module_safety_requires_private_output_permissions(tmp_path):
    copied = module_copy(tmp_path)
    script = copied / "scripts/write_report.sh"
    script.write_text(
        script.read_text(encoding="utf-8").replace("umask 077", "umask 022"),
        encoding="utf-8",
    )
    errors = package_magisk_module.validate_private_collection(copied)
    assert any("umask 077" in error for error in errors)


def test_module_safety_ignores_commented_guard_text(tmp_path):
    copied = module_copy(tmp_path)
    script = copied / "scripts/write_report.sh"
    script.write_text(
        script.read_text(encoding="utf-8").replace("umask 077", ": # umask 077"),
        encoding="utf-8",
    )
    errors = package_magisk_module.validate_private_collection(copied)
    assert any("umask 077" in error for error in errors)


def test_module_safety_rejects_shell_writable_output_path(tmp_path):
    copied = module_copy(tmp_path)
    script = copied / "scripts/write_report.sh"
    script.write_text(
        script.read_text(encoding="utf-8").replace(
            "/data/adb/android-trust-lab", "/data/local/tmp/android-trust-lab"
        ),
        encoding="utf-8",
    )
    errors = package_magisk_module.validate_private_collection(copied)
    assert any("under /data/adb" in error for error in errors)
    assert any("/data/local/tmp" in error for error in errors)


def test_module_safety_rejects_broad_property_collection(tmp_path):
    copied = module_copy(tmp_path)
    script = copied / "scripts/collect_props.sh"
    script.write_text(
        script.read_text(encoding="utf-8") + "\ngetprop 2>/dev/null\n",
        encoding="utf-8",
    )
    errors = package_magisk_module.validate_private_collection(copied)
    assert any("only individual allowlisted properties" in error for error in errors)


def test_module_safety_requires_portable_integrity_bound_manifest(tmp_path):
    copied = module_copy(tmp_path)
    script = copied / "scripts/write_report.sh"
    content = script.read_text(encoding="utf-8")
    content = content.replace('"schema_version": "1.0.0"', '"schema_version": "0.1"')
    content = content.replace('"relative_path": "raw.txt"', '"relative_path": "$RAW"')
    content = content.replace('sha256sum "$RAW"', "printf missing-digest")
    script.write_text(content, encoding="utf-8")

    errors = package_magisk_module.validate_private_collection(copied)
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


def test_module_safety_rejects_kernel_command_line_capture(tmp_path):
    copied = module_copy(tmp_path)
    script = copied / "scripts/collect_boot_state.sh"
    script.write_text(
        script.read_text(encoding="utf-8") + "\ncat /proc/cmdline\n",
        encoding="utf-8",
    )
    errors = package_magisk_module.validate_private_collection(copied)
    assert any("kernel command line" in error for error in errors)


def test_module_safety_scans_every_collector_for_sensitive_sources(tmp_path):
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

    errors = package_magisk_module.validate_private_collection(copied)
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
        check=True,
    )
    processes = subprocess.run(
        ["sh", ROOT / "module/trustlab-magisk/scripts/collect_process_state.sh"],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
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


def test_module_safety_rejects_symlinks_without_reading_target(tmp_path):
    copied = module_copy(tmp_path)
    external = tmp_path / "sensitive.txt"
    external.write_text("host-sensitive-sentinel\n", encoding="utf-8")
    (copied / "leak.txt").symlink_to(external)

    errors = package_magisk_module.validate_no_mutating_payloads(copied)
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

    import zipfile

    with zipfile.ZipFile(out) as archive:
        names = set(archive.namelist())
    assert "module.prop" in names
    assert "scripts/write_report.sh" in names
    assert not any(name.startswith("META-INF/") for name in names)
