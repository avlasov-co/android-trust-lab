from pathlib import Path
import importlib.util
import os
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("package_magisk_module", ROOT / "tools" / "package_magisk_module.py")
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
        "if [ \"$1\" = \"-AZ\" ]; then\n"
        "  printf '%s\\n' 'u:r:init:s0 root 1 0 init PRIVATE_COMMAND_TOKEN'\n"
        "else\n"
        "  printf '%s\\n' 'root 1 0 init PRIVATE_COMMAND_TOKEN'\n"
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
