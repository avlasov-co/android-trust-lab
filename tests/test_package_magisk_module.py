from pathlib import Path
import importlib.util
import shutil

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
