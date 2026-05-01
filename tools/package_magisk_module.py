#!/usr/bin/env python3
"""Validate and package the Android Trust Lab Magisk collector module.

The module is intentionally a read-only collector. This packaging helper refuses
common Magisk payload locations that would turn the archive into a system
modification package instead of a measurement artifact.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path
from typing import Iterable, List, Sequence

ROOT = Path(__file__).resolve().parents[1]
MODULE_DIR = ROOT / "module" / "trustlab-magisk"
DEFAULT_OUTPUT = ROOT / "dist" / "androidtrustlab-magisk.zip"

REQUIRED_FILES = [
    "module.prop",
    "skip_mount",
    "action.sh",
    "post-fs-data.sh",
    "service.sh",
    "uninstall.sh",
    "scripts/collect_boot_state.sh",
    "scripts/collect_props.sh",
    "scripts/collect_mounts.sh",
    "scripts/collect_selinux.sh",
    "scripts/collect_magisk_state.sh",
    "scripts/collect_process_state.sh",
    "scripts/write_report.sh",
]

FORBIDDEN_EXACT = {
    "META-INF",
    "system.prop",
    "scripts/lib.sh",
}

FORBIDDEN_DIR_PREFIXES = (
    "system/",
    "vendor/",
    "product/",
    "system_ext/",
    "odm/",
)


def iter_module_files(module_dir: Path = MODULE_DIR) -> Iterable[Path]:
    for path in sorted(module_dir.rglob("*")):
        if path.is_file():
            yield path


def relative_posix(path: Path, module_dir: Path = MODULE_DIR) -> str:
    return path.relative_to(module_dir).as_posix()


def validate_required_files(module_dir: Path = MODULE_DIR) -> List[str]:
    errors: List[str] = []
    for rel in REQUIRED_FILES:
        path = module_dir / rel
        if not path.is_file():
            errors.append(f"missing required module file: {rel}")
    return errors


def validate_no_mutating_payloads(module_dir: Path = MODULE_DIR) -> List[str]:
    errors: List[str] = []
    for path in sorted(module_dir.rglob("*")):
        rel = relative_posix(path, module_dir)
        if rel in FORBIDDEN_EXACT or any(rel.startswith(prefix) for prefix in FORBIDDEN_DIR_PREFIXES):
            errors.append(f"forbidden module payload path: {rel}")
        if path.is_file() and path.suffix == ".zip":
            errors.append(f"embedded zip is not allowed inside module: {rel}")
    return errors



def validate_module(module_dir: Path = MODULE_DIR) -> None:
    errors = []
    if not module_dir.is_dir():
        errors.append(f"module directory does not exist: {module_dir}")
    else:
        errors.extend(validate_required_files(module_dir))
        errors.extend(validate_no_mutating_payloads(module_dir))
    if errors:
        raise SystemExit("\n".join(errors))


def zip_permissions(path: Path) -> int:
    mode = path.stat().st_mode & 0o777
    return (mode | 0o100000) << 16


def write_zip(output: Path, module_dir: Path = MODULE_DIR) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in iter_module_files(module_dir):
            rel = relative_posix(path, module_dir)
            info = zipfile.ZipInfo(rel)
            # Fixed timestamp keeps archives reproducible enough for review diffs.
            info.date_time = (2026, 4, 25, 0, 0, 0)
            info.external_attr = zip_permissions(path)
            archive.writestr(info, path.read_bytes())


def parse_args(argv: Sequence[str] | None = None) -> tuple[Path, Path, bool]:
    """Parse a tiny CLI without argparse to keep the helper dependency-light."""
    args = list(sys.argv[1:] if argv is None else argv)
    module_dir = MODULE_DIR
    output = DEFAULT_OUTPUT
    check_only = False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--check-only":
            check_only = True
            index += 1
        elif arg == "--module-dir":
            if index + 1 >= len(args):
                raise SystemExit("--module-dir requires a path")
            module_dir = Path(args[index + 1])
            index += 2
        elif arg == "--output":
            if index + 1 >= len(args):
                raise SystemExit("--output requires a path")
            output = Path(args[index + 1])
            index += 2
        elif arg in {"-h", "--help"}:
            print("usage: package_magisk_module.py [--check-only] [--module-dir PATH] [--output PATH]")
            raise SystemExit(0)
        else:
            raise SystemExit(f"unknown argument: {arg}")
    return module_dir.resolve(), output.resolve(), check_only


def main(argv: Sequence[str] | None = None) -> int:
    module_dir, output, check_only = parse_args(argv)
    validate_module(module_dir)
    if not check_only:
        write_zip(output, module_dir)
        print(output)
    else:
        print("Magisk module safety checks passed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
