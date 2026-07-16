#!/usr/bin/env python3
"""Validate and package the Android Trust Lab Magisk collector module.

The module is intentionally a read-only collector. This packaging helper refuses
common Magisk payload locations that would turn the archive into a system
modification package instead of a measurement artifact.
"""

from __future__ import annotations

import re
import sys
import zipfile
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

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

COLLECTED_PROPERTY_ALLOWLIST = {
    "ro.boot.flash.locked",
    "ro.boot.vbmeta.device_state",
    "ro.boot.verifiedbootstate",
    "ro.boot.veritymode",
    "ro.build.fingerprint",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.crypto.state",
    "ro.crypto.type",
    "ro.crypto.volume.filenames_mode",
    "ro.product.device",
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.debuggable",
    "ro.secure",
    "ro.adb.secure",
    "sys.boot_completed",
}

ALLOWED_GETPROP_LINES = {
    'VALUE=$(getprop "$KEY" 2>/dev/null)',
    "sys.boot_completed=$(getprop sys.boot_completed 2>/dev/null)",
    "ro.boot.bootreason=$(getprop ro.boot.bootreason 2>/dev/null)",
    "ro.boot.slot_suffix=$(getprop ro.boot.slot_suffix 2>/dev/null)",
    "ro.boot.verifiedbootstate=$(getprop ro.boot.verifiedbootstate 2>/dev/null)",
    "ro.boot.flash.locked=$(getprop ro.boot.flash.locked 2>/dev/null)",
    "ro.boot.vbmeta.device_state=$(getprop ro.boot.vbmeta.device_state 2>/dev/null)",
    "ro.boot.veritymode=$(getprop ro.boot.veritymode 2>/dev/null)",
    'while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ] && [ "$count" -lt 120 ]; do',
}

ALLOWED_PROCESS_QUERY_LINES = {
    "CONTEXT_OUTPUT=$(ps -AZ 2>/dev/null)",
    "BASIC_OUTPUT=$(ps 2>/dev/null)",
}

COLLECTOR_VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$"
)


def iter_module_files(module_dir: Path = MODULE_DIR) -> Iterable[Path]:
    for path in sorted(module_dir.rglob("*")):
        if path.is_symlink():
            raise ValueError(
                f"module symlink is not allowed: {relative_posix(path, module_dir)}"
            )
        if path.is_file():
            yield path


def relative_posix(path: Path, module_dir: Path = MODULE_DIR) -> str:
    return path.relative_to(module_dir).as_posix()


def validate_required_files(module_dir: Path = MODULE_DIR) -> list[str]:
    errors: list[str] = []
    for rel in REQUIRED_FILES:
        path = module_dir / rel
        if not path.is_file():
            errors.append(f"missing required module file: {rel}")
    return errors


def validate_module_metadata(module_dir: Path = MODULE_DIR) -> list[str]:
    """Require the runtime-interpolated module version to be schema-safe."""

    path = module_dir / "module.prop"
    if not path.is_file() or path.is_symlink():
        return []
    versions = [
        line.removeprefix("version=")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("version=")
    ]
    if len(versions) != 1 or COLLECTOR_VERSION_RE.fullmatch(versions[0]) is None:
        return ["module.prop version must be one schema-safe collector version"]
    return []


def validate_no_mutating_payloads(module_dir: Path = MODULE_DIR) -> list[str]:
    errors: list[str] = []
    for path in sorted(module_dir.rglob("*")):
        rel = relative_posix(path, module_dir)
        if path.is_symlink():
            errors.append(f"module symlink is not allowed: {rel}")
            continue
        if rel in FORBIDDEN_EXACT or any(
            rel.startswith(prefix) for prefix in FORBIDDEN_DIR_PREFIXES
        ):
            errors.append(f"forbidden module payload path: {rel}")
        if path.is_file() and path.suffix == ".zip":
            errors.append(f"embedded zip is not allowed inside module: {rel}")
    return errors


def active_shell_lines(text: str) -> set[str]:
    return {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def validate_private_collection(module_dir: Path = MODULE_DIR) -> list[str]:
    errors: list[str] = []
    write_path = module_dir / "scripts/write_report.sh"
    boot_path = module_dir / "scripts/collect_boot_state.sh"
    props_path = module_dir / "scripts/collect_props.sh"
    if not all(
        path.is_file() and not path.is_symlink()
        for path in (write_path, boot_path, props_path)
    ):
        return errors
    write_report = write_path.read_text(encoding="utf-8")
    collect_props = props_path.read_text(encoding="utf-8")

    active_write_lines = active_shell_lines(write_report)
    required_write_guards: tuple[tuple[Callable[[], bool], str], ...] = (
        (lambda: "umask 077" in active_write_lines, "collector must set umask 077"),
        (
            lambda: 'BASE_DIR="/data/adb/android-trust-lab"' in active_write_lines,
            "collector output must be under /data/adb",
        ),
        (
            lambda: any(
                line.startswith("RUN_DIR=$(mktemp -d ") for line in active_write_lines
            ),
            "collector must create an exclusive randomized run directory",
        ),
        (
            lambda: 'case "$RUN_DIR" in' in active_write_lines,
            "collector must constrain the randomized run path",
        ),
        (
            lambda: any(
                'chmod 0700 "$BASE_DIR" "$OUT_DIR"' in line
                for line in active_write_lines
            ),
            "collector directories must be mode 0700",
        ),
        (
            lambda: any('chmod 0600 "$RAW"' in line for line in active_write_lines),
            "raw collector output must be mode 0600",
        ),
        (
            lambda: any('chmod 0600 "$TMP"' in line for line in active_write_lines),
            "manifest output must be mode 0600",
        ),
        (
            lambda: any('[ -L "$BASE_DIR" ]' in line for line in active_write_lines),
            "collector must reject symlinked output directories",
        ),
        (
            lambda: "RUN_ID=${RUN_DIR##*/}" in active_write_lines,
            "collector manifest IDs must include the exclusive run identifier",
        ),
        (
            lambda: any(
                '"schema_version": "1.0.0"' in line for line in active_write_lines
            ),
            "collector must emit collection-manifest schema 1.0.0",
        ),
        (
            lambda: any(
                '"relative_path": "raw.txt"' in line for line in active_write_lines
            ),
            "collector manifest artifact paths must be portable and relative",
        ),
        (
            lambda: any('sha256sum "$RAW"' in line for line in active_write_lines),
            "collector manifest must bind the raw artifact digest",
        ),
        (
            lambda: (
                'TARGET_TOKEN_FILE="$BASE_DIR/target_pseudonym"' in active_write_lines
            ),
            "collector must persist a random privacy-preserving target pseudonym",
        ),
        (
            lambda: any(
                "COLLECTOR_VERSION" in line and "grep -Eq" in line
                for line in active_write_lines
            ),
            "collector must validate dynamic manifest versions before JSON emission",
        ),
    )
    for predicate, message in required_write_guards:
        if not predicate():
            errors.append(message)

    script_texts = {
        path.relative_to(module_dir).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(module_dir.rglob("*.sh"))
        if path.is_file() and not path.is_symlink()
    }
    active_script_lines = {
        line for text in script_texts.values() for line in active_shell_lines(text)
    }
    if any(
        "/proc/cmdline" in line or "kernel_cmdline=" in line
        for line in active_script_lines
    ):
        errors.append("collector must not capture the kernel command line")
    if "/data/local/tmp/android-trust-lab" in write_report:
        errors.append("collector must not publish reports under /data/local/tmp")
    if "chmod 0755" in write_report or "chmod 0644" in write_report:
        errors.append("collector must not make report paths group/world readable")

    declared_properties = {
        line.strip().rstrip("\\").strip()
        for line in collect_props.splitlines()
        if line.strip().startswith(("ro.", "sys."))
    }
    if declared_properties != COLLECTED_PROPERTY_ALLOWLIST:
        errors.append(
            "collector property keys must exactly match the privacy allowlist"
        )
    getprop_lines = {line for line in active_script_lines if "getprop" in line}
    if not getprop_lines.issubset(ALLOWED_GETPROP_LINES):
        errors.append("collector must query only individual allowlisted properties")
    process_query_lines = {
        line
        for line in active_script_lines
        if re.search(r"(^|[;&|($`/\s])ps(?:\s|$)", line)
    }
    if not process_query_lines.issubset(ALLOWED_PROCESS_QUERY_LINES):
        errors.append("collector must not publish raw process command lines")

    return errors


def validate_module(module_dir: Path = MODULE_DIR) -> None:
    errors = []
    if not module_dir.is_dir():
        errors.append(f"module directory does not exist: {module_dir}")
    else:
        errors.extend(validate_required_files(module_dir))
        errors.extend(validate_module_metadata(module_dir))
        errors.extend(validate_no_mutating_payloads(module_dir))
        errors.extend(validate_private_collection(module_dir))
    if errors:
        raise SystemExit("\n".join(errors))


def zip_permissions(path: Path) -> int:
    mode = path.stat().st_mode & 0o777
    return (mode | 0o100000) << 16


def write_zip(output: Path, module_dir: Path = MODULE_DIR) -> None:
    files = list(iter_module_files(module_dir))
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
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
            print(
                "usage: package_magisk_module.py [--check-only] [--module-dir PATH] [--output PATH]"
            )
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
