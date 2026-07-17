#!/usr/bin/env python3
"""Build a deterministic Magisk module under strict structural guardrails.

These checks prove archive structure, bounded payload membership, normalized ZIP
metadata, host-shell parseability, and selected textual policy markers. They do
not prove shell-script semantics or runtime safety.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
MODULE_DIR = ROOT / "module" / "trustlab-magisk"
DEFAULT_OUTPUT = ROOT / "dist" / "androidtrustlab-magisk.zip"

REQUIRED_FILES = (
    "META-INF/com/google/android/update-binary",
    "META-INF/com/google/android/updater-script",
    "README.md",
    "action.sh",
    "customize.sh",
    "module.prop",
    "post-fs-data.sh",
    "scripts/collect_boot_state.sh",
    "scripts/collect_magisk_state.sh",
    "scripts/collect_mounts.sh",
    "scripts/collect_process_state.sh",
    "scripts/collect_props.sh",
    "scripts/collect_root_state.sh",
    "scripts/collect_selinux.sh",
    "scripts/run_collection.sh",
    "scripts/webui_api.sh",
    "scripts/write_report.sh",
    "service.sh",
    "skip_mount",
    "uninstall.sh",
    "webroot/THIRD_PARTY_NOTICES.md",
    "webroot/app.js",
    "webroot/bridge.js",
    "webroot/index.html",
    "webroot/state.js",
    "webroot/styles.css",
    "webroot/vendor/kernelsu.js",
)
ALLOWED_FILES = frozenset(REQUIRED_FILES)
ARCHIVE_DIRECTORY_ENTRIES = frozenset(
    {
        "META-INF/",
        "META-INF/com/",
        "META-INF/com/google/",
        "META-INF/com/google/android/",
        "scripts/",
        "webroot/",
        "webroot/vendor/",
    }
)
ALLOWED_DIRECTORIES = frozenset(
    {
        "META-INF",
        "META-INF/com",
        "META-INF/com/google",
        "META-INF/com/google/android",
        "scripts",
        "webroot",
        "webroot/vendor",
    }
)
SCRIPT_FILES = frozenset(path for path in REQUIRED_FILES if path.endswith(".sh"))

MODULE_PROP_FIELDS = (
    "id",
    "name",
    "version",
    "versionCode",
    "author",
    "description",
)
COLLECTOR_VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\.installfix\.[1-9][0-9]*)?$"
)
MODULE_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")
VERSION_CODE_RE = re.compile(r"^[1-9][0-9]{0,9}$")
WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")

SCRIPT_MODE = 0o755
NORMAL_MODE = 0o644
DEFAULT_SOURCE_DATE_EPOCH = 315532800
DEFAULT_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
MIN_ZIP_YEAR = 1980
MAX_ZIP_YEAR = 2107
MAX_ENTRIES = 48
MAX_FILES = 48
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_PATH_BYTES = 240
SHELL_CHECK_TIMEOUT_SECONDS = 10
READ_CHUNK_BYTES = 64 * 1024
KERNELSU_BRIDGE_SHA256 = "868805848c3a208c79fbf0f7581255a33c33b812dfaae8b457125fbbb2c400ca"  # pragma: allowlist secret

ARCHIVE_SUFFIXES = frozenset(
    {
        ".7z",
        ".aar",
        ".apk",
        ".bz2",
        ".gz",
        ".jar",
        ".rar",
        ".tar",
        ".tgz",
        ".xz",
        ".zip",
    }
)

COLLECTED_PROPERTY_ALLOWLIST = {
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
}

ALLOWED_GETPROP_LINES = {
    'VALUE=$(getprop "$KEY" 2>/dev/null)',
    "VALUE=$(getprop sys.boot_completed 2>/dev/null)",
    "CURRENT_BOOT=$(getprop sys.boot_completed 2>&1)",
    "BOOT_QUERY_OUTPUT=$(getprop sys.boot_completed 2>&1)",
}

ALLOWED_PROCESS_QUERY_LINES = {
    "CONTEXT_OUTPUT=$(ps -AZ 2>&1)",
    "BASIC_OUTPUT=$(ps 2>&1)",
}


class ModuleFile(NamedTuple):
    path: Path
    archive_name: str
    size: int
    device: int
    inode: int
    modified_ns: int
    changed_ns: int


class ModuleEntry(NamedTuple):
    path: Path
    raw_name: str
    file_stat: os.stat_result


class EntryBudget:
    def __init__(self) -> None:
        self.count = 0
        self.exhausted = False


def relative_posix(path: Path, module_dir: Path = MODULE_DIR) -> str:
    return path.relative_to(module_dir).as_posix()


def normalize_archive_path(raw_name: str) -> tuple[str, list[str]]:
    """Return separator-normalized form plus strict portability errors."""

    errors: list[str] = []
    normalized = raw_name.replace("\\", "/")
    if normalized != raw_name:
        errors.append(f"archive path must use forward separators: {raw_name}")
    if (
        normalized.startswith("/")
        or normalized.startswith("//")
        or WINDOWS_DRIVE_RE.match(normalized)
    ):
        errors.append(f"archive path must be relative: {raw_name}")
    parts = normalized.split("/")
    if not normalized or any(part in {"", ".", ".."} for part in parts):
        errors.append(f"archive path must be normalized: {raw_name}")
    if len(normalized.encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES:
        errors.append(
            f"archive path exceeds {MAX_ARCHIVE_PATH_BYTES} bytes: {raw_name}"
        )
    return "/".join(parts), errors


def validate_archive_paths(raw_names: Iterable[str]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for raw_name in raw_names:
        normalized, path_errors = normalize_archive_path(raw_name)
        errors.extend(path_errors)
        if normalized in seen:
            errors.append(f"duplicate normalized archive path: {normalized}")
        seen.add(normalized)
    return errors


def _entry_kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "FIFO"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character device"
    if stat.S_ISBLK(mode):
        return "block device"
    return "special file"


def _walk_module_tree(
    directory: Path,
    prefix: str,
    errors: list[str],
    budget: EntryBudget,
) -> list[ModuleEntry]:
    scanned: list[ModuleEntry] = []
    try:
        with os.scandir(directory) as iterator:
            entries: list[os.DirEntry[str]] = []
            for entry in iterator:
                budget.count += 1
                if budget.count > MAX_ENTRIES:
                    budget.exhausted = True
                    errors.append(f"module entry count exceeds {MAX_ENTRIES}")
                    break
                entries.append(entry)
            entries.sort(key=lambda entry: entry.name)
    except OSError:
        errors.append(f"module directory could not be enumerated: {prefix or '.'}")
        return scanned
    for entry in entries:
        raw_name = f"{prefix}/{entry.name}" if prefix else entry.name
        try:
            entry_stat = entry.stat(follow_symlinks=False)
        except OSError:
            errors.append(f"module entry could not be inspected: {raw_name}")
            continue
        scanned.append(
            ModuleEntry(
                path=Path(entry.path),
                raw_name=raw_name,
                file_stat=entry_stat,
            )
        )
        if stat.S_ISDIR(entry_stat.st_mode) and not budget.exhausted:
            scanned.extend(
                _walk_module_tree(Path(entry.path), raw_name, errors, budget)
            )
    return scanned


def inspect_module_tree(
    module_dir: Path = MODULE_DIR,
) -> tuple[list[ModuleFile], list[str]]:
    files: list[ModuleFile] = []
    errors: list[str] = []
    total_size = 0
    try:
        root_stat = module_dir.lstat()
    except OSError:
        return [], [f"module directory does not exist: {module_dir}"]
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        return [], [f"module root must be one real directory: {module_dir}"]

    budget = EntryBudget()
    entries = _walk_module_tree(module_dir, "", errors, budget)
    for entry in entries:
        normalized, path_errors = normalize_archive_path(entry.raw_name)
        errors.extend(path_errors)
        mode = entry.file_stat.st_mode
        if stat.S_ISDIR(mode):
            if normalized not in ALLOWED_DIRECTORIES:
                errors.append(f"unexpected module directory: {normalized}")
            continue
        if not stat.S_ISREG(mode):
            errors.append(f"module {_entry_kind(mode)} is not allowed: {normalized}")
            continue
        if normalized not in ALLOWED_FILES:
            errors.append(f"unexpected module payload: {normalized}")
        if Path(normalized).suffix.lower() in ARCHIVE_SUFFIXES:
            errors.append(f"embedded archive is not allowed: {normalized}")
        if entry.file_stat.st_size > MAX_FILE_BYTES:
            errors.append(f"module file exceeds {MAX_FILE_BYTES} bytes: {normalized}")
        total_size += entry.file_stat.st_size
        files.append(
            ModuleFile(
                path=entry.path,
                archive_name=normalized,
                size=entry.file_stat.st_size,
                device=entry.file_stat.st_dev,
                inode=entry.file_stat.st_ino,
                modified_ns=entry.file_stat.st_mtime_ns,
                changed_ns=entry.file_stat.st_ctime_ns,
            )
        )

    errors.extend(validate_archive_paths(entry.raw_name for entry in entries))
    if len(files) > MAX_FILES:
        errors.append(f"module file count exceeds {MAX_FILES}")
    if total_size > MAX_TOTAL_BYTES:
        errors.append(f"module payload exceeds {MAX_TOTAL_BYTES} bytes")
    files.sort(key=lambda item: item.archive_name)
    return files, errors


def _read_module_file(source: ModuleFile) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source.path, flags)
    except OSError as error:
        raise ValueError(
            f"module file could not be opened safely: {source.archive_name}"
        ) from error
    chunks: list[bytes] = []
    total = 0
    try:
        opened_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_stat.st_mode)
            or opened_stat.st_dev != source.device
            or opened_stat.st_ino != source.inode
            or opened_stat.st_size != source.size
            or opened_stat.st_mtime_ns != source.modified_ns
            or opened_stat.st_ctime_ns != source.changed_ns
        ):
            raise ValueError(f"module file changed during build: {source.archive_name}")
        while True:
            chunk = os.read(descriptor, READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise ValueError(
                    f"module file exceeds {MAX_FILE_BYTES} bytes: {source.archive_name}"
                )
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    if total != source.size:
        raise ValueError(f"module file changed during build: {source.archive_name}")
    try:
        final_stat = source.path.lstat()
    except OSError as error:
        raise ValueError(
            f"module file changed during build: {source.archive_name}"
        ) from error
    if (
        not stat.S_ISREG(final_stat.st_mode)
        or final_stat.st_dev != source.device
        or final_stat.st_ino != source.inode
        or final_stat.st_size != source.size
        or final_stat.st_mtime_ns != source.modified_ns
        or final_stat.st_ctime_ns != source.changed_ns
    ):
        raise ValueError(f"module file changed during build: {source.archive_name}")
    return b"".join(chunks)


def _has_archive_signature(payload: bytes) -> bool:
    prefixes = (
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
        b"\x1f\x8b",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"BZh",
        b"\xfd7zXZ\x00",
    )
    return (
        payload.startswith(prefixes)
        or (len(payload) >= 262 and payload[257:262] == b"ustar")
        or zipfile.is_zipfile(io.BytesIO(payload))
    )


def validate_payload_structure(module_dir: Path = MODULE_DIR) -> list[str]:
    files, errors = inspect_module_tree(module_dir)
    if errors:
        return errors
    for source in files:
        if source.size > MAX_FILE_BYTES:
            continue
        try:
            payload = _read_module_file(source)
        except ValueError as error:
            errors.append(str(error))
            continue
        if _has_archive_signature(payload):
            errors.append(
                f"embedded archive signature is not allowed: {source.archive_name}"
            )
    return errors


def validate_required_files(module_dir: Path = MODULE_DIR) -> list[str]:
    errors: list[str] = []
    for relative in REQUIRED_FILES:
        path = module_dir / relative
        try:
            path_stat = path.lstat()
        except OSError:
            errors.append(f"missing required module file: {relative}")
            continue
        if not stat.S_ISREG(path_stat.st_mode):
            errors.append(f"required module file is not regular: {relative}")
    return errors


def _read_utf8_regular(path: Path, relative: str) -> tuple[str | None, list[str]]:
    try:
        path_stat = path.lstat()
        if not stat.S_ISREG(path_stat.st_mode):
            return None, [f"module text file is not regular: {relative}"]
        if path_stat.st_size > MAX_FILE_BYTES:
            return None, [f"module file exceeds {MAX_FILE_BYTES} bytes: {relative}"]
        payload = _read_module_file(
            ModuleFile(
                path=path,
                archive_name=relative,
                size=path_stat.st_size,
                device=path_stat.st_dev,
                inode=path_stat.st_ino,
                modified_ns=path_stat.st_mtime_ns,
                changed_ns=path_stat.st_ctime_ns,
            )
        )
        return payload.decode("utf-8"), []
    except (OSError, UnicodeDecodeError, ValueError):
        return None, [f"module text file must be readable UTF-8: {relative}"]


def validate_module_metadata(module_dir: Path = MODULE_DIR) -> list[str]:
    path = module_dir / "module.prop"
    text, errors = _read_utf8_regular(path, "module.prop")
    if text is None:
        return errors
    if "\r" in text or not text.endswith("\n"):
        errors.append("module.prop must use LF lines and end with one newline")
    values: dict[str, str] = {}
    observed_order: list[str] = []
    for line in text.splitlines():
        if not line or "=" not in line:
            errors.append("module.prop must contain only nonempty key=value lines")
            continue
        key, value = line.split("=", 1)
        if key in values:
            errors.append(f"module.prop contains duplicate key: {key}")
            continue
        if key not in MODULE_PROP_FIELDS:
            errors.append(f"module.prop contains unknown key: {key}")
        if not value or any(not 0x20 <= ord(character) <= 0x7E for character in value):
            errors.append(f"module.prop value must be printable and nonempty: {key}")
        values[key] = value
        observed_order.append(key)
    missing = [field for field in MODULE_PROP_FIELDS if field not in values]
    for field in missing:
        errors.append(f"module.prop is missing required key: {field}")
    if not missing and tuple(observed_order) != MODULE_PROP_FIELDS:
        errors.append("module.prop keys must use the canonical order")
    module_id = values.get("id")
    if module_id is not None and MODULE_ID_RE.fullmatch(module_id) is None:
        errors.append("module.prop id must be one safe Magisk module identifier")
    version = values.get("version")
    if version is not None and COLLECTOR_VERSION_RE.fullmatch(version) is None:
        errors.append("module.prop version must be one schema-safe collector version")
    version_code = values.get("versionCode")
    if version_code is not None and VERSION_CODE_RE.fullmatch(version_code) is None:
        errors.append("module.prop versionCode must be one positive decimal integer")
    for field, maximum in (("name", 128), ("author", 128), ("description", 256)):
        text_value = values.get(field)
        if text_value is not None and len(text_value) > maximum:
            errors.append(f"module.prop {field} exceeds {maximum} characters")
    return errors


def validate_shell_contract(module_dir: Path = MODULE_DIR) -> list[str]:
    errors: list[str] = []
    shell = shutil.which("sh")
    if shell is None:
        return ["POSIX sh is required for package-time syntax validation"]
    for relative in sorted(SCRIPT_FILES):
        path = module_dir / relative
        text, text_errors = _read_utf8_regular(path, relative)
        errors.extend(text_errors)
        if text is None:
            continue
        if not text.startswith("#!/system/bin/sh\n"):
            errors.append(f"module script has invalid shebang: {relative}")
        try:
            result = subprocess.run(
                [shell, "-n", os.fspath(path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=SHELL_CHECK_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            errors.append(f"module shell syntax check could not complete: {relative}")
            continue
        if result.returncode != 0:
            errors.append(f"module shell syntax is invalid: {relative}")
    skip_mount = module_dir / "skip_mount"
    try:
        skip_stat = skip_mount.lstat()
        if not stat.S_ISREG(skip_stat.st_mode) or skip_stat.st_size != 0:
            errors.append("skip_mount must be one empty regular file")
    except OSError:
        pass
    return errors


def active_shell_lines(text: str) -> set[str]:
    return {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def validate_collector_guardrails(module_dir: Path = MODULE_DIR) -> list[str]:
    """Check selected static boundary markers without claiming semantic proof."""

    errors: list[str] = []
    write_path = module_dir / "scripts/write_report.sh"
    boot_path = module_dir / "scripts/collect_boot_state.sh"
    props_path = module_dir / "scripts/collect_props.sh"
    if not all(
        path.is_file() and not path.is_symlink()
        for path in (write_path, boot_path, props_path)
    ):
        return errors
    write_report, write_errors = _read_utf8_regular(
        write_path, "scripts/write_report.sh"
    )
    collect_props, props_errors = _read_utf8_regular(
        props_path, "scripts/collect_props.sh"
    )
    if write_report is None or collect_props is None:
        return [*write_errors, *props_errors]

    active_write_lines = active_shell_lines(write_report)
    required_write_guards: tuple[tuple[Callable[[], bool], str], ...] = (
        (lambda: "umask 077" in active_write_lines, "collector must set umask 077"),
        (
            lambda: 'BASE_DIR="/data/adb/android-trust-lab"' in active_write_lines,
            "collector output must be under /data/adb",
        ),
        (
            lambda: "if ! acquire_collector_lock; then" in active_write_lines,
            "collector must acquire an atomic directory lock",
        ),
        (
            lambda: (
                'if [ -e "$STAGING_DIR" ] || ! mkdir "$STAGING_DIR" 2>/dev/null; then'
                in active_write_lines
            ),
            "collector must create an exclusive private staging directory",
        ),
        (
            lambda: any(
                'chmod 0700 "$BASE_DIR" "$OUT_DIR" "$EVENT_DIR"' in line
                for line in active_write_lines
            ),
            "collector directories must be mode 0700",
        ),
        (
            lambda: any('chmod 0600 "$RAW"' in line for line in active_write_lines),
            "raw collector output must be mode 0600",
        ),
        (
            lambda: any(
                'chmod 0600 "$MANIFEST_TMP"' in line for line in active_write_lines
            ),
            "manifest output must be mode 0600",
        ),
        (
            lambda: any('[ -L "$BASE_DIR" ]' in line for line in active_write_lines),
            "collector must reject symlinked output directories",
        ),
        (
            lambda: 'RUN_ID="run_${TS_FILE}_${RUN_NONCE}"' in active_write_lines,
            "collector run IDs must bind UTC time and verified entropy",
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
                "grep -Eq '^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)" in line
                for line in active_write_lines
            ),
            "collector must validate dynamic manifest versions before JSON emission",
        ),
        (
            lambda: "trap 'on_interrupt' HUP INT TERM" in active_write_lines,
            "collector must trap interruptions",
        ),
        (
            lambda: any(
                'ln "$MANIFEST" "$FINAL_DIR/collector_manifest.json"' in line
                for line in active_write_lines
            ),
            "collector must publish a non-replacing completion manifest last",
        ),
        (
            lambda: any("collector.log" in line for line in active_write_lines),
            "collector must preserve a sanitized private log",
        ),
    )
    for predicate, message in required_write_guards:
        if not predicate():
            errors.append(message)

    script_texts: dict[str, str] = {}
    for relative in sorted(SCRIPT_FILES):
        script_text, script_errors = _read_utf8_regular(module_dir / relative, relative)
        if script_text is None:
            return [*errors, *script_errors]
        script_texts[relative] = script_text
    active_script_lines = {
        line for text in script_texts.values() for line in active_shell_lines(text)
    }
    if any(
        "/proc/cmdline" in line or "kernel_cmdline=" in line
        for line in active_script_lines
    ):
        errors.append("collector must not capture the kernel command line")
    forbidden_runtime_commands = re.compile(
        r"^(?:(?:/[^\s]+/)?adb\s+(?:root|remount|reboot)|"
        r"(?:/[^\s]+/)?fastboot(?:\s|$)|"
        r"(?:(?:/[^\s]+/)?|toybox\s+)mount(?:\s|$)|"
        r"(?:/[^\s]+/)?reboot(?:\s|$)|"
        r"(?:/[^\s]+/)?(?:resetprop|setenforce|setprop|su)(?:\s|$)|"
        r"magisk\s+(?:--install|--remove-modules|--sqlite)(?:\s|$)|"
        r"dd\s+.*\bof=/dev/block/)"
    )
    if any(forbidden_runtime_commands.search(line) for line in active_script_lines):
        errors.append("collector must not invoke privileged mutation commands")
    if "/data/local/tmp/android-trust-lab" in write_report:
        errors.append("collector must not publish reports under /data/local/tmp")
    if "chmod 0755" in write_report or "chmod 0644" in write_report:
        errors.append("collector must not make report paths group/world readable")

    declared_properties = {
        match.group(1)
        for line in collect_props.splitlines()
        if (match := re.fullmatch(r"\s{2}((?:ro|sys)\.[a-z0-9._]+)\s*\\?", line))
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


def validate_webui_contract(module_dir: Path = MODULE_DIR) -> list[str]:
    """Check the narrow local-only WebUI boundary and vendored bridge pin."""

    errors: list[str] = []
    webroot = module_dir / "webroot"
    index = webroot / "index.html"
    bridge = webroot / "bridge.js"
    vendor = webroot / "vendor/kernelsu.js"
    notice = webroot / "THIRD_PARTY_NOTICES.md"
    required = (index, bridge, vendor, notice)
    if not all(path.is_file() and not path.is_symlink() for path in required):
        return ["WebUI files must be regular local files"]
    index_text, index_errors = _read_utf8_regular(index, "webroot/index.html")
    bridge_text, bridge_errors = _read_utf8_regular(bridge, "webroot/bridge.js")
    notice_text, notice_errors = _read_utf8_regular(
        notice, "webroot/THIRD_PARTY_NOTICES.md"
    )
    errors.extend(index_errors)
    errors.extend(bridge_errors)
    errors.extend(notice_errors)
    if index_text is None or bridge_text is None or notice_text is None:
        return errors
    if (
        "Content-Security-Policy" not in index_text
        or "connect-src 'none'" not in index_text
    ):
        errors.append("WebUI must set a restrictive CSP with connect-src 'none'")
    if "/data/adb/modules/androidtrustlab/scripts/webui_api.sh" not in bridge_text:
        errors.append("WebUI bridge must use the fixed backend executable")
    if "spawn(backend, [operation, ...args]" not in bridge_text:
        errors.append("WebUI bridge must use KernelSU spawn with an argument array")
    if hashlib.sha256(vendor.read_bytes()).hexdigest() != KERNELSU_BRIDGE_SHA256:
        errors.append(
            "vendored KernelSU bridge digest does not match the pinned source"
        )
    if (
        "kernelsu` version `3.0.2`" not in notice_text
        or "Apache-2.0" not in notice_text
    ):
        errors.append(
            "WebUI third-party notice must pin the KernelSU bridge version and license"
        )
    for path in sorted(webroot.rglob("*")):
        if not path.is_file() or path.suffix not in {".html", ".js", ".css"}:
            continue
        relative = relative_posix(path, module_dir)
        content, read_errors = _read_utf8_regular(path, relative)
        errors.extend(read_errors)
        if content is None:
            continue
        if "http://" in content or "https://" in content:
            errors.append(
                f"WebUI runtime asset must not contain a network URL: {relative}"
            )
        if any(
            marker in content
            for marker in ("innerHTML", "document.write", "eval(", "Function(")
        ):
            errors.append(
                f"WebUI runtime asset contains forbidden dynamic rendering: {relative}"
            )
        if "onclick=" in content:
            errors.append(f"WebUI must not use inline event handlers: {relative}")
    return errors


def module_validation_errors(module_dir: Path = MODULE_DIR) -> list[str]:
    errors = validate_payload_structure(module_dir)
    if errors:
        return list(dict.fromkeys(errors))
    errors.extend(validate_required_files(module_dir))
    errors.extend(validate_module_metadata(module_dir))
    errors.extend(validate_shell_contract(module_dir))
    errors.extend(validate_collector_guardrails(module_dir))
    errors.extend(validate_webui_contract(module_dir))
    return list(dict.fromkeys(errors))


def validate_module(module_dir: Path = MODULE_DIR) -> None:
    errors = module_validation_errors(module_dir)
    if errors:
        raise SystemExit("\n".join(errors))


def canonical_zip_timestamp(
    environment: Mapping[str, str] | None = None,
) -> tuple[int, int, int, int, int, int]:
    source = os.environ if environment is None else environment
    raw_epoch = source.get("SOURCE_DATE_EPOCH")
    if raw_epoch is None:
        raw_epoch = str(DEFAULT_SOURCE_DATE_EPOCH)
    if len(raw_epoch) > 12 or re.fullmatch(r"[0-9]+", raw_epoch) is None:
        raise ValueError("SOURCE_DATE_EPOCH must be one decimal Unix timestamp")
    try:
        utc = time.gmtime(int(raw_epoch))
    except (OverflowError, OSError, ValueError) as error:
        raise ValueError("SOURCE_DATE_EPOCH is outside the supported range") from error
    if not MIN_ZIP_YEAR <= utc.tm_year <= MAX_ZIP_YEAR:
        raise ValueError("SOURCE_DATE_EPOCH must resolve to ZIP year 1980..2107")
    return (
        utc.tm_year,
        utc.tm_mon,
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec - (utc.tm_sec % 2),
    )


def archive_mode(archive_name: str) -> int:
    return SCRIPT_MODE if archive_name in SCRIPT_FILES else NORMAL_MODE


def _validated_inventory(module_dir: Path) -> list[ModuleFile]:
    errors = module_validation_errors(module_dir)
    if errors:
        raise ValueError("\n".join(errors))
    files, inventory_errors = inspect_module_tree(module_dir)
    if inventory_errors:
        raise ValueError("\n".join(inventory_errors))
    return files


def _assert_output_outside_module(output: Path, module_dir: Path) -> None:
    resolved_module = module_dir.resolve()
    resolved_output = output.resolve(strict=False)
    if resolved_output.is_relative_to(resolved_module):
        raise ValueError("archive output must be outside the module source tree")
    if output.is_symlink() or (output.exists() and not output.is_file()):
        raise ValueError("archive output must be absent or one regular file")


def _absolute_without_symlink_resolution(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def write_zip(
    output: Path,
    module_dir: Path = MODULE_DIR,
    *,
    timestamp: tuple[int, int, int, int, int, int] | None = None,
) -> None:
    """Write one validated canonical archive; callers publish only after comparison."""

    module_dir = _absolute_without_symlink_resolution(module_dir)
    output = _absolute_without_symlink_resolution(output)
    _assert_output_outside_module(output, module_dir)
    inventory = _validated_inventory(module_dir)
    archive_timestamp = canonical_zip_timestamp() if timestamp is None else timestamp
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_STORED,
        allowZip64=False,
    ) as archive:
        archive.comment = b""
        # Interleave explicit directory entries in canonical sorted order with
        # file entries. Some unzip implementations (including those bundled with
        # Magisk) do not infer parent directories from file paths and require an
        # explicit directory entry to create the scripts/ subdirectory before
        # any files inside it can be extracted.
        all_entries = sorted(
            [(dir_name, None) for dir_name in ARCHIVE_DIRECTORY_ENTRIES]
            + [(source.archive_name, source) for source in inventory],
            key=lambda entry: entry[0],
        )
        for archive_name, source in all_entries:
            if source is None:
                info = zipfile.ZipInfo(archive_name, archive_timestamp)
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.create_version = 20
                info.extract_version = 20
                info.external_attr = (stat.S_IFDIR | 0o755) << 16
                info.internal_attr = 0
                info.extra = b""
                info.flag_bits = 0
                archive.writestr(info, b"", compress_type=zipfile.ZIP_STORED)
            else:
                payload = _read_module_file(source)
                info = zipfile.ZipInfo(source.archive_name, archive_timestamp)
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.create_version = 20
                info.extract_version = 20
                info.external_attr = (
                    stat.S_IFREG | archive_mode(source.archive_name)
                ) << 16
                info.internal_attr = 0
                info.extra = b""
                info.comment = b""
                info.flag_bits = 0
                archive.writestr(info, payload, compress_type=zipfile.ZIP_STORED)


def _validate_dir_member(
    info: zipfile.ZipInfo,
    expected_timestamp: tuple[int, int, int, int, int, int],
) -> list[str]:
    errors: list[str] = []
    unix_mode = info.external_attr >> 16
    if not stat.S_ISDIR(unix_mode) or stat.S_IMODE(unix_mode) != 0o755:
        errors.append(f"archive directory mode is invalid: {info.filename}")
    if info.create_system != 3:
        errors.append(f"archive directory must declare Unix metadata: {info.filename}")
    if info.create_version != 20 or info.extract_version != 20:
        errors.append(
            f"archive directory ZIP version is not canonical: {info.filename}"
        )
    if info.compress_type != zipfile.ZIP_STORED:
        errors.append(
            f"archive directory compression is not canonical: {info.filename}"
        )
    if info.date_time != expected_timestamp:
        errors.append(f"archive directory timestamp is not canonical: {info.filename}")
    if info.extra or info.comment:
        errors.append(f"archive directory metadata must be empty: {info.filename}")
    if info.flag_bits & 0x1:
        errors.append(f"encrypted archive directory is not allowed: {info.filename}")
    return errors


def _validate_archive_member(
    info: zipfile.ZipInfo,
    expected_timestamp: tuple[int, int, int, int, int, int],
) -> tuple[list[str], bool]:
    errors: list[str] = []
    bounded = True
    if info.file_size > MAX_FILE_BYTES:
        bounded = False
        errors.append(f"archive member exceeds {MAX_FILE_BYTES} bytes: {info.filename}")
    unix_mode = info.external_attr >> 16
    expected_mode = archive_mode(info.filename)
    if info.is_dir() or not stat.S_ISREG(unix_mode):
        errors.append(f"archive member must be regular: {info.filename}")
    if stat.S_IMODE(unix_mode) != expected_mode or expected_mode & 0o022:
        errors.append(f"archive member mode is invalid: {info.filename}")
    if info.create_system != 3:
        errors.append(f"archive member must declare Unix metadata: {info.filename}")
    if info.create_version != 20 or info.extract_version != 20:
        errors.append(f"archive member ZIP version is not canonical: {info.filename}")
    if info.compress_type != zipfile.ZIP_STORED:
        errors.append(f"archive member compression is not canonical: {info.filename}")
    if info.compress_size != info.file_size:
        errors.append(f"stored archive member size mismatch: {info.filename}")
    if info.date_time != expected_timestamp:
        errors.append(f"archive member timestamp is not canonical: {info.filename}")
    if info.extra or info.comment:
        errors.append(f"archive member metadata must be empty: {info.filename}")
    if info.flag_bits & 0x1:
        errors.append(f"encrypted archive member is not allowed: {info.filename}")
    return errors, bounded


def validate_archive_structure(
    archive_path: Path,
    *,
    timestamp: tuple[int, int, int, int, int, int] | None = None,
) -> list[str]:
    expected_timestamp = canonical_zip_timestamp() if timestamp is None else timestamp
    errors: list[str] = []
    try:
        with zipfile.ZipFile(archive_path, "r", allowZip64=False) as archive:
            infos = archive.infolist()
            raw_names = [info.filename for info in infos]
            file_raw_names = [n for n in raw_names if not n.endswith("/")]
            dir_raw_names = [n for n in raw_names if n.endswith("/")]
            errors.extend(validate_archive_paths(file_raw_names))
            for dir_name in dir_raw_names:
                if dir_name not in ARCHIVE_DIRECTORY_ENTRIES:
                    errors.append(f"unexpected archive directory entry: {dir_name}")
            if archive.comment:
                errors.append("archive comment must be empty")
            if len(infos) > MAX_FILES:
                errors.append(f"archive file count exceeds {MAX_FILES}")
            if raw_names != sorted(raw_names):
                errors.append("archive entries must use canonical sorted order")
            if set(file_raw_names) != ALLOWED_FILES:
                errors.append("archive payload must exactly match the closed allowlist")
            if set(dir_raw_names) != ARCHIVE_DIRECTORY_ENTRIES:
                errors.append(
                    "archive directory entries must exactly match the expected set"
                )
            total_size = 0
            bounded = True
            for info in infos:
                if info.filename.endswith("/"):
                    errors.extend(_validate_dir_member(info, expected_timestamp))
                    continue
                total_size += info.file_size
                member_errors, member_bounded = _validate_archive_member(
                    info, expected_timestamp
                )
                errors.extend(member_errors)
                bounded = bounded and member_bounded
            if total_size > MAX_TOTAL_BYTES:
                bounded = False
                errors.append(f"archive payload exceeds {MAX_TOTAL_BYTES} bytes")
            if bounded:
                bad_member = archive.testzip()
                if bad_member is not None:
                    errors.append(f"archive CRC failed: {bad_member}")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return ["archive is not one bounded readable ZIP file"]
    return list(dict.fromkeys(errors))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(READ_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def build_reproducible_archive(
    output: Path,
    module_dir: Path = MODULE_DIR,
    *,
    timestamp: tuple[int, int, int, int, int, int] | None = None,
) -> str:
    """Build twice, compare exact bytes, then atomically publish one archive."""

    module_dir = _absolute_without_symlink_resolution(module_dir)
    output = _absolute_without_symlink_resolution(output)
    _assert_output_outside_module(output, module_dir)
    archive_timestamp = canonical_zip_timestamp() if timestamp is None else timestamp
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: list[Path] = []
    try:
        for label in ("first", "second"):
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{output.name}.{label}.",
                suffix=".tmp",
                dir=output.parent,
            )
            os.close(descriptor)
            temporary_path = Path(temporary_name)
            temporary.append(temporary_path)
            write_zip(
                temporary_path,
                module_dir,
                timestamp=archive_timestamp,
            )
        first_bytes = temporary[0].read_bytes()
        second_bytes = temporary[1].read_bytes()
        if first_bytes != second_bytes:
            raise ValueError(
                "independent Magisk archive builds were not byte-identical"
            )
        structure_errors = validate_archive_structure(
            temporary[0], timestamp=archive_timestamp
        )
        if structure_errors:
            raise ValueError("\n".join(structure_errors))
        digest = hashlib.sha256(first_bytes).hexdigest()
        os.chmod(temporary[0], NORMAL_MODE)
        if output.is_symlink() or (output.exists() and not output.is_file()):
            raise ValueError("archive output must be absent or one regular file")
        os.replace(temporary[0], output)
        temporary.pop(0)
        return digest
    finally:
        for path in temporary:
            path.unlink(missing_ok=True)


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
                "usage: package_magisk_module.py "
                "[--check-only] [--module-dir PATH] [--output PATH]"
            )
            raise SystemExit(0)
        else:
            raise SystemExit(f"unknown argument: {arg}")
    return (
        _absolute_without_symlink_resolution(module_dir),
        _absolute_without_symlink_resolution(output),
        check_only,
    )


def main(argv: Sequence[str] | None = None) -> int:
    module_dir, output, check_only = parse_args(argv)
    try:
        timestamp = canonical_zip_timestamp()
        if check_only:
            with tempfile.TemporaryDirectory(prefix="trustlab-magisk-check-") as temp:
                digest = build_reproducible_archive(
                    Path(temp) / "androidtrustlab-magisk.zip",
                    module_dir,
                    timestamp=timestamp,
                )
            print("Magisk deterministic structural packaging guardrails passed")
            print(f"reproducible_sha256={digest}")
        else:
            digest = build_reproducible_archive(
                output,
                module_dir,
                timestamp=timestamp,
            )
            print(output)
            print(f"sha256={digest}")
    except ValueError as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
