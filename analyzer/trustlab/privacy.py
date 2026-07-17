"""Fail-closed privacy helpers for portable normalized evidence."""

from __future__ import annotations

import ipaddress
import json
import re
from copy import deepcopy
from typing import Any, cast

from .assessment import confidence_assessment, direction_assessment
from .comparison import observer_protocol
from .dimension_registry import DEFAULT_DIMENSIONS, TRUST_DIMENSIONS_BY_ID
from .exceptions import SchemaValidationError
from .transitions import (
    classify_status_transition,
    confidence_impact,
    evidence_is_available,
    evidence_status,
    signal_direction,
    transition_interpretation,
)

_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:+/@-]{1,255}$", flags=re.ASCII)
_SAFE_ANDROID_PATHS = frozenset(
    {"/", "/system", "/vendor", "/product", "/system_ext", "/odm", "/data", "/apex"}
)
_SAFE_MOUNT_OPTIONS = frozenset(
    {
        "async",
        "atime",
        "bind",
        "dev",
        "dirsync",
        "exec",
        "lazytime",
        "noatime",
        "nodev",
        "nodiratime",
        "noexec",
        "nolazytime",
        "norelatime",
        "nosuid",
        "relatime",
        "remount",
        "ro",
        "rw",
        "strictatime",
        "suid",
        "sync",
        "unbindable",
    }
)
_SAFE_FILESYSTEM_TYPES = frozenset(
    {
        "apex",
        "bpf",
        "cgroup",
        "cgroup2",
        "configfs",
        "debugfs",
        "devpts",
        "devtmpfs",
        "erofs",
        "ext4",
        "f2fs",
        "functionfs",
        "fuse",
        "none",
        "overlay",
        "proc",
        "pstore",
        "ramfs",
        "rootfs",
        "securityfs",
        "selinuxfs",
        "squashfs",
        "sysfs",
        "tmpfs",
        "tracefs",
        "unknown",
        "vfat",
        "virtiofs",
    }
)
_IDENTITY_CATEGORIES = frozenset(
    {"build-fingerprint", "device-codename", "manufacturer", "model"}
)
_PORTABLE_VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:(?:-|\.)(?:alpha|beta|canary|dev|rc)[0-9]+)?$",
    flags=re.ASCII,
)
_MAGISK_VERSION_NAME_RE = re.compile(
    r"^(?:synthetic-)?v?[0-9]{1,4}(?:\.[0-9]{1,4}){0,3}"
    r"(?:-(?:alpha|beta|canary|debug|release|rc)[0-9]*)?$",
    flags=re.ASCII,
)
_PORTABLE_EXPERIMENT_IDS = frozenset(
    {
        "E01_stock_avd",
        "E02_rooted_avd",
        "E03_writable_system_avd",
        "E05_magisk_collector",
        "E10_adversarial",
        "E10_golden",
        "E10_identity",
        "E16_adapter_contract",
        "E17_parser_limits",
        "E18_modern_mounts",
        "E18_nested_mount",
        "E18_overlay_context",
        "E18_partial_generic_mount",
        "E18_partial_mounts",
        "E19_structured_security",
        "E26_host_collection",
        "E27_adb_collection",
        "E99_manual",
        "E99_physical_device_template",
    }
)
_PORTABLE_COLLECTION_METHODS = frozenset(
    {
        "adb_shell_snapshot",
        "adb_snapshot",
        "app_snapshot",
        "fixture_snapshot",
        "golden_fixture",
        "host_snapshot",
        "identity_fixture",
        "legacy_migration",
        "magisk_module_boot",
        "magisk_module_manual",
        "manual_capture",
        "manual_fixture",
        "raw_artifact",
        "report_v2_migration",
        "synthetic_adb_fixture",
        "synthetic_app_fixture",
        "synthetic_confidence_probe",
        "synthetic_host_fixture",
        "synthetic_magisk_fixture",
        "synthetic_root_collector_snapshot",
        "synthetic_rooted_adb_snapshot",
        "synthetic_security_fixture",
        "synthetic_writable_system_snapshot",
        "test_fixture",
    }
)

_SENSITIVE_PATTERNS = (
    re.compile(
        r"(?i)(?:^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:$|[^A-Za-z0-9.-])"
    ),
    re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"),
    re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])"),
    re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}-){5}[0-9a-f]{2}(?![0-9a-f])"),
    re.compile(
        r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![0-9a-f])"
    ),
    re.compile(r"(?i)(?:emulator-[0-9]{4,}|transport[_ -]?id\s*[:=]\s*[0-9]+)"),
    re.compile(
        r"(?i)(?:serial(?:no|number)?|device[_-]?id|boot[_-]?id)\s*[:=]\s*[^\s,;]+"
    ),
    re.compile(
        r"(?i)(?:password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)androidboot\.(?:serialno|deviceid|bootdevice)=[^\s]+"),
    re.compile(r"(?:^|[\s=])/(?:Users|home)/[^/\s]+/"),
    re.compile(r"(?i)(?:^|[\s=])[A-Z]:\\Users\\[^\\\s]+\\"),
    re.compile(r"(?i)(?:^|[^A-Za-z0-9])R[0-9A-Z]{10,}(?:$|[^A-Za-z0-9])"),
    re.compile(r"(?i)(?:gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,})"),
    re.compile(r"(?i)(?:PRIVATE_?KEY|PRIVATEVALUE|BEGIN [A-Z ]+ PRIVATE KEY)"),
    re.compile(
        r"(?i)/(?:data/(?:local|user|media|misc|adb)|sdcard|storage|mnt)/(?:[^\s\"',}\]]+)"
    ),
)


def contains_sensitive_identifier(value: str) -> bool:
    """Return whether text contains a recognized portable-output hazard."""

    if any(pattern.search(value) is not None for pattern in _SENSITIVE_PATTERNS):
        return True
    for token in re.findall(r"(?i)(?<![0-9a-f:])[0-9a-f:]{2,}(?![0-9a-f:])", value):
        if ":" not in token:
            continue
        try:
            if ipaddress.ip_address(token).version == 6:
                return True
        except ValueError:
            continue
    return False


def deterministic_pseudonym(value: str, *, category: str, scope: str) -> str:
    """Create a deterministic non-linkable category pseudonym.

    The source and scope are deliberately not encoded into portable output, so
    low-entropy candidates cannot be confirmed offline.
    """

    del value, scope
    safe_category = re.sub(r"[^a-z0-9]+", "-", category.lower()).strip("-")
    return f"redacted-{safe_category or 'value'}"


def semantic_capture_ref(name: str) -> str:
    """Map an untrusted capture filename to its fixed semantic reference."""

    safe_name = re.sub(r"[^a-z0-9_]+", "_", name.lower()).strip("_")
    return f"captures/{safe_name or 'unknown'}.txt"


def sanitize_collection_id(value: str, *, scope: str) -> str:
    """Keep derived opaque IDs and remap caller-controlled collection labels."""

    if re.fullmatch(r"atlcol-[a-f0-9]{32}", value):
        return value
    del value, scope
    return "collection-redacted"


def sanitize_metadata_value(value: str, *, category: str, scope: str) -> str:
    """Retain bounded metadata tokens and pseudonymize unsafe values."""

    if value == "unknown":
        return value
    if category in _IDENTITY_CATEGORIES:
        return deterministic_pseudonym(value, category=category, scope=scope)
    if category == "module-context" and value != "androidtrustlab":
        return deterministic_pseudonym(value, category=category, scope=scope)
    if category == "magisk-version-name" and not (
        _MAGISK_VERSION_NAME_RE.fullmatch(value)
        and not contains_sensitive_identifier(value)
    ):
        return deterministic_pseudonym(value, category=category, scope=scope)
    if (
        not _SAFE_TOKEN_RE.fullmatch(value)
        or contains_sensitive_identifier(value)
        or value.startswith(("/", "~"))
        or ".." in value
    ):
        return deterministic_pseudonym(value, category=category, scope=scope)
    return value


_PROPERTY_VALUE_PATTERNS: dict[str, re.Pattern[str]] = {
    "ro.boot.flash.locked": re.compile(r"^[01]$"),
    "ro.boot.vbmeta.device_state": re.compile(r"^(?:locked|unlocked)$"),
    "ro.boot.verifiedbootstate": re.compile(r"^(?:green|yellow|orange|red)$"),
    "ro.boot.veritymode": re.compile(r"^(?:enforcing|eio|logging|disabled)$"),
    "ro.build.version.release": re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){0,3}$"),
    "ro.build.version.sdk": re.compile(r"^[0-9]{1,3}$"),
    "ro.crypto.state": re.compile(r"^(?:encrypted|unencrypted|unsupported)$"),
    "ro.crypto.type": re.compile(r"^(?:block|file|none)$"),
    "ro.crypto.volume.filenames_mode": re.compile(
        r"^(?:aes-256-cts|aes-256-heh|adiantum|ice|unknown)$"
    ),
    "ro.debuggable": re.compile(r"^[01]$"),
    "ro.secure": re.compile(r"^[01]$"),
    "ro.adb.secure": re.compile(r"^[01]$"),
    "sys.boot_completed": re.compile(r"^[01]$"),
    "ro.kernel.qemu": re.compile(r"^[01]$"),
    "ro.boot.slot_suffix": re.compile(r"^_[ab]$"),
}
_PROPERTY_IDENTITY_CATEGORIES = {
    "ro.build.fingerprint": "build-fingerprint",
    "ro.product.device": "device-codename",
    "ro.product.manufacturer": "manufacturer",
    "ro.product.model": "model",
}


def sanitize_property_value(key: str, value: str, *, scope: str) -> str:
    """Apply exact security-property grammars and sanitize identity metadata."""

    if value == "unknown":
        return value
    identity_category = _PROPERTY_IDENTITY_CATEGORIES.get(key)
    if identity_category is not None:
        return deterministic_pseudonym(value, category=identity_category, scope=scope)
    pattern = _PROPERTY_VALUE_PATTERNS.get(key)
    if pattern is not None:
        return (
            value
            if pattern.fullmatch(value) and not contains_sensitive_identifier(value)
            else deterministic_pseudonym(value, category="property", scope=scope)
        )
    return sanitize_metadata_value(value, category="property", scope=scope)


def sanitize_boot_reason(value: str, *, scope: str) -> str:
    """Retain controlled boot-reason tokens; pseudonymize everything else."""

    if value == "unknown":
        return value
    if value in {
        "bootloader",
        "cold",
        "hard",
        "kernel_panic",
        "normal",
        "reboot",
        "recovery",
        "shutdown",
        "userrequested",
        "warm",
        "watchdog",
    }:
        return value
    return deterministic_pseudonym(value, category="boot-reason", scope=scope)


def _portable_mount_path(value: object, *, scope: str) -> str | None:
    if not isinstance(value, str):
        return None
    if value in _SAFE_ANDROID_PATHS:
        return value
    if re.fullmatch(r"/apex/[A-Za-z0-9._+-]{1,160}(?:@[A-Za-z0-9._+-]+)?", value):
        return "/apex/redacted-package"
    return "/redacted/path"


def _portable_mount_source(value: object, *, scope: str) -> str:
    text = value if isinstance(value, str) else "unknown"
    if text in {"overlay", "tmpfs", "none", "rootfs"}:
        return text
    if text.startswith("/dev/block/mapper/"):
        return "/dev/block/mapper/redacted"
    if re.fullmatch(r"/dev/block/dm-[0-9]+", text):
        return "/dev/block/dm-redacted"
    return deterministic_pseudonym(text, category="mount-source", scope=scope)


def _portable_fs_type(value: object) -> str:
    text = value if isinstance(value, str) else "unknown"
    return text if text in _SAFE_FILESYSTEM_TYPES else "redacted-fs-type"


def _portable_options(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    names = {
        item.split("=", 1)[0]
        for item in values
        if isinstance(item, str) and item.split("=", 1)[0] in _SAFE_MOUNT_OPTIONS
    }
    return sorted(names)


def sanitize_mount_model(mounts: dict[str, Any], *, scope: str) -> dict[str, Any]:
    """Withhold raw mount rows, paths, sources, and option values."""

    result = deepcopy(mounts)
    apex_labels = sorted(
        {
            str(record.get("mount_point"))
            .removeprefix("/apex/")
            .split("/", 1)[0]
            .split("@", 1)[0]
            for record in result.get("records", [])
            if isinstance(record, dict)
            and str(record.get("mount_point", "")).startswith("/apex/")
        }
    )
    apex_pseudonyms = {
        label: f"redacted-apex-package-{index:03d}"
        for index, label in enumerate(apex_labels, start=1)
    }
    for name in (
        "system_mount",
        "vendor_mount",
        "product_mount",
        "system_ext_mount",
        "odm_mount",
        "data_mount",
        "apex_mount",
    ):
        summary = result.get(name)
        if not isinstance(summary, dict):
            continue
        summary["mount_point"] = (
            _portable_mount_path(summary.get("mount_point"), scope=scope)
            or "/redacted/path"
        )
        summary["options"] = _portable_options(summary.get("options"))
        summary["fs_type"] = _portable_fs_type(summary.get("fs_type"))
        summary["raw"] = "<withheld>"
    for record in result.get("records", []):
        record["root"] = _portable_mount_path(record.get("root"), scope=scope)
        mount_point = record.get("mount_point")
        if isinstance(mount_point, str) and mount_point.startswith("/apex/"):
            label = mount_point.removeprefix("/apex/").split("/", 1)[0].split("@", 1)[0]
            record["mount_point"] = f"/apex/{apex_pseudonyms[label]}"
        else:
            record["mount_point"] = (
                _portable_mount_path(mount_point, scope=scope) or "/redacted/path"
            )
        record["mount_options"] = _portable_options(record.get("mount_options"))
        record["optional_fields"] = []
        record["source"] = _portable_mount_source(record.get("source"), scope=scope)
        record["fs_type"] = _portable_fs_type(record.get("fs_type"))
        record["super_options"] = _portable_options(record.get("super_options"))
        record["raw"] = "<withheld>"
        selected = result.get("observation", {}).get("selected_source")
        record["evidence_path"] = semantic_capture_ref(
            selected if isinstance(selected, str) else "mounts"
        )
    observation = result.get("observation", {})
    selected = observation.get("selected_source")
    evidence_ref = semantic_capture_ref(
        selected if isinstance(selected, str) else "mounts"
    )
    observation["evidence_paths"] = [evidence_ref] if result.get("records") else []
    for attempt in observation.get("attempts", []):
        attempt["source_ref"] = semantic_capture_ref(str(attempt.get("name", "mounts")))
    dynamic = result.get("dynamic_partitions", {})
    indices = set(dynamic.get("record_indices", []))
    dynamic["sources"] = sorted(
        {
            record["source"]
            for record in result.get("records", [])
            if record.get("record_index") in indices
        }
    )
    apex = result.get("apex_set", {})
    apex["packages"] = sorted(apex_pseudonyms.values())
    apex["package_count"] = len(apex["packages"])
    return result


def sanitize_raw_artifact_references(
    artifacts: list[dict[str, Any]], *, scope: str
) -> list[dict[str, Any]]:
    """Replace caller-controlled provenance labels with semantic identifiers."""

    result = deepcopy(artifacts)
    for index, artifact in enumerate(result, start=1):
        logical_id = f"raw-artifact-{index:03d}"
        artifact["logical_id"] = logical_id
        suffix = ".json" if artifact.get("media_type") == "application/json" else ".txt"
        artifact["relative_path"] = f"artifacts/{logical_id}{suffix}"
        collector = str(artifact.get("collector_name", "unknown"))
        artifact["collector_name"] = (
            collector
            if collector in {"unknown", "trustlab", "trustlab-magisk", "adb"}
            else "redacted-collector"
        )
        version = str(artifact.get("collector_version", "unknown"))
        if not (
            version in {"legacy", "unknown"} or _PORTABLE_VERSION_RE.fullmatch(version)
        ):
            artifact["collector_version"] = "unknown"
    return result


def sanitize_experiment_id(value: str, *, scope: str) -> str:
    if value == "unknown" or value in _PORTABLE_EXPERIMENT_IDS:
        return value
    return deterministic_pseudonym(value, category="experiment", scope=scope)


def sanitize_collection_method(value: str, *, scope: str) -> str:
    if value in _PORTABLE_COLLECTION_METHODS:
        return value
    return deterministic_pseudonym(value, category="collection-method", scope=scope)


def _iter_strings(value: object, path: str = "$") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            found.append((f"{path}.<key>", str(key)))
            found.extend(_iter_strings(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_iter_strings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        found.append((path, value))
    return found


def _reject_sensitive_strings(value: object, *, artifact: str) -> None:
    for path, text in _iter_strings(value):
        if contains_sensitive_identifier(text):
            raise SchemaValidationError(
                f"{artifact} portable privacy validation failed at {path}"
            )


def _evidence_value(value: object) -> object:
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value


_SYNTHETIC_IDENTITIES = {
    "device_codename": {"generic_x86_64"},
    "manufacturer": {"Google"},
    "model": {"sdk_gphone64_x86_64"},
    "build_fingerprint": {"google/sdk_gphone64_x86_64/generic:14/UP1A/test-keys"},
}


def _validate_identity_fields(report: dict[str, Any]) -> None:
    target = report.get("target")
    if not isinstance(target, dict):
        return
    for field, category in (
        ("device_codename", "device-codename"),
        ("manufacturer", "manufacturer"),
        ("model", "model"),
        ("build_fingerprint", "build-fingerprint"),
    ):
        value = _evidence_value(target.get(field))
        if value is None:
            continue
        allowed = {"unknown", f"redacted-{category}", *_SYNTHETIC_IDENTITIES[field]}
        if value not in allowed:
            raise SchemaValidationError(
                f"report portable identity field {field} is not redacted"
            )


def _property_maps(report: dict[str, Any]) -> list[dict[str, Any]]:
    properties = report.get("properties")
    if not isinstance(properties, dict):
        return []
    maps: list[dict[str, Any]] = []
    for group in ("boot", "build", "product", "crypto", "security"):
        current = _evidence_value(properties.get(group))
        if isinstance(current, dict):
            maps.append(current)
    raw = report.get("verified_boot")
    if isinstance(raw, dict):
        current = _evidence_value(raw.get("raw_properties"))
        if isinstance(current, dict):
            maps.append(current)
    return maps


def _validate_property_fields(report: dict[str, Any]) -> None:
    for values in _property_maps(report):
        for key, value in values.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            identity_category = _PROPERTY_IDENTITY_CATEGORIES.get(key)
            if identity_category is not None:
                field = {
                    "build-fingerprint": "build_fingerprint",
                    "device-codename": "device_codename",
                    "manufacturer": "manufacturer",
                    "model": "model",
                }[identity_category]
                if value not in {
                    f"redacted-{identity_category}",
                    *_SYNTHETIC_IDENTITIES[field],
                }:
                    raise SchemaValidationError(
                        f"report portable property {key} is not redacted"
                    )
                continue
            pattern = _PROPERTY_VALUE_PATTERNS.get(key)
            if pattern is None:
                raise SchemaValidationError(
                    f"report portable property {key} is not allowlisted"
                )
            if pattern is not None and not (
                pattern.fullmatch(value) or value in {"redacted-property", "unknown"}
            ):
                raise SchemaValidationError(
                    f"report portable property {key} has an unsafe value"
                )


def _validate_direct_v6_mounts(report: dict[str, Any]) -> None:
    mounts = report.get("mounts")
    if not isinstance(mounts, dict):
        return
    summaries = [
        mounts.get(name)
        for name in (
            "system_mount",
            "vendor_mount",
            "product_mount",
            "system_ext_mount",
            "odm_mount",
            "data_mount",
            "apex_mount",
        )
    ]
    records = mounts.get("records", [])
    for item in [*summaries, *(records if isinstance(records, list) else [])]:
        if not isinstance(item, dict):
            continue
        is_record = "record_index" in item
        unavailable = item.get("status") not in {"observed", "observed_absent"}
        if (is_record and item.get("raw") != "<withheld>") or (
            not is_record
            and (
                (unavailable and item.get("raw") is not None)
                or (not unavailable and item.get("raw") != "<withheld>")
            )
        ):
            raise SchemaValidationError(
                "direct report portable mount raw evidence must be withheld"
            )
        if item.get("fs_type") is not None and item.get(
            "fs_type"
        ) not in _SAFE_FILESYSTEM_TYPES | {"redacted-fs-type"}:
            raise SchemaValidationError(
                "direct report portable mount filesystem type is unsafe"
            )
        for key in ("mount_point", "root"):
            path = item.get(key)
            if path is None:
                continue
            if (
                path not in _SAFE_ANDROID_PATHS | {"/redacted/path"}
                and re.fullmatch(r"/apex/redacted-apex-package-[0-9]{3}", str(path))
                is None
            ):
                raise SchemaValidationError(
                    "direct report portable mount path is unsafe"
                )
        if is_record and item.get("source") not in {
            "/dev/block/dm-redacted",
            "/dev/block/mapper/redacted",
            "none",
            "overlay",
            "redacted-mount-source",
            "rootfs",
            "tmpfs",
        }:
            raise SchemaValidationError("direct report portable mount source is unsafe")
    apex = mounts.get("apex_set", {})
    if isinstance(apex, dict) and any(
        re.fullmatch(r"redacted-apex-package-[0-9]{3}", str(package)) is None
        for package in apex.get("packages", [])
    ):
        raise SchemaValidationError("direct report portable APEX labels are unsafe")


_PORTABLE_CAPTURE_NAMES = frozenset(
    {
        "adb_version",
        "app_context",
        "boot_state",
        "collector_context",
        "emulator_version",
        "getprop_selected",
        "getenforce",
        "identity",
        "id",
        "host_os",
        "kernel_cmdline",
        "magisk",
        "mountinfo",
        "mounts",
        "processes",
        "proc_mounts",
        "properties",
        "ps_selected",
        "python_version",
        "root_probe",
        "selinux_context",
        "selinux_denials",
        "selinux_mode",
        "su_paths",
    }
)
_PORTABLE_CAPTURE_STATUSES = frozenset(
    {
        "command_error",
        "empty",
        "error",
        "inaccessible",
        "not_collected",
        "observed",
        "observed_absent",
        "timeout",
        "unsupported",
    }
)
_PORTABLE_INPUT_KINDS = frozenset(
    {
        "adb_collection_manifest",
        "app_probe",
        "app_probe_json",
        "host_collection_manifest",
        "legacy_sectioned_text",
        "magisk_collection_manifest",
    }
)


def _portable_collector_version(value: object) -> bool:
    return isinstance(value, str) and (
        value in {"legacy", "unknown"}
        or _PORTABLE_VERSION_RE.fullmatch(value) is not None
    )


def _validate_adapter_extension(adapter: object) -> None:
    if not isinstance(adapter, dict):
        raise SchemaValidationError("report adapter extension is not portable")
    if not _portable_collector_version(adapter.get("collector_version")):
        raise SchemaValidationError("report adapter collector version is not portable")
    if adapter.get("input_kind") not in _PORTABLE_INPUT_KINDS:
        raise SchemaValidationError("report adapter input kind is not portable")
    input_version = adapter.get("input_schema_version")
    if input_version not in {
        "1.0.0",
        "legacy-sectioned-text-1",
        "unknown",
    }:
        raise SchemaValidationError(
            "report adapter input schema version is not portable"
        )
    warning_patterns = (
        re.compile(r"adapter warning [0-9]{3} withheld"),
        re.compile(r"source artifact warning [0-9]+ withheld"),
        re.compile(
            r"legacy sectioned text has inferred command status and no collector manifest"
        ),
        re.compile(
            r"portable collection manifest selected the observer-specific adapter; legacy payload has inferred per-command status"
        ),
    )
    if any(
        not any(pattern.fullmatch(str(warning)) for pattern in warning_patterns)
        for warning in adapter.get("warnings", [])
    ):
        raise SchemaValidationError("direct report adapter warnings are not portable")
    if any(
        re.fullmatch(r"adapter error [0-9]{3} withheld", str(error)) is None
        for error in adapter.get("errors", [])
    ):
        raise SchemaValidationError("direct report adapter errors are not portable")
    captures = adapter.get("captures", [])
    if not isinstance(captures, list):
        raise SchemaValidationError("report adapter captures are not portable")
    for capture in captures:
        if not isinstance(capture, dict) or set(capture) != {
            "name",
            "source_ref",
            "status",
        }:
            raise SchemaValidationError("report adapter capture is not semantic")
        name = capture.get("name")
        source_ref = capture.get("source_ref")
        if (
            name not in _PORTABLE_CAPTURE_NAMES
            or capture.get("status") not in _PORTABLE_CAPTURE_STATUSES
            or not isinstance(source_ref, str)
            or source_ref
            not in {
                f"captures/{name}.txt",
                f"legacy-sections/{str(name).upper()}",
            }
        ):
            # Legacy section labels have two deliberate aliases.
            aliases = {
                "identity": "legacy-sections/ID",
                "kernel_cmdline": "legacy-sections/CMDLINE",
                "mounts": "legacy-sections/MOUNT",
                "properties": "legacy-sections/GETPROP",
                "processes": {
                    "legacy-sections/PS",
                    "legacy-sections/PS_SELECTED",
                },
                "selinux_mode": "legacy-sections/GETENFORCE",
            }
            allowed_aliases = aliases.get(str(name))
            if source_ref not in (
                allowed_aliases
                if isinstance(allowed_aliases, set)
                else {allowed_aliases}
            ):
                raise SchemaValidationError("report adapter capture is not semantic")


def _validate_collection_extension(extension: object) -> None:
    if not isinstance(extension, dict) or set(extension) != {
        "canonical_manifest_sha256",
        "canonicalization",
        "portable_binding",
    }:
        raise SchemaValidationError("report portable collection binding is unsafe")
    if (
        re.fullmatch(r"[a-f0-9]{64}", str(extension.get("canonical_manifest_sha256")))
        is None
        or extension.get("canonicalization") != "atl-canonical-json-v1"
    ):
        raise SchemaValidationError("report portable collection binding is unsafe")
    binding = extension.get("portable_binding")
    if not isinstance(binding, dict) or set(binding) != {
        "artifact_results",
        "collection_errors",
        "collection_id",
        "completion_status",
        "raw_artifact_sha256",
        "raw_artifact_status",
        "redaction_state",
    }:
        raise SchemaValidationError("report portable collection binding is unsafe")
    if (
        binding.get("collection_id") not in {"collection-redacted"}
        and re.fullmatch(r"atlcol-[a-f0-9]{32}", str(binding.get("collection_id")))
        is None
    ):
        raise SchemaValidationError("report portable collection binding is unsafe")
    if (
        binding.get("completion_status") not in {"complete", "failed", "partial"}
        or binding.get("raw_artifact_status") not in _PORTABLE_CAPTURE_STATUSES
        or binding.get("redaction_state")
        not in {"not_required", "redacted", "withheld"}
        or re.fullmatch(r"[a-f0-9]{64}", str(binding.get("raw_artifact_sha256")))
        is None
    ):
        raise SchemaValidationError("report portable collection binding is unsafe")
    for index, result in enumerate(binding.get("artifact_results", []), start=1):
        if (
            not isinstance(result, dict)
            or result.get("command_id") != f"artifact-{index:03d}"
            or result.get("detail") is not None
            or result.get("status") not in _PORTABLE_CAPTURE_STATUSES
        ):
            raise SchemaValidationError("report portable collection binding is unsafe")
    error_patterns = (
        re.compile(
            r"collection manifest completion status: (?:complete|failed|partial)"
        ),
        re.compile(
            r"probe [0-9]{3}: (?:command_error|inaccessible|not_collected|observed_absent|unsupported)"
        ),
    )
    if any(
        not any(pattern.fullmatch(str(error)) for pattern in error_patterns)
        for error in binding.get("collection_errors", [])
    ):
        raise SchemaValidationError("report portable collection binding is unsafe")


def _validate_migration_extension(extension: object) -> None:
    if not isinstance(extension, dict) or set(extension) != {
        "encoding",
        "source_report_json",
        "source_sha256",
    }:
        raise SchemaValidationError("historical report migration extension is unsafe")
    if (
        extension.get("encoding")
        not in {"atl-canonical-json-v1", "canonical-json-text-v1"}
        or re.fullmatch(r"[a-f0-9]{64}", str(extension.get("source_sha256"))) is None
    ):
        raise SchemaValidationError("historical report migration extension is unsafe")
    encoded = extension.get("source_report_json")
    if not isinstance(encoded, str):
        raise SchemaValidationError("historical report migration extension is unsafe")
    try:
        nested = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise SchemaValidationError(
            "historical report contains an invalid preserved source"
        ) from exc
    validate_portable_historical_report(nested)


def _validate_comparison_context_extension(
    report: dict[str, Any], extension: object
) -> None:
    fields = {
        "environment_context",
        "experiment_id",
        "measurement_id",
        "observer",
        "observer_privilege",
        "protocol",
        "report_schema_version",
        "state_id",
        "target_class",
        "target_pseudonym",
    }
    if not isinstance(extension, dict) or set(extension) != fields:
        raise SchemaValidationError("report comparison context is not portable")
    observer = report.get("observer", {})
    target = report.get("target", {})
    expected = {
        "experiment_id": report.get("experiment_id"),
        "measurement_id": report.get("collection_event_id"),
        "observer": observer.get("observer_type")
        if isinstance(observer, dict)
        else None,
        "observer_privilege": (
            observer.get("privilege_level") if isinstance(observer, dict) else None
        ),
        "protocol": observer_protocol(
            observer.get("observer_type") if isinstance(observer, dict) else None
        ),
        "report_schema_version": report.get("schema_version"),
        "target_class": target.get("target_type") if isinstance(target, dict) else None,
    }
    if any(extension.get(name) != value for name, value in expected.items()):
        raise SchemaValidationError(
            "report comparison context does not bind report metadata"
        )
    target_pseudonym = extension.get("target_pseudonym")
    state_id = extension.get("state_id")
    environment = extension.get("environment_context")
    if not isinstance(target_pseudonym, str) or (
        target_pseudonym != "unknown"
        and re.fullmatch(r"target-[a-z0-9][a-z0-9-]{2,127}", target_pseudonym) is None
    ):
        raise SchemaValidationError("report target pseudonym is not portable")
    if not isinstance(state_id, str) or (
        state_id != "unknown"
        and re.fullmatch(r"state-[a-z0-9][a-z0-9-]{1,127}", state_id) is None
    ):
        raise SchemaValidationError("report state identifier is not portable")
    if not isinstance(environment, str) or (
        environment != "unknown"
        and re.fullmatch(r"[a-z][a-z0-9_]{1,63}", environment) is None
    ):
        raise SchemaValidationError("report environment context is not portable")


def _validate_report_extensions(report: dict[str, Any]) -> None:
    extensions = report.get("extensions")
    if not isinstance(extensions, dict):
        return
    allowed = {
        "org.androidtrustlab.adapter",
        "org.androidtrustlab.collection",
        "org.androidtrustlab.comparison-context",
        "org.androidtrustlab.migration",
        "org.androidtrustlab.migration-v3",
        "org.androidtrustlab.migration-v4",
        "org.androidtrustlab.migration-v5",
        "org.androidtrustlab.migration-v6",
    }
    if not set(extensions) <= allowed:
        raise SchemaValidationError("report uses an unportable extension")
    if "org.androidtrustlab.adapter" in extensions:
        _validate_adapter_extension(extensions["org.androidtrustlab.adapter"])
    if "org.androidtrustlab.collection" in extensions:
        _validate_collection_extension(extensions["org.androidtrustlab.collection"])
    if "org.androidtrustlab.comparison-context" in extensions:
        _validate_comparison_context_extension(
            report, extensions["org.androidtrustlab.comparison-context"]
        )
    for key, extension in extensions.items():
        if key.startswith("org.androidtrustlab.migration"):
            _validate_migration_extension(extension)


def _validate_report_metadata(report: dict[str, Any]) -> None:
    experiment_id = report.get("experiment_id")
    if isinstance(experiment_id, str) and not (
        experiment_id in {"unknown", "redacted-experiment"}
        or experiment_id in _PORTABLE_EXPERIMENT_IDS
    ):
        raise SchemaValidationError("report portable experiment identifier is unsafe")
    target = report.get("target")
    if isinstance(target, dict):
        android_version = _evidence_value(target.get("android_version"))
        sdk = _evidence_value(target.get("sdk"))
        if isinstance(android_version, str) and not (
            android_version == "unknown"
            or re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){0,3}", android_version)
            or android_version == "redacted-property"
        ):
            raise SchemaValidationError("report portable Android version is unsafe")
        if isinstance(sdk, str) and not (
            sdk == "unknown" or re.fullmatch(r"[0-9]{1,3}", sdk)
        ):
            raise SchemaValidationError("report portable SDK value is unsafe")
    observer = report.get("observer")
    if isinstance(observer, dict):
        method = observer.get("collection_method")
        if isinstance(method, str) and not (
            method == "redacted-collection-method"
            or method in _PORTABLE_COLLECTION_METHODS
        ):
            raise SchemaValidationError(
                "report portable collection method is not semantic"
            )
    boot = report.get("boot")
    if isinstance(boot, dict):
        reason = _evidence_value(boot.get("boot_reason"))
        if isinstance(reason, str) and reason not in {
            "unknown",
            "redacted-boot-reason",
            "bootloader",
            "cold",
            "hard",
            "kernel_panic",
            "normal",
            "reboot",
            "recovery",
            "shutdown",
            "userrequested",
            "warm",
            "watchdog",
        }:
            raise SchemaValidationError("report portable boot reason is unsafe")
        slot = _evidence_value(boot.get("slot_suffix"))
        if isinstance(slot, str) and slot not in {
            "_a",
            "_b",
            "redacted-property",
            "unknown",
        }:
            raise SchemaValidationError("report portable slot suffix is unsafe")


def _validate_direct_raw_artifacts(report: dict[str, Any]) -> None:
    raw_artifacts = report.get("raw_artifacts", [])
    for artifact in raw_artifacts if isinstance(raw_artifacts, list) else []:
        if not isinstance(artifact, dict):
            continue
        logical_id = artifact.get("logical_id")
        relative_path = artifact.get("relative_path")
        if (
            not isinstance(logical_id, str)
            or re.fullmatch(r"raw-artifact-[0-9]{3}", logical_id) is None
            or relative_path
            not in {
                f"artifacts/{logical_id}.json",
                f"artifacts/{logical_id}.txt",
            }
        ):
            raise SchemaValidationError("report raw artifact reference is not semantic")
        if artifact.get("collector_name") not in {
            "adb",
            "redacted-collector",
            "trustlab",
            "trustlab-magisk",
            "unknown",
        }:
            raise SchemaValidationError("report collector name is not portable")
        if not _portable_collector_version(artifact.get("collector_version")):
            raise SchemaValidationError("report collector version is not portable")


def _observation_value(observation: object) -> object:
    return observation.get("value") if isinstance(observation, dict) else None


def _validate_root_magisk_metadata(report: dict[str, Any]) -> None:
    magisk = report.get("magisk_state")
    if not isinstance(magisk, dict):
        return
    version_name = _observation_value(magisk.get("version_name"))
    if version_name is not None and (
        not isinstance(version_name, str)
        or (
            version_name not in {"redacted-magisk-version-name", "unknown"}
            and _MAGISK_VERSION_NAME_RE.fullmatch(version_name) is None
        )
    ):
        raise SchemaValidationError("report Magisk version name is not portable")
    version_code = _observation_value(magisk.get("version_code"))
    if version_code is not None and (
        not isinstance(version_code, str)
        or re.fullmatch(r"[0-9]{1,12}", version_code) is None
    ):
        raise SchemaValidationError("report Magisk version code is not portable")
    module_context = _observation_value(magisk.get("module_context"))
    if module_context not in {
        None,
        "androidtrustlab",
        "redacted-module-context",
        "unknown",
    }:
        raise SchemaValidationError("report Magisk module context is not portable")


def _validate_report_diagnostics(report: dict[str, Any]) -> None:
    limitations = report.get("limitations", {})
    if isinstance(limitations, dict):
        allowed_error_patterns = (
            re.compile(r"capture issue [0-9]{3} withheld"),
            re.compile(
                r"collection manifest completion status: (?:complete|failed|partial)"
            ),
            re.compile(r"collection warning [0-9]{3} withheld"),
            re.compile(r"missing (?:getprop|mount) section"),
            re.compile(
                r"probe [0-9]{3}: (?:command_error|inaccessible|not_collected|observed_absent|unsupported)"
            ),
        )
        if any(
            not any(pattern.fullmatch(str(error)) for pattern in allowed_error_patterns)
            for error in limitations.get("collection_errors", [])
        ):
            raise SchemaValidationError(
                "report collection diagnostics are not portable"
            )


def _validate_report_provenance(report: dict[str, Any]) -> None:
    provenance = report.get("provenance")
    if not isinstance(provenance, dict):
        return
    for field in ("normalizer", "generator"):
        product = provenance.get(field)
        if not isinstance(product, dict):
            raise SchemaValidationError("report product provenance is not portable")
        expected_names = (
            {"trustlab", "trustlab-migration"} if field == "generator" else {"trustlab"}
        )
        if product.get("name") not in expected_names or not _portable_collector_version(
            product.get("version")
        ):
            raise SchemaValidationError("report product provenance is not portable")
    for migration in provenance.get("migration_history", []):
        implementation = (
            migration.get("implementation") if isinstance(migration, dict) else None
        )
        if (
            not isinstance(implementation, dict)
            or implementation.get("name") != "trustlab-migration"
            or not _portable_collector_version(implementation.get("version"))
        ):
            raise SchemaValidationError("report migration provenance is not portable")
    command_results = provenance.get("command_results", [])
    if not isinstance(command_results, list):
        raise SchemaValidationError("report command provenance is not portable")
    for result in command_results:
        command_id = result.get("command_id") if isinstance(result, dict) else None
        if (
            not isinstance(result, dict)
            or result.get("detail")
            not in {
                None,
                "capture command failed",
                "capture command timed out",
                "capture failed",
                "capture is unsupported",
                "capture was inaccessible",
            }
            or result.get("status")
            not in {
                "command_error",
                "inaccessible",
                "not_collected",
                "observed",
                "observed_absent",
                "unsupported",
            }
            or not isinstance(command_id, str)
            or (
                command_id not in _PORTABLE_CAPTURE_NAMES
                and re.fullmatch(r"artifact-[0-9]{3}", command_id) is None
            )
        ):
            raise SchemaValidationError("report command provenance is not portable")


def validate_portable_report(report: object) -> None:
    """Reject sensitive or identity-bearing content in portable reports."""

    if not isinstance(report, dict):
        return
    direct_v6 = (
        report.get("schema_version") == "6.0.0"
        and isinstance(report.get("provenance"), dict)
        and report["provenance"].get("source_schema_version") == "raw"
    )
    _reject_sensitive_strings(report, artifact="report")
    _validate_identity_fields(report)
    _validate_property_fields(report)
    _validate_report_metadata(report)
    _validate_report_diagnostics(report)
    _validate_root_magisk_metadata(report)
    if report.get("schema_version") == "6.0.0":
        _validate_report_provenance(report)
        _validate_report_extensions(report)
    if direct_v6:
        _validate_direct_raw_artifacts(report)
        _validate_direct_v6_mounts(report)


def validate_portable_historical_report(report: object) -> None:
    """Screen an exact historical source before embedding it in portable v6."""

    if not isinstance(report, dict):
        return
    _reject_sensitive_strings(report, artifact="historical report")
    _validate_identity_fields(report)
    _validate_property_fields(report)
    _validate_report_metadata(report)
    _validate_report_diagnostics(report)
    _validate_root_magisk_metadata(report)
    _validate_report_extensions(report)


_LEGACY_DIFF_DIMENSION_PATHS = {
    "observer_uid_root": "root_state.observer_effective_uid_is_root",
    "observer_privilege": "observer.privilege_level",
}
_DIFF_DIMENSION_PATHS = {
    **{
        definition.id: definition.evidence_paths[0] for definition in DEFAULT_DIMENSIONS
    },
    **_LEGACY_DIFF_DIMENSION_PATHS,
}
_VERIFIED_BOOT_DIFF_DIMENSIONS = frozenset(
    definition.id
    for definition in DEFAULT_DIMENSIONS
    if definition.category == "boot_integrity"
)
_DIFF_SEVERITIES = {
    "bootloader_lock_state": "high",
    "verified_boot_state": "high",
    "vbmeta_state": "high",
    "verity_mode": "high",
    "selinux_mode": "high",
    "selinux_current_context": "medium",
    "selinux_denial_collection": "low",
    "selected_process_visibility": "medium",
    "mount_integrity": "high",
    "system_mount_resolution": "medium",
    "dynamic_partition_state": "low",
    "apex_mount_set": "medium",
    "observer_uid_root": "medium",
    "root_shell_availability": "medium",
    "su_binary_visibility": "medium",
    "su_invocation_tested": "low",
    "su_invocation_result": "medium",
    "root_management_artifact": "medium",
    "magisk_binary_visibility": "medium",
    "magisk_daemon_visibility": "medium",
    "magisk_process_visibility": "medium",
    "zygisk_visibility": "medium",
    "magisk_version_name": "info",
    "magisk_version_code": "info",
    "magisk_module_context": "info",
    "magisk_command_status": "low",
    "property_consistency": "medium",
    "emulator_state": "info",
    "observer_privilege": "info",
}
_DIFF_INTERPRETATIONS = {
    **{definition.id: definition.interpretation for definition in DEFAULT_DIMENSIONS},
    "observer_privilege": "Observer privilege changed, so visibility differences may be caused by privilege boundary rather than target mutation.",
}
_DEFAULT_DIFF_INTERPRETATION = "Trust-state dimension changed between reports."
_DIFF_STATUSES = frozenset(
    {
        "command_error",
        "inaccessible",
        "not_collected",
        "observed",
        "observed_absent",
        "unsupported",
    }
)


def _validate_diff_observation(
    value: object,
    *,
    predicate: Any,
    absent_values: tuple[object, ...] = (None,),
) -> None:
    if not isinstance(value, dict) or set(value) != {"status", "value"}:
        raise SchemaValidationError(
            "diff dimension value is not a portable observation"
        )
    status = value.get("status")
    observed = value.get("value")
    if status not in _DIFF_STATUSES:
        raise SchemaValidationError("diff dimension status is not portable")
    if status == "observed":
        valid = predicate(observed)
    elif status == "observed_absent":
        valid = observed in absent_values
    else:
        valid = observed is None
    if not valid:
        raise SchemaValidationError("diff dimension value contradicts its status")


def _is_string_in(values: frozenset[str]) -> Any:
    return lambda value: isinstance(value, str) and value in values


def _validate_diff_mount_integrity(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "overlay_detected",
        "writable_sensitive_mounts",
    }:
        raise SchemaValidationError("diff mount-integrity value is not portable")
    _validate_diff_observation(
        value["overlay_detected"],
        predicate=lambda item: isinstance(item, bool),
        absent_values=(False,),
    )
    _validate_diff_observation(
        value["writable_sensitive_mounts"],
        predicate=lambda item: (
            isinstance(item, list) and all(path in _SAFE_ANDROID_PATHS for path in item)
        ),
        absent_values=([],),
    )


def _validate_diff_system_resolution(value: object) -> None:
    reasons = {
        "one exact /system mount was observed",
        "multiple exact /system mounts were observed",
        "no /system mount was observed; one root mount is the system root",
        "multiple root mounts were observed without an exact /system mount",
        "partial evidence cannot establish that /system is absent",
        "neither an exact /system mount nor a root mount was observed",
    }
    if (
        not isinstance(value, dict)
        or set(value) != {"reason", "record_indices", "state", "system_root"}
        or value.get("state")
        not in {"ambiguous", "explicit_system", "system_as_root", "unresolved"}
        or value.get("system_root") not in {None, "/", "/system"}
        or value.get("reason") not in reasons
        or not isinstance(value.get("record_indices"), list)
        or not all(
            isinstance(item, int) and 0 <= item <= 4095
            for item in value["record_indices"]
        )
    ):
        raise SchemaValidationError("diff system-mount value is not portable")


def _validate_diff_dynamic_partitions(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"record_indices", "sources", "state"}
        or value.get("state") not in {"detected", "not_detected", "unknown"}
        or not isinstance(value.get("record_indices"), list)
        or not all(
            isinstance(item, int) and 0 <= item <= 4095
            for item in value["record_indices"]
        )
        or not isinstance(value.get("sources"), list)
        or not all(
            source
            in {
                "/dev/block/dm-redacted",
                "/dev/block/mapper/redacted",
                "none",
                "overlay",
                "redacted-mount-source",
                "rootfs",
                "tmpfs",
            }
            for source in value["sources"]
        )
    ):
        raise SchemaValidationError("diff dynamic-partition value is not portable")


def _validate_diff_apex(value: object) -> None:
    count_keys = {
        "bind_count",
        "mount_count",
        "overlay_count",
        "package_count",
        "read_only_count",
        "unknown_access_count",
        "writable_count",
    }
    if (
        not isinstance(value, dict)
        or set(value) != count_keys | {"packages", "record_indices"}
        or any(
            not isinstance(value.get(key), int) or not 0 <= value[key] <= 4096
            for key in count_keys
        )
        or not isinstance(value.get("packages"), list)
        or any(
            re.fullmatch(r"redacted-apex-package-[0-9]{3}", str(package)) is None
            for package in value["packages"]
        )
        or value["package_count"] != len(value["packages"])
        or not isinstance(value.get("record_indices"), list)
        or not all(
            isinstance(item, int) and 0 <= item <= 4095
            for item in value["record_indices"]
        )
    ):
        raise SchemaValidationError("diff APEX value is not portable")


def _validate_diff_processes(value: object) -> None:
    names = ("init", "adbd", "zygote", "zygote64", "system_server", "magisk", "magiskd")
    if not isinstance(value, list) or [
        item.get("name") for item in value if isinstance(item, dict)
    ] != list(names):
        raise SchemaValidationError("diff process value is not portable")
    for item in value:
        if not isinstance(item, dict) or set(item) != {"context", "name", "visibility"}:
            raise SchemaValidationError("diff process value is not portable")
        _validate_diff_observation(
            item["visibility"],
            predicate=lambda current: isinstance(current, bool),
            absent_values=(False,),
        )
        _validate_diff_observation(
            item["context"],
            predicate=lambda current: (
                isinstance(current, str)
                and (
                    current == "redacted-selinux-context"
                    or re.fullmatch(
                        r"u:r:(?:adbd|init|magisk|magiskd|system_server|zygote):s[0-9]+(?:-s[0-9]+)?",
                        current,
                    )
                    is not None
                )
            ),
        )


def _validate_diff_property_group(value: object) -> None:
    def safe_properties(current: object) -> bool:
        if not isinstance(current, dict):
            return False
        for key, property_value in current.items():
            pattern = _PROPERTY_VALUE_PATTERNS.get(str(key))
            if (
                pattern is None
                or not isinstance(property_value, str)
                or not (
                    property_value in {"redacted-property", "unknown"}
                    or pattern.fullmatch(property_value)
                )
            ):
                return False
        return True

    _validate_diff_observation(value, predicate=safe_properties, absent_values=({},))


def _validate_diff_observation_dimension(dimension: str, value: object) -> bool:
    boolean_dimensions = {
        "emulator_state",
        "magisk_binary_visibility",
        "magisk_daemon_visibility",
        "magisk_process_visibility",
        "observer_uid_root",
        "root_management_artifact",
        "root_shell_availability",
        "su_binary_visibility",
        "su_invocation_tested",
        "zygisk_visibility",
    }
    if dimension in boolean_dimensions:
        _validate_diff_observation(
            value,
            predicate=lambda item: isinstance(item, bool),
            absent_values=(False,),
        )
        return True
    allowed_strings = {
        "bootloader_lock_state": frozenset({"0", "1"}),
        "verified_boot_state": frozenset({"green", "orange", "red", "yellow"}),
        "vbmeta_state": frozenset({"locked", "unlocked"}),
        "verity_mode": frozenset({"disabled", "eio", "enforcing", "logging"}),
        "selinux_mode": frozenset({"disabled", "enforcing", "permissive"}),
        "su_invocation_result": frozenset(
            {"denied", "failed", "non_root", "succeeded"}
        ),
        "magisk_module_context": frozenset(
            {"androidtrustlab", "redacted-module-context", "unknown"}
        ),
    }
    if dimension in allowed_strings:
        _validate_diff_observation(
            value, predicate=_is_string_in(allowed_strings[dimension])
        )
        return True
    if dimension == "selinux_current_context":
        _validate_diff_observation(
            value,
            predicate=lambda item: (
                isinstance(item, str)
                and (
                    item == "redacted-selinux-context"
                    or re.fullmatch(r"u:r:[a-z0-9_]+:s[0-9]+(?:-s[0-9]+)?", item)
                    is not None
                )
            ),
        )
        return True
    if dimension == "magisk_version_name":
        _validate_diff_observation(
            value,
            predicate=lambda item: (
                isinstance(item, str)
                and (
                    item == "redacted-magisk-version-name"
                    or _MAGISK_VERSION_NAME_RE.fullmatch(item) is not None
                )
            ),
        )
        return True
    if dimension == "magisk_version_code":
        _validate_diff_observation(
            value,
            predicate=lambda item: (
                isinstance(item, str) and re.fullmatch(r"[0-9]{1,12}", item) is not None
            ),
        )
        return True
    return False


def _validate_diff_status(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"status"}
        or value.get("status") not in _DIFF_STATUSES
    ):
        raise SchemaValidationError("diff status dimension is not portable")


def _validate_diff_privilege(value: object) -> None:
    if value not in {"app_sandbox", "host", "root", "shell"}:
        raise SchemaValidationError("diff observer privilege is not portable")


def _validate_diff_dimension_value(dimension: str, value: object) -> None:
    if _validate_diff_observation_dimension(dimension, value):
        return
    handlers = {
        "apex_mount_set": _validate_diff_apex,
        "dynamic_partition_state": _validate_diff_dynamic_partitions,
        "magisk_command_status": _validate_diff_status,
        "mount_integrity": _validate_diff_mount_integrity,
        "observer_privilege": _validate_diff_privilege,
        "property_consistency": _validate_diff_property_group,
        "selected_process_visibility": _validate_diff_processes,
        "selinux_denial_collection": _validate_diff_status,
        "system_mount_resolution": _validate_diff_system_resolution,
    }
    handler = handlers.get(dimension)
    if handler is None:
        raise SchemaValidationError("diff dimension is not portable")
    handler(value)


def _validate_diff_confidence(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "command_success",
        "corroborating_signal_count",
        "level",
        "observer_capability",
        "source_quality",
        "target_limitations",
    }:
        raise SchemaValidationError("diff confidence value is not portable")
    allowed_limitations = {
        "hardware_attestation_not_collected",
        "historical_factors_unavailable",
        "legacy_capture_status_inferred",
        "observer_capability_limited",
        "virtual_target_not_hardware_backed",
    }
    if (
        value.get("level") not in {"high", "low", "medium", "unassessed"}
        or value.get("source_quality")
        not in {
            "historical_unstructured",
            "legacy_inferred",
            "structured_capture",
            "unavailable",
        }
        or value.get("command_success")
        not in {"complete", "failed", "not_collected", "partial", "unknown"}
        or value.get("observer_capability")
        not in {"app_sandbox", "host", "root", "shell", "unspecified"}
        or not isinstance(value.get("corroborating_signal_count"), int)
        or not 0 <= value["corroborating_signal_count"] <= 64
        or not isinstance(value.get("target_limitations"), list)
        or not set(value["target_limitations"]) <= allowed_limitations
    ):
        raise SchemaValidationError("diff confidence value is not portable")


def _validate_diff_provenance(diff: dict[str, Any]) -> None:
    provenance = diff.get("provenance")
    if not isinstance(provenance, dict):
        raise SchemaValidationError("diff provenance is not portable")
    for side in ("base", "compare"):
        source = provenance.get(side)
        if not isinstance(source, dict):
            raise SchemaValidationError("diff provenance is not portable")
        original_id = source.get("original_report_id")
        if not isinstance(original_id, str) or not (
            re.fullmatch(r"atl-[a-f0-9]{16}", original_id)
            or re.fullmatch(r"atlrep-[a-f0-9]{32}", original_id)
        ):
            raise SchemaValidationError("diff original report identity is not portable")
        for migration in source.get("applied_migrations", []):
            implementation = (
                migration.get("implementation") if isinstance(migration, dict) else None
            )
            if (
                not isinstance(implementation, dict)
                or implementation.get("name") != "trustlab-migration"
                or not _portable_collector_version(implementation.get("version"))
            ):
                raise SchemaValidationError("diff migration provenance is not portable")


def _validate_diff_compatibility_portability(diff: dict[str, Any]) -> None:
    compatibility = diff.get("compatibility")
    if not isinstance(compatibility, dict) or set(compatibility) != {
        "canonical_comparison_schema_version",
        "input_schema_versions",
        "migration_mode",
        "migrations",
        "warnings",
    }:
        raise SchemaValidationError("diff compatibility is not portable")
    versions = compatibility.get("input_schema_versions")
    migrations = compatibility.get("migrations")
    warnings = compatibility.get("warnings")
    readable_report_versions = {
        "1.0.0",
        "2.0.0",
        "3.0.0",
        "4.0.0",
        "5.0.0",
        "6.0.0",
    }
    migration_ids = {
        "report-v1-to-v2",
        "report-v2-to-v3",
        "report-v3-to-v4",
        "report-v4-to-v5",
        "report-v5-to-v6",
    }
    migration_values_portable = isinstance(migrations, dict) and all(
        isinstance(migrations.get(side), list)
        and all(
            isinstance(step, dict)
            and set(step)
            == {
                "migration_id",
                "source_schema_version",
                "target_schema_version",
            }
            and step.get("migration_id") in migration_ids
            and step.get("source_schema_version") in readable_report_versions
            and step.get("target_schema_version") in readable_report_versions
            for step in migrations[side]
        )
        for side in ("base", "compare")
    )
    if (
        compatibility.get("canonical_comparison_schema_version") != "6.0.0"
        or compatibility.get("migration_mode") != "temporary_in_memory"
        or not isinstance(versions, dict)
        or set(versions) != {"base", "compare"}
        or any(version not in readable_report_versions for version in versions.values())
        or not isinstance(migrations, dict)
        or set(migrations) != {"base", "compare"}
        or not migration_values_portable
        or not isinstance(warnings, list)
        or any(
            warning
            not in {
                "base_input_migrated_temporarily_in_memory",
                "compare_input_migrated_temporarily_in_memory",
            }
            for warning in warnings
        )
    ):
        raise SchemaValidationError("diff compatibility is not portable")


def _validate_diff_comparison_portability(diff: dict[str, Any]) -> None:
    comparison = diff.get("comparison")
    if not isinstance(comparison, dict) or set(comparison) != {
        "acknowledgement",
        "axis",
        "comparability",
        "context",
        "reasons",
        "visibility_context_changed",
        "warnings",
    }:
        raise SchemaValidationError("diff comparison classification is not portable")
    reason_fields = {
        "environment_context",
        "experiment",
        "measurement",
        "observer",
        "observer_effective_uid",
        "observer_privilege",
        "protocol",
        "report_schema",
        "state_identity",
        "target_class",
        "target_identity",
    }
    allowed_reasons = {
        f"{field}_{relationship}"
        for field in reason_fields
        for relationship in {"differs", "matches", "missing"}
    }
    context = comparison.get("context")
    context_fields = {
        "environment_context",
        "experiment_id",
        "measurement_id",
        "observer",
        "observer_effective_uid_is_root",
        "observer_privilege",
        "protocol",
        "report_schema_version",
        "state_id",
        "target_class",
        "target_pseudonym",
    }
    contexts_portable = (
        isinstance(context, dict)
        and set(context)
        == {
            "base",
            "compare",
        }
        and all(
            isinstance(context.get(side), dict)
            and set(context[side]) == context_fields
            and all(isinstance(value, str) for value in context[side].values())
            for side in ("base", "compare")
        )
    )
    if (
        comparison.get("axis")
        not in {
            "same_target_state_change",
            "same_state_observer_change",
            "repeat_measurement",
            "different_target_context",
            "mixed_change",
            "incomparable",
        }
        or comparison.get("comparability")
        not in {"comparable", "limited", "incomparable"}
        or comparison.get("acknowledgement") not in {"allow_mixed", "not_required"}
        or not isinstance(comparison.get("visibility_context_changed"), bool)
        or not isinstance(comparison.get("reasons"), list)
        or not set(comparison["reasons"]) <= allowed_reasons
        or not isinstance(comparison.get("warnings"), list)
        or not set(comparison["warnings"])
        <= {
            "different_target_context_limits_attribution",
            "insufficient_metadata_for_comparison",
            "mixed_state_and_observer_change_acknowledged",
            "observer_context_changed_visibility_may_differ",
        }
        or not contexts_portable
    ):
        raise SchemaValidationError("diff comparison classification is not portable")


def _expected_observed_value(value: object, status: str) -> object:
    if not evidence_is_available(status):
        return None
    if isinstance(value, dict) and value.get("status") == status:
        return value.get("value")
    return value


def _validate_structured_signal_portability(
    diff: dict[str, Any],
    changed_by_name: dict[str, dict[str, Any]],
    *,
    field_name: str,
    expected_direction: str,
) -> None:
    signals = diff.get(field_name)
    if not isinstance(signals, list):
        raise SchemaValidationError("diff structured signals are not portable")
    names: list[str] = []
    for signal in signals:
        if not isinstance(signal, dict):
            raise SchemaValidationError("diff structured signal is not portable")
        dimension = signal.get("dimension")
        if not isinstance(dimension, str) or dimension not in changed_by_name:
            raise SchemaValidationError("diff structured signal dimension is invalid")
        names.append(dimension)
        change = changed_by_name[dimension]
        transition = change["transition"]
        before_status = transition["before_status"]
        after_status = transition["after_status"]
        if signal_direction(before_status, after_status) != expected_direction:
            raise SchemaValidationError("diff structured signal direction is invalid")
        expected_transition = {
            "before_status": before_status,
            "after_status": after_status,
            "classification": transition["classification"],
            "confidence_impact": transition["confidence_impact"],
        }
        if any(signal.get(key) != value for key, value in expected_transition.items()):
            raise SchemaValidationError("diff structured signal transition is invalid")
        expected_values = {
            "before": _expected_observed_value(change["before"], before_status),
            "after": _expected_observed_value(change["after"], after_status),
        }
        if signal.get("observed_values") != expected_values:
            raise SchemaValidationError("diff structured signal values are invalid")
        source_evidence = signal.get("source_evidence")
        if not isinstance(source_evidence, dict) or set(source_evidence) != {
            "before",
            "after",
        }:
            raise SchemaValidationError("diff structured signal evidence is invalid")
        for refs in source_evidence.values():
            if (
                not isinstance(refs, list)
                or any(not isinstance(ref, str) for ref in refs)
                or refs != sorted(set(refs))
            ):
                raise SchemaValidationError(
                    "diff structured signal evidence is invalid"
                )
        if signal.get("interpretation") != transition_interpretation(
            before_status,
            after_status,
            transition["classification"],
        ):
            raise SchemaValidationError(
                "diff structured signal interpretation is invalid"
            )
        if diff["schema_version"] == "2.7.0" and any(
            signal.get(key) != change.get(key)
            for key in (
                "materiality",
                "direction",
                "confidence",
                "rationale",
                "evidence_paths",
            )
        ):
            raise SchemaValidationError(
                "diff structured signal assessment is not canonical"
            )
    if len(names) != len(set(names)):
        raise SchemaValidationError("diff structured signals are not unique")


def _validate_diff_assessment(
    diff: dict[str, Any], item: dict[str, Any], dimension: str
) -> None:
    definition = TRUST_DIMENSIONS_BY_ID.get(dimension)
    if definition is None:
        raise SchemaValidationError("current diff dimension is undocumented")
    direction, direction_rationale = direction_assessment(
        definition.direction_rule.policy_id,
        item["before"],
        item["after"],
        transition_class=item["transition"]["classification"],
    )
    if item.get("materiality") != definition.materiality_rule.value:
        raise SchemaValidationError("diff materiality is not canonical")
    if item.get("direction") != direction:
        raise SchemaValidationError("diff direction is not canonical")
    if item.get("rationale") != [
        "materiality_from_dimension_policy",
        direction_rationale,
        "confidence_from_explicit_factors",
    ]:
        raise SchemaValidationError("diff assessment rationale is not canonical")
    confidence = item.get("confidence")
    factors = confidence.get("factors") if isinstance(confidence, dict) else None
    if not isinstance(factors, dict):
        raise SchemaValidationError("diff confidence factors are not canonical")
    expected_migration_count = sum(
        len(diff["compatibility"]["migrations"][side]) for side in ("base", "compare")
    )
    if (
        factors.get("evidence_statuses")
        != {
            "before": item["transition"]["before_status"],
            "after": item["transition"]["after_status"],
        }
        or factors.get("migration_count") != expected_migration_count
        or factors.get("comparability") != diff["comparison"]["comparability"]
        or factors.get("comparability_warning_count")
        != len(diff["comparison"]["warnings"])
    ):
        raise SchemaValidationError("diff confidence factors are not canonical")
    field_confidence = factors.get("field_confidence")
    if not isinstance(field_confidence, dict):
        raise SchemaValidationError("diff field confidence is not canonical")
    if dimension not in _VERIFIED_BOOT_DIFF_DIMENSIONS and field_confidence != {
        "before": "not_available",
        "after": "not_available",
    }:
        raise SchemaValidationError("diff field confidence is not canonical")
    expected_confidence = confidence_assessment(
        before_status=item["transition"]["before_status"],
        after_status=item["transition"]["after_status"],
        before_field_confidence=cast(str, field_confidence.get("before")),
        after_field_confidence=cast(str, field_confidence.get("after")),
        corroborating_evidence_count=cast(
            int, factors.get("corroborating_evidence_count")
        ),
        migration_count=cast(int, factors.get("migration_count")),
        comparability=cast(str, factors.get("comparability")),
        warning_count=cast(int, factors.get("comparability_warning_count")),
    )
    if confidence != expected_confidence:
        raise SchemaValidationError("diff confidence is not canonical")


def _validate_changed_dimensions_portability(
    diff: dict[str, Any], all_dimensions: set[str]
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    schema_version = diff["schema_version"]
    changed = diff.get("changed_dimensions", [])
    changed_names: list[str] = []
    changed_by_name: dict[str, dict[str, Any]] = {}
    for item in changed if isinstance(changed, list) else []:
        if not isinstance(item, dict):
            raise SchemaValidationError("diff changed dimension is not portable")
        dimension = item.get("dimension")
        if not isinstance(dimension, str) or dimension not in all_dimensions:
            raise SchemaValidationError("diff dimension is not portable")
        changed_names.append(dimension)
        changed_by_name[dimension] = item
        if item.get("evidence_paths") != [_DIFF_DIMENSION_PATHS[dimension]] or item.get(
            "interpretation"
        ) != _DIFF_INTERPRETATIONS.get(dimension, _DEFAULT_DIFF_INTERPRETATION):
            raise SchemaValidationError("diff dimension metadata is not canonical")
        if (
            schema_version != "2.7.0"
            and item.get("severity") != _DIFF_SEVERITIES[dimension]
        ):
            raise SchemaValidationError("diff dimension metadata is not canonical")
        _validate_diff_dimension_value(dimension, item.get("before"))
        _validate_diff_dimension_value(dimension, item.get("after"))
        if schema_version in {"2.6.0", "2.7.0"}:
            before_status = evidence_status(item.get("before"))
            after_status = evidence_status(item.get("after"))
            expected_transition = {
                "before_status": before_status,
                "after_status": after_status,
                "classification": classify_status_transition(
                    before_status,
                    after_status,
                    comparison_axis=diff["comparison"]["axis"],
                ),
                "confidence_impact": confidence_impact(before_status, after_status),
            }
            if item.get("transition") != expected_transition:
                raise SchemaValidationError("diff status transition is not canonical")
        if schema_version == "2.7.0":
            _validate_diff_assessment(diff, item, dimension)
    if len(changed_names) != len(set(changed_names)):
        raise SchemaValidationError("diff changed dimensions are not unique")
    return changed_names, changed_by_name


def _validate_diff_dimensions_portability(diff: dict[str, Any]) -> None:
    all_dimensions = set(_DIFF_DIMENSION_PATHS)
    schema_version = diff.get("schema_version")
    if schema_version in {"2.5.0", "2.6.0", "2.7.0"}:
        all_dimensions -= {"observer_privilege", "observer_uid_root"}
    changed_names, changed_by_name = _validate_changed_dimensions_portability(
        diff, all_dimensions
    )
    unchanged = diff.get("unchanged_dimensions", [])
    for field in (unchanged,):
        if not isinstance(field, list) or not set(field) <= all_dimensions:
            raise SchemaValidationError("diff signal list is not portable")
    if schema_version in {"2.6.0", "2.7.0"}:
        _validate_structured_signal_portability(
            diff,
            changed_by_name,
            field_name="new_signals",
            expected_direction="new",
        )
        _validate_structured_signal_portability(
            diff,
            changed_by_name,
            field_name="missing_signals",
            expected_direction="missing",
        )
    else:
        for field in (diff.get("new_signals", []), diff.get("missing_signals", [])):
            if not isinstance(field, list) or not set(field) <= all_dimensions:
                raise SchemaValidationError("diff signal list is not portable")
    if set(changed_names) & set(unchanged):
        raise SchemaValidationError("diff changed and unchanged dimensions overlap")
    if (
        schema_version in {"2.5.0", "2.6.0", "2.7.0"}
        and (set(changed_names) | set(unchanged)) != all_dimensions
    ):
        raise SchemaValidationError(
            "diff target-state dimensions do not form a complete partition"
        )
    expected_summary = f"{len(changed_names)} dimensions changed, {len(unchanged)} dimensions unchanged."
    if schema_version in {"2.6.0", "2.7.0"}:
        expected_summary = (
            f"{len(changed_names)} dimensions changed, {len(unchanged)} dimensions "
            f"unchanged; {len(diff['new_signals'])} signals became available, "
            f"{len(diff['missing_signals'])} signals became unavailable."
        )
    if diff.get("summary") != expected_summary:
        raise SchemaValidationError("diff summary is not canonical")
    for item in diff.get("confidence_changes", []):
        if not isinstance(item, dict) or item.get("path") != "verified_boot.confidence":
            raise SchemaValidationError("diff confidence path is not portable")
        _validate_diff_confidence(item.get("before"))
        _validate_diff_confidence(item.get("after"))


def validate_portable_diff(diff: object) -> None:
    """Reject sensitive or non-semantic values before portable diff output."""

    _reject_sensitive_strings(diff, artifact="diff")
    if not isinstance(diff, dict) or diff.get("schema_version") not in {
        "2.3.0",
        "2.4.0",
        "2.5.0",
        "2.6.0",
        "2.7.0",
    }:
        return
    _validate_diff_provenance(diff)
    if diff.get("schema_version") in {"2.4.0", "2.5.0", "2.6.0", "2.7.0"}:
        _validate_diff_compatibility_portability(diff)
    if diff.get("schema_version") in {"2.5.0", "2.6.0", "2.7.0"}:
        _validate_diff_comparison_portability(diff)
    _validate_diff_dimensions_portability(diff)


def _validate_manifest_identity_fields(manifest: dict[str, Any]) -> None:
    if manifest.get("experiment_id") not in _PORTABLE_EXPERIMENT_IDS | {"unknown"}:
        raise SchemaValidationError(
            "collection manifest experiment identifier is not semantic"
        )
    collector = manifest.get("collector", {})
    observer = manifest.get("observer", {})
    environment = manifest.get("environment", {})
    collector_name = collector.get("name") if isinstance(collector, dict) else None
    if collector_name not in {
        "trustlab-adb",
        "trustlab-app",
        "trustlab-fixture",
        "trustlab-host",
        "trustlab-magisk",
    }:
        raise SchemaValidationError(
            "collection manifest collector name is not semantic"
        )
    if not _portable_collector_version(
        collector.get("version") if isinstance(collector, dict) else None
    ):
        raise SchemaValidationError(
            "collection manifest collector version is not portable"
        )
    if isinstance(observer, dict):
        method = observer.get("collection_method")
        methods_by_collector = {
            "trustlab-host": {"host_snapshot"},
            "trustlab-adb": {"adb_shell_snapshot", "adb_snapshot"},
            "trustlab-app": {"app_snapshot"},
            "trustlab-magisk": {"magisk_module_boot", "magisk_module_manual"},
            "trustlab-fixture": {
                "fixture_snapshot",
                "manual_fixture",
                "test_fixture",
            },
        }
        if method not in methods_by_collector.get(str(collector_name), set()):
            raise SchemaValidationError("collection manifest method is not semantic")
    contexts_by_collector = {
        "trustlab-host": {"host_collector"},
        "trustlab-adb": {"adb_collector"},
        "trustlab-app": {"app_collector"},
        "trustlab-magisk": {"magisk_collector", "magisk_module"},
        "trustlab-fixture": {"test_fixture"},
    }
    if not isinstance(environment, dict) or environment.get(
        "execution_context"
    ) not in contexts_by_collector.get(str(collector_name), set()):
        raise SchemaValidationError(
            "collection manifest execution context is not semantic"
        )


def _validate_manifest_tools(manifest: dict[str, Any]) -> None:
    tool_versions = manifest.get("tool_versions", {})
    if isinstance(tool_versions, dict):
        allowed_tools = {
            "adb",
            "android_shell",
            "avdmanager",
            "emulator",
            "ps",
            "python",
            "sdkmanager",
            "trustlab_fixture",
            "trustlab_host",
            "trustlab_magisk",
        }
        for name, version in tool_versions.items():
            if (
                name not in allowed_tools
                or not isinstance(version, str)
                or not (
                    version in {"toolbox", "toybox", "unknown"}
                    or _PORTABLE_VERSION_RE.fullmatch(version)
                    or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9]+)?", version)
                )
            ):
                raise SchemaValidationError(
                    "collection manifest tool version is not portable"
                )


def _validate_manifest_artifact_bindings(manifest: dict[str, Any]) -> None:
    collector = manifest.get("collector", {})
    collector_name = collector.get("name") if isinstance(collector, dict) else None
    adb_capture_names = {
        "device_selection",
        "target_state",
        "identity",
        "getenforce",
        "mountinfo",
        "proc_mounts",
        "selinux_context",
        "ps_selected",
        "ps_selected_fallback",
        *{
            f"property_{key.replace('.', '_')}"
            for key in {
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
        },
    }
    magisk_capture_bindings = {
        "boot_completion": ("captures/boot_completion.txt", "magisk.boot_completion"),
        "boot_state": ("captures/boot_state.txt", "magisk.boot_state"),
        "properties": ("captures/properties.txt", "magisk.properties"),
        "mounts": ("captures/mounts.txt", "magisk.mounts"),
        "selinux": ("captures/selinux.txt", "magisk.selinux"),
        "root_state": ("captures/root_state.txt", "magisk.root_state"),
        "magisk_state": ("captures/magisk_state.txt", "magisk.magisk_state"),
        "process_state": ("captures/process_state.txt", "magisk.process_state"),
    }
    for artifact in manifest.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        logical_name = artifact.get("logical_name")
        probe_id = artifact.get("probe_id")
        relative_path = artifact.get("relative_path")
        safe_probe_ids = {
            f"{prefix}.{suffix}"
            for prefix in {"adb", "app", "fixture", "host", "magisk"}
            for suffix in {
                "command_results",
                "other_observed_artifact",
                "raw_report",
                "readonly_snapshot",
            }
        }
        if logical_name == "raw_report":
            status = artifact.get("status")
            allowed_raw_path = (
                relative_path
                in {
                    "empty_raw.txt",
                    "moved/raw_sample.txt",
                    "raw_sample.txt",
                }
                or (
                    collector_name == "trustlab-adb"
                    and relative_path == "adb_snapshot.txt"
                )
                or (collector_name == "trustlab-magisk" and relative_path == "raw.txt")
            )
            valid = (
                probe_id in safe_probe_ids
                and str(probe_id).endswith((".raw_report", ".readonly_snapshot"))
                and artifact.get("media_type") in {"application/json", "text/plain"}
                and (
                    (status in {"observed", "observed_absent"} and allowed_raw_path)
                    or (
                        status not in {"observed", "observed_absent"}
                        and relative_path is None
                    )
                )
            )
        elif logical_name == "command_results":
            is_host_capture = collector_name == "trustlab-host"
            is_adb_capture = collector_name == "trustlab-adb"
            is_magisk_capture = collector_name == "trustlab-magisk"
            valid = (
                probe_id in safe_probe_ids
                and str(probe_id).endswith(".command_results")
                and artifact.get("media_type") == "application/json"
                and (
                    (
                        is_host_capture
                        and relative_path == "host_provenance.json"
                        and artifact.get("status") == "observed"
                    )
                    or (
                        is_adb_capture
                        and relative_path == "adb_provenance.json"
                        and artifact.get("status") == "observed"
                    )
                    or (
                        is_magisk_capture
                        and relative_path == "command_results.json"
                        and artifact.get("status") == "observed"
                    )
                    or relative_path is None
                )
            )
        elif collector_name == "trustlab-magisk" and logical_name == "collector_log":
            valid = (
                relative_path == "collector.log"
                and probe_id == "magisk.collector_log"
                and artifact.get("media_type") == "text/plain"
                and artifact.get("status") == "observed"
            )
        elif (
            collector_name == "trustlab-magisk"
            and logical_name in magisk_capture_bindings
        ):
            expected_path, expected_probe_id = magisk_capture_bindings[
                str(logical_name)
            ]
            status = artifact.get("status")
            valid = (
                probe_id == expected_probe_id
                and artifact.get("media_type") == "text/plain"
                and (
                    (status == "observed" and relative_path == expected_path)
                    or (status != "observed" and relative_path is None)
                )
            )
        elif collector_name == "trustlab-adb" and logical_name in adb_capture_names:
            status = artifact.get("status")
            expected_probe_id = (
                "adb.property." + str(logical_name).removeprefix("property_")
                if str(logical_name).startswith("property_")
                else f"adb.{logical_name}"
            )
            valid = (
                probe_id == expected_probe_id
                and artifact.get("media_type") == "text/plain"
                and (
                    (
                        status == "observed"
                        and relative_path == f"captures/{logical_name}.txt"
                    )
                    or (status != "observed" and relative_path is None)
                )
            )
        elif logical_name == "other_observed_artifact":
            valid = (
                relative_path == "other_artifact.json"
                and probe_id == "magisk.other_observed_artifact"
                and artifact.get("media_type") == "application/json"
            )
        else:
            valid = False
        if not valid or artifact.get("detail") is not None:
            raise SchemaValidationError(
                "collection manifest artifact binding is not semantic"
            )
    policy = manifest.get("redaction_policy")
    if not isinstance(policy, dict) or policy.get("policy_id") != "atl_portable_v1":
        raise SchemaValidationError(
            "collection manifest redaction policy is not semantic"
        )


def validate_portable_collection_manifest(manifest: object) -> None:
    """Apply field-aware portability checks to collection manifests."""

    if not isinstance(manifest, dict):
        return
    _reject_sensitive_strings(manifest, artifact="collection manifest")
    _validate_manifest_identity_fields(manifest)
    _validate_manifest_tools(manifest)
    _validate_manifest_artifact_bindings(manifest)
