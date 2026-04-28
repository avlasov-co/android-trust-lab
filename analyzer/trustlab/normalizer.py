"""Normalize parsed Android Trust Lab artifacts into the report schema."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
import hashlib

from .parser import parse_raw_report

SENSITIVE_MOUNTS = {
    "/system": "system_mount",
    "/vendor": "vendor_mount",
    "/product": "product_mount",
    "/system_ext": "system_ext_mount",
    "/odm": "odm_mount",
    "/data": "data_mount",
    "/apex": "apex_mount",
}

PROPERTY_GROUP_PREFIXES = {
    "boot": "ro.boot.",
    "build": "ro.build.",
    "product": "ro.product.",
    "crypto": "ro.crypto.",
}

SECURITY_PROPERTIES = ["ro.debuggable", "ro.secure", "ro.adb.secure", "sys.boot_completed"]


def unknown_mount(path: str) -> Dict[str, Any]:
    return {
        "mount_point": path,
        "fs_type": "unknown",
        "options": [],
        "classification": "unknown",
        "raw": "",
    }


def select_mount(mounts: List[Dict[str, Any]], mount_point: str) -> Dict[str, Any]:
    exact = [m for m in mounts if m.get("mount_point") == mount_point]
    if exact:
        return exact[-1]
    nested = [m for m in mounts if str(m.get("mount_point", "")).startswith(mount_point + "/")]
    if nested:
        return nested[-1]
    return unknown_mount(mount_point)


def normalize_properties(props: Dict[str, str]) -> Dict[str, Any]:
    grouped: Dict[str, Any] = {}
    for group, prefix in PROPERTY_GROUP_PREFIXES.items():
        grouped[group] = {key: value for key, value in props.items() if key.startswith(prefix)}
    grouped["security"] = {key: props.get(key, "unknown") for key in SECURITY_PROPERTIES}
    grouped["all_count"] = len(props)
    return grouped


def normalize_selinux(mode: str) -> Dict[str, Any]:
    normalized = mode if mode in {"enforcing", "permissive", "disabled", "unknown", "inaccessible"} else "unknown"
    return {
        "mode": normalized,
        "policy_visible": normalized not in {"unknown", "inaccessible"},
        "denials_collected": False,
    }


def detect_emulator(props: Dict[str, str], target_type: str) -> Dict[str, Any]:
    fingerprint = props.get("ro.build.fingerprint", "").lower()
    model = props.get("ro.product.model", "").lower()
    manufacturer = props.get("ro.product.manufacturer", "").lower()
    indicators = []
    for key, value in {
        "fingerprint": fingerprint,
        "model": model,
        "manufacturer": manufacturer,
        "ro.kernel.qemu": props.get("ro.kernel.qemu", ""),
        "ro.boot.qemu": props.get("ro.boot.qemu", ""),
    }.items():
        val = str(value).lower()
        if any(token in val for token in ["generic", "emulator", "sdk_gphone", "goldfish", "ranchu"]) or val == "1":
            indicators.append(key)
    is_emulator = target_type == "avd" or bool(indicators)
    return {"is_emulator": is_emulator, "indicators": sorted(set(indicators))}


def normalize_mounts(mounts: List[Dict[str, Any]]) -> Dict[str, Any]:
    result = {field: select_mount(mounts, path) for path, field in SENSITIVE_MOUNTS.items()}
    result["overlay_detected"] = any(m.get("classification") == "overlay" for m in mounts)
    writable = []
    for path, field in SENSITIVE_MOUNTS.items():
        mount = result[field]
        options = set(mount.get("options", []))
        if path != "/data" and (mount.get("classification") in {"read-write", "overlay"} or "rw" in options):
            writable.append(path)
    result["writable_sensitive_mounts"] = writable
    result["integrity_summary"] = {
        "overlay_detected": result["overlay_detected"],
        "writable_sensitive_mounts": writable,
    }
    return result


def root_state(parsed: Dict[str, Any]) -> Dict[str, Any]:
    identity = parsed.get("id", {})
    uid = str(identity.get("uid", "unknown"))
    gid = str(identity.get("gid", "unknown"))
    su_paths = parsed.get("su_paths", [])
    su_present = bool(su_paths) or uid == "0"
    return {
        "su_present": su_present,
        "uid": uid,
        "gid": gid,
        "root_shell_available": uid == "0",
        "root_paths": su_paths,
    }


def magisk_state(parsed: Dict[str, Any]) -> Dict[str, Any]:
    raw = parsed.get("magisk", "") or ""
    lower = raw.lower()
    present = "magisk" in lower and "not found" not in lower
    version = "unknown"
    path = "unknown"
    indicators = []
    for line in raw.splitlines():
        clean = line.strip()
        if not clean:
            continue
        lowered = clean.lower()
        if lowered.startswith("magisk_version="):
            version = clean.split("=", 1)[1].strip()
        elif "version" in lowered:
            version = clean.split(":", 1)[-1].strip() if ":" in clean else clean
        if lowered.startswith("magisk_path="):
            path = clean.split("=", 1)[1].strip()
        elif not lowered.startswith("magisk_data_path=") and ("/magisk" in lowered or clean.endswith("magisk")):
            path = clean
        if "zygisk" in lowered:
            indicators.append(clean)
    return {
        "magisk_binary_present": present,
        "magisk_version": version,
        "magisk_path": path,
        "zygisk_visible_indicators": indicators,
        "module_context": "androidtrustlab" if "androidtrustlab" in lower else "unknown",
    }


def _lookup_with_boot_fallback(props: Dict[str, str], boot_state: Dict[str, str], key: str) -> str:
    return props.get(key) or boot_state.get(key) or "unknown"


def verified_boot_state(props: Dict[str, str], target_type: str, boot_state: Dict[str, str] | None = None) -> Dict[str, Any]:
    boot_state = boot_state or {}
    raw_keys = [
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state",
        "ro.boot.veritymode",
    ]
    raw = {key: _lookup_with_boot_fallback(props, boot_state, key) for key in raw_keys}
    return {
        "verified_boot_state": raw["ro.boot.verifiedbootstate"],
        "flash_locked": raw["ro.boot.flash.locked"],
        "vbmeta_device_state": raw["ro.boot.vbmeta.device_state"],
        "verity_mode": raw["ro.boot.veritymode"],
        "raw_properties": raw,
        "confidence": "low" if target_type == "avd" else "medium",
    }


def build_report(
    parsed: Dict[str, Any],
    *,
    experiment_id: str = "unknown",
    target_type: str = "unknown",
    observer_type: str = "adb_shell",
    collection_method: str = "raw_artifact",
    raw_artifact: str = "unknown",
    collection_timestamp: str | None = None,
) -> Dict[str, Any]:
    props = parsed.get("properties", {})
    boot_state_raw = parsed.get("boot_state_raw", {}) or {}
    mounts = parsed.get("mounts", [])
    timestamp = collection_timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    rid_source = f"{experiment_id}:{observer_type}:{timestamp}:{raw_artifact}"
    report_id = "atl-" + hashlib.sha256(rid_source.encode()).hexdigest()[:16]
    cmdline = parsed.get("cmdline", "") or boot_state_raw.get("kernel_cmdline", "") or ""
    emulator = detect_emulator(props, target_type)
    collection_errors = []
    if not props:
        collection_errors.append("missing getprop section")
    if not mounts:
        collection_errors.append("missing mount section")

    return {
        "report_id": report_id,
        "schema_version": "1.0.0",
        "collection_timestamp": timestamp,
        "experiment_id": experiment_id,
        "target": {
            "target_type": target_type,
            "device_codename": props.get("ro.product.device", "unknown"),
            "manufacturer": props.get("ro.product.manufacturer", "unknown"),
            "model": props.get("ro.product.model", "unknown"),
            "android_version": props.get("ro.build.version.release", "unknown"),
            "sdk": props.get("ro.build.version.sdk", "unknown"),
            "build_fingerprint": props.get("ro.build.fingerprint", "unknown"),
        },
        "observer": {
            "observer_type": observer_type,
            "privilege_level": "root" if observer_type == "root_collector" else ("shell" if observer_type == "adb_shell" else observer_type),
            "collection_method": collection_method,
        },
        "boot_state": {
            "boot_completed": props.get("sys.boot_completed", boot_state_raw.get("sys.boot_completed", "unknown")),
            "boot_reason": props.get("ro.boot.bootreason", props.get("sys.boot.reason", boot_state_raw.get("ro.boot.bootreason", "unknown"))),
            "slot_suffix": props.get("ro.boot.slot_suffix", boot_state_raw.get("ro.boot.slot_suffix", "unknown")),
            "kernel_cmdline_present": bool(cmdline.strip()),
        },
        "verified_boot": verified_boot_state(props, target_type, boot_state_raw),
        "selinux": normalize_selinux(parsed.get("selinux_mode", "unknown")),
        "mounts": normalize_mounts(mounts),
        "properties": normalize_properties(props),
        "root_state": root_state(parsed),
        "magisk_state": magisk_state(parsed),
        "process_state": parsed.get("processes", {}),
        "emulator_state": emulator,
        "limitations": {
            "emulator_target": bool(emulator["is_emulator"]),
            "missing_real_bootloader": target_type != "physical",
            "missing_tee_validation": True,
            "incomplete_permissions": observer_type not in {"root_collector"},
            "collection_errors": collection_errors,
        },
        "raw_artifacts": [raw_artifact],
    }


def normalize_raw_file(
    input_path: str | Path,
    *,
    experiment_id: str = "unknown",
    target_type: str = "unknown",
    observer_type: str = "adb_shell",
    collection_method: str = "raw_artifact",
    collection_timestamp: str | None = None,
    raw_artifact_ref: str | None = None,
) -> Dict[str, Any]:
    parsed = parse_raw_report(input_path)
    stable_raw_artifact = raw_artifact_ref if raw_artifact_ref is not None else str(input_path)
    return build_report(
        parsed,
        experiment_id=experiment_id,
        target_type=target_type,
        observer_type=observer_type,
        collection_method=collection_method,
        raw_artifact=stable_raw_artifact,
        collection_timestamp=collection_timestamp,
    )
