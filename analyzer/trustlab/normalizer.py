"""Normalize parsed Android Trust Lab artifacts into the report schema."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .exceptions import (
    CollectionError,
    MissingFileError,
    NormalizationError,
    safe_path_label,
)
from .observers import observer_spec
from .parser import parse_raw_report
from .report_v2 import report_v2_from_v1_shape

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

SECURITY_PROPERTIES = [
    "ro.debuggable",
    "ro.secure",
    "ro.adb.secure",
    "sys.boot_completed",
]
REPORTABLE_PROPERTY_KEYS = frozenset(
    {
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
    }
)


def unknown_mount(path: str) -> dict[str, Any]:
    return {
        "mount_point": path,
        "fs_type": "unknown",
        "options": [],
        "classification": "unknown",
        "raw": "",
    }


def select_mount(mounts: list[dict[str, Any]], mount_point: str) -> dict[str, Any]:
    exact = [m for m in mounts if m.get("mount_point") == mount_point]
    if exact:
        return exact[-1]
    nested = [
        m for m in mounts if str(m.get("mount_point", "")).startswith(mount_point + "/")
    ]
    if nested:
        return nested[-1]
    return unknown_mount(mount_point)


def normalize_properties(props: dict[str, str]) -> dict[str, Any]:
    grouped: dict[str, Any] = {}
    for group, prefix in PROPERTY_GROUP_PREFIXES.items():
        grouped[group] = {
            key: value
            for key, value in props.items()
            if key.startswith(prefix) and key in REPORTABLE_PROPERTY_KEYS
        }
    grouped["security"] = {
        key: props[key] for key in SECURITY_PROPERTIES if key in props
    }
    grouped["all_count"] = len(props)
    return grouped


def normalize_selinux(mode: str) -> dict[str, Any]:
    normalized = (
        mode
        if mode in {"enforcing", "permissive", "disabled", "unknown", "inaccessible"}
        else "unknown"
    )
    return {
        "mode": normalized,
        "policy_visible": normalized not in {"unknown", "inaccessible"},
        "denials_collected": False,
    }


def detect_emulator(props: dict[str, str], target_type: str) -> dict[str, Any]:
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
        if (
            any(
                token in val
                for token in ["generic", "emulator", "sdk_gphone", "goldfish", "ranchu"]
            )
            or val == "1"
        ):
            indicators.append(key)
    is_emulator = target_type == "avd" or bool(indicators)
    return {"is_emulator": is_emulator, "indicators": sorted(set(indicators))}


def normalize_mounts(mounts: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {
        field: select_mount(mounts, path) for path, field in SENSITIVE_MOUNTS.items()
    }
    result["overlay_detected"] = any(
        m.get("classification") == "overlay" for m in mounts
    )
    writable = []
    for path, field in SENSITIVE_MOUNTS.items():
        mount = result[field]
        options = set(mount.get("options", []))
        if path != "/data" and (
            mount.get("classification") in {"read-write", "overlay"} or "rw" in options
        ):
            writable.append(path)
    result["writable_sensitive_mounts"] = writable
    result["integrity_summary"] = {
        "overlay_detected": result["overlay_detected"],
        "writable_sensitive_mounts": writable,
    }
    return result


def root_state(parsed: dict[str, Any]) -> dict[str, Any]:
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


def magisk_state(parsed: dict[str, Any]) -> dict[str, Any]:
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
        elif not lowered.startswith("magisk_data_path=") and (
            "/magisk" in lowered or clean.endswith("magisk")
        ):
            path = clean
        if "zygisk" in lowered:
            indicators.append(clean)
    return {
        "magisk_binary_present": present,
        "magisk_version": version,
        "magisk_path": path,
        "zygisk_visible_indicators": indicators,
        "module_context": "androidtrustlab"
        if "androidtrustlab" in lower
        else "unknown",
    }


def _lookup_with_boot_fallback(
    props: dict[str, str], boot_state: dict[str, str], key: str
) -> str:
    return props.get(key) or boot_state.get(key) or "unknown"


def verified_boot_state(
    props: dict[str, str], target_type: str, boot_state: dict[str, str] | None = None
) -> dict[str, Any]:
    boot_state = boot_state or {}
    raw_keys = [
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state",
        "ro.boot.veritymode",
    ]
    values = {
        key: _lookup_with_boot_fallback(props, boot_state, key) for key in raw_keys
    }
    raw = {key: values[key] for key in raw_keys if key in props or key in boot_state}
    return {
        "verified_boot_state": values["ro.boot.verifiedbootstate"],
        "flash_locked": values["ro.boot.flash.locked"],
        "vbmeta_device_state": values["ro.boot.vbmeta.device_state"],
        "verity_mode": values["ro.boot.veritymode"],
        "raw_properties": raw,
        "confidence": "low" if target_type == "avd" else "medium",
    }


def build_report(
    parsed: dict[str, Any],
    *,
    experiment_id: str = "unknown",
    target_type: str = "unknown",
    observer_type: str = "adb_shell",
    collection_method: str = "raw_artifact",
    raw_artifact: str = "unknown",
    report_id_material: str | None = None,
    collection_timestamp: str | None = None,
) -> dict[str, Any]:
    observer = observer_spec(observer_type)
    props = parsed.get("properties", {})
    boot_state_raw = parsed.get("boot_state_raw", {}) or {}
    mounts = parsed.get("mounts", [])
    timestamp = collection_timestamp or datetime.now(UTC).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    identifier_material = report_id_material or raw_artifact
    rid_source = (
        f"{experiment_id}:{observer.observer_id}:{timestamp}:{identifier_material}"
    )
    report_id = "atl-" + hashlib.sha256(rid_source.encode()).hexdigest()[:16]
    cmdline = (
        parsed.get("cmdline", "") or boot_state_raw.get("kernel_cmdline", "") or ""
    )
    emulator = detect_emulator(props, target_type)
    collection_errors = []
    if not props:
        collection_errors.append("missing getprop section")
    if not mounts:
        collection_errors.append("missing mount section")

    section_names = set(parsed.get("section_names", []))

    def section_was_collected(*names: str) -> bool:
        return bool(section_names.intersection(names))

    observed_probes = frozenset(
        probe
        for probe, observed in {
            "properties": section_was_collected("GETPROP", "PROPS"),
            "boot_state": section_was_collected("BOOT_STATE"),
            "mounts": section_was_collected("MOUNT", "MOUNTS"),
            "identity": section_was_collected("ID"),
            "selinux": section_was_collected("GETENFORCE", "SELINUX"),
            "cmdline": section_was_collected("CMDLINE", "BOOT_STATE"),
            "su_paths": section_was_collected("SU_PATHS"),
            "magisk": section_was_collected("MAGISK"),
            "processes": section_was_collected("PS", "PROCESSES"),
            "emulator_basis": section_was_collected("GETPROP", "PROPS")
            or target_type in {"avd", "physical"},
        }.items()
        if observed
    )

    legacy_shape = {
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
            "observer_type": observer.observer_id,
            "privilege_level": observer.privilege_level,
            "collection_method": collection_method,
        },
        "boot_state": {
            "boot_completed": props.get(
                "sys.boot_completed",
                boot_state_raw.get("sys.boot_completed", "unknown"),
            ),
            "boot_reason": props.get(
                "ro.boot.bootreason",
                props.get(
                    "sys.boot.reason",
                    boot_state_raw.get("ro.boot.bootreason", "unknown"),
                ),
            ),
            "slot_suffix": props.get(
                "ro.boot.slot_suffix",
                boot_state_raw.get("ro.boot.slot_suffix", "unknown"),
            ),
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
            "incomplete_permissions": observer.privilege_level != "root",
            "collection_errors": collection_errors,
        },
        "raw_artifacts": [raw_artifact],
    }
    return report_v2_from_v1_shape(
        legacy_shape,
        preserve_legacy_source=False,
        observed_probes=observed_probes,
    )


def normalize_raw_file(
    input_path: str | Path,
    *,
    experiment_id: str = "unknown",
    target_type: str = "unknown",
    observer_type: str = "adb_shell",
    collection_method: str = "raw_artifact",
    collection_timestamp: str | None = None,
    raw_artifact_ref: str | None = None,
) -> dict[str, Any]:
    observer_spec(observer_type)
    source = Path(input_path)
    label = safe_path_label(source)
    try:
        parsed = parse_raw_report(source)
    except FileNotFoundError as exc:
        raise MissingFileError(f"input file not found: {label}") from exc
    except UnicodeDecodeError as exc:
        raise CollectionError(f"input artifact is not valid UTF-8: {label}") from exc
    except OSError as exc:
        raise CollectionError(f"could not read input artifact: {label}") from exc
    except (TypeError, ValueError) as exc:
        raise NormalizationError(
            f"could not normalize input artifact: {label}"
        ) from exc
    stable_raw_artifact = raw_artifact_ref if raw_artifact_ref is not None else label
    report_id_material = stable_raw_artifact
    if raw_artifact_ref is None:
        canonical_evidence = json.dumps(
            parsed,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        evidence_digest = hashlib.sha256(
            canonical_evidence.encode("utf-8", errors="surrogatepass")
        ).hexdigest()
        report_id_material = f"{label}:sha256:{evidence_digest}"
    return build_report(
        parsed,
        experiment_id=experiment_id,
        target_type=target_type,
        observer_type=observer_type,
        collection_method=collection_method,
        raw_artifact=stable_raw_artifact,
        report_id_material=report_id_material,
        collection_timestamp=collection_timestamp,
    )
