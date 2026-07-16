"""Normalize parsed Android Trust Lab artifacts into the report schema."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .bounded_io import read_bounded_regular_file
from .canonical_json import MAX_CANONICAL_BYTES, canonical_json_bytes
from .collection_manifest import (
    ArtifactEntry,
    CollectionManifest,
    read_collection_manifest,
    verify_collection_artifacts,
)
from .compatibility import EvidenceStatus
from .exceptions import (
    CollectionError,
    NormalizationError,
    safe_path_label,
)
from .identity import (
    RawArtifactReference,
    collection_event_identity,
    derive_collection_id,
    finalize_report_identity,
    make_raw_artifact_reference,
)
from .observers import observer_spec
from .parser import parse_raw_text
from .report_v2 import report_v2_from_v1_shape
from .report_v3 import report_v3_from_v2_shape

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
MAX_RAW_ARTIFACT_BYTES = MAX_CANONICAL_BYTES


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
    raw_artifact: RawArtifactReference,
    collection_event_id: str,
    collection_timestamp: str,
    generator_name: str = "trustlab",
) -> dict[str, Any]:
    observer = observer_spec(observer_type)
    props = parsed.get("properties", {})
    boot_state_raw = parsed.get("boot_state_raw", {}) or {}
    mounts = parsed.get("mounts", [])
    timestamp = collection_timestamp
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
        "report_id": "atl-" + "0" * 16,
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
        "raw_artifacts": [raw_artifact.relative_path],
    }
    report_v2 = report_v2_from_v1_shape(
        legacy_shape,
        preserve_legacy_source=False,
        observed_probes=observed_probes,
    )
    return report_v3_from_v2_shape(
        report_v2,
        raw_artifacts=[raw_artifact],
        collection_event_id=collection_event_id,
        source_schema_version="raw",
        generator_name=generator_name,
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
    raw_artifact_id: str | None = None,
    collector_name: str = "unknown",
    collector_version: str = "unknown",
    collection_id: str | None = None,
    redaction_state: str = "unknown",
) -> dict[str, Any]:
    observer_spec(observer_type)
    source = Path(input_path)
    label = safe_path_label(source)
    payload = read_bounded_regular_file(
        source,
        limit=MAX_RAW_ARTIFACT_BYTES,
        subject="raw input artifact",
    )
    return _normalize_raw_payload(
        payload,
        label=label,
        experiment_id=experiment_id,
        target_type=target_type,
        observer_type=observer_type,
        collection_method=collection_method,
        collection_timestamp=collection_timestamp,
        raw_artifact_ref=raw_artifact_ref,
        raw_artifact_id=raw_artifact_id,
        collector_name=collector_name,
        collector_version=collector_version,
        collection_id=collection_id,
        redaction_state=redaction_state,
    )


def _normalize_raw_payload(
    payload: bytes,
    *,
    label: str,
    experiment_id: str,
    target_type: str,
    observer_type: str,
    collection_method: str,
    collection_timestamp: str | None,
    raw_artifact_ref: str | None,
    raw_artifact_id: str | None = None,
    collector_name: str = "unknown",
    collector_version: str = "unknown",
    collection_id: str | None = None,
    raw_status: str = "observed",
    redaction_state: str = "unknown",
    media_type: str = "text/plain",
    expected_sha256: str | None = None,
    expected_byte_size: int | None = None,
    generator_name: str = "trustlab",
    collection_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Normalize the exact bytes supplied by a caller after provenance checks."""

    timestamp = collection_timestamp or datetime.now(UTC).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    raw_sha256 = hashlib.sha256(payload).hexdigest()
    resolved_collection_id = collection_id or derive_collection_id(
        timestamp=timestamp,
        experiment_id=experiment_id,
        target_type=target_type,
        observer_type=observer_type,
        collection_method=collection_method,
        raw_sha256=raw_sha256,
    )
    raw_reference = make_raw_artifact_reference(
        payload,
        logical_id=raw_artifact_id,
        relative_path=raw_artifact_ref or label,
        media_type=media_type,
        collector_name=collector_name,
        collector_version=collector_version,
        collection_id=resolved_collection_id,
        status=raw_status,
        redaction_state=redaction_state,
        expected_sha256=expected_sha256,
        expected_byte_size=expected_byte_size,
    )
    event_id = collection_event_identity(
        collection_id=resolved_collection_id,
        timestamp=timestamp,
        experiment_id=experiment_id,
        target_type=target_type,
        observer_type=observer_type,
        collection_method=collection_method,
        collection_manifest_sha256=collection_manifest_sha256,
    )
    try:
        parsed = parse_raw_text(payload.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise CollectionError(f"input artifact is not valid UTF-8: {label}") from exc
    except (TypeError, ValueError) as exc:
        raise NormalizationError(
            f"could not normalize input artifact: {label}"
        ) from exc
    report = _normalize_parsed_report(
        parsed,
        experiment_id=experiment_id,
        target_type=target_type,
        observer_type=observer_type,
        collection_method=collection_method,
        collection_timestamp=timestamp,
        raw_artifact=raw_reference,
        collection_event_id=event_id,
        generator_name=generator_name,
    )
    report["collection_event_id"] = collection_event_identity(
        collection_id=resolved_collection_id,
        timestamp=report["collection_timestamp"],
        experiment_id=report["experiment_id"],
        target_type=report["target"]["target_type"],
        observer_type=report["observer"]["observer_type"],
        collection_method=report["observer"]["collection_method"],
        collection_manifest_sha256=collection_manifest_sha256,
    )
    return finalize_report_identity(report)


def normalize_raw_bytes(
    payload: bytes,
    *,
    label: str,
    experiment_id: str,
    target_type: str,
    observer_type: str,
    collection_method: str,
    collection_timestamp: str | None,
    raw_artifact_ref: str | None,
    raw_artifact_id: str | None = None,
    collector_name: str = "unknown",
    collector_version: str = "unknown",
    collection_id: str | None = None,
    raw_status: str = "observed",
    redaction_state: str = "unknown",
    media_type: str = "text/plain",
    expected_sha256: str | None = None,
    expected_byte_size: int | None = None,
    generator_name: str = "trustlab",
) -> dict[str, Any]:
    """Normalize one already-verified immutable byte snapshot."""

    return _normalize_raw_payload(
        payload,
        label=label,
        experiment_id=experiment_id,
        target_type=target_type,
        observer_type=observer_type,
        collection_method=collection_method,
        collection_timestamp=collection_timestamp,
        raw_artifact_ref=raw_artifact_ref,
        raw_artifact_id=raw_artifact_id,
        collector_name=collector_name,
        collector_version=collector_version,
        collection_id=collection_id,
        raw_status=raw_status,
        redaction_state=redaction_state,
        media_type=media_type,
        expected_sha256=expected_sha256,
        expected_byte_size=expected_byte_size,
        generator_name=generator_name,
    )


def _normalize_parsed_report(
    parsed: dict[str, Any],
    *,
    experiment_id: str,
    target_type: str,
    observer_type: str,
    collection_method: str,
    collection_timestamp: str,
    raw_artifact: RawArtifactReference,
    collection_event_id: str,
    generator_name: str,
) -> dict[str, Any]:
    return build_report(
        parsed,
        experiment_id=experiment_id,
        target_type=target_type,
        observer_type=observer_type,
        collection_method=collection_method,
        raw_artifact=raw_artifact,
        collection_event_id=collection_event_id,
        collection_timestamp=collection_timestamp,
        generator_name=generator_name,
    )


def _canonical_manifest_payload(manifest: dict[str, Any]) -> bytes:
    return canonical_json_bytes(manifest)


def _manifest_raw_report_entry(manifest: CollectionManifest) -> ArtifactEntry:
    raw_entries = [
        artifact
        for artifact in manifest.artifacts
        if artifact.logical_name == "raw_report"
        and artifact.media_type == "text/plain"
        and artifact.status is EvidenceStatus.OBSERVED
    ]
    if len(raw_entries) != 1:
        raise NormalizationError(
            "collection manifest must contain one observed raw_report artifact"
        )
    raw_entry = raw_entries[0]
    if (
        raw_entry.relative_path is None
        or raw_entry.sha256 is None
        or raw_entry.byte_size is None
    ):
        raise NormalizationError(
            "collection manifest raw_report provenance is incomplete"
        )
    return raw_entry


def _manifest_collection_errors(manifest: CollectionManifest) -> list[str]:
    errors: list[str] = []
    if manifest.completion_status != "complete":
        errors.append(
            f"collection manifest completion status: {manifest.completion_status}"
        )
    errors.extend(
        f"collection warning: {warning}"[:1024] for warning in manifest.warnings
    )
    for artifact in manifest.artifacts:
        if artifact.status in {EvidenceStatus.OBSERVED, EvidenceStatus.OBSERVED_ABSENT}:
            continue
        detail = f": {artifact.detail}" if artifact.detail else ""
        errors.append(
            f"probe {artifact.probe_id}: {artifact.status.value}{detail}"[:1024]
        )
    return list(dict.fromkeys(errors))[:256]


def normalize_collection_payload(
    payload: bytes,
    manifest: CollectionManifest,
    *,
    label: str,
    generator_name: str = "trustlab",
) -> dict[str, Any]:
    """Normalize exact bytes through their complete collection-manifest binding."""

    raw_entry = _manifest_raw_report_entry(manifest)
    manifest_data = manifest.to_dict()
    manifest_digest = hashlib.sha256(
        _canonical_manifest_payload(manifest_data)
    ).hexdigest()
    report = _normalize_raw_payload(
        payload,
        label=label,
        experiment_id=manifest.experiment_id,
        target_type=manifest.target.target_type,
        observer_type=manifest.observer.observer_type,
        collection_method=manifest.observer.collection_method,
        collection_timestamp=manifest.ended_at,
        raw_artifact_ref=raw_entry.relative_path,
        raw_artifact_id=raw_entry.logical_name,
        collector_name=manifest.collector.name,
        collector_version=manifest.collector.version,
        collection_id=manifest.collection_id,
        raw_status=raw_entry.status,
        redaction_state=raw_entry.redaction_state,
        media_type=raw_entry.media_type,
        expected_sha256=raw_entry.sha256,
        expected_byte_size=raw_entry.byte_size,
        generator_name=generator_name,
        collection_manifest_sha256=manifest_digest,
    )
    report["provenance"]["command_results"] = [
        {
            "command_id": artifact.probe_id,
            "status": artifact.status,
            "exit_code": artifact.exit_code,
            "timed_out": artifact.timed_out,
            "detail": artifact.detail,
        }
        for artifact in manifest.artifacts
    ]
    report["limitations"]["collection_errors"] = list(
        dict.fromkeys(
            [
                *report["limitations"]["collection_errors"],
                *_manifest_collection_errors(manifest),
            ]
        )
    )[:256]
    report["extensions"]["org.androidtrustlab.collection"] = {
        "canonicalization": "atl-canonical-json-v1",
        "canonical_manifest_sha256": manifest_digest,
        "manifest": manifest_data,
    }
    return finalize_report_identity(report)


def normalize_collection_manifest_with_inputs(
    manifest_path: str | Path,
) -> tuple[dict[str, Any], tuple[Path, ...]]:
    """Normalize one manifest snapshot and return its verified input paths."""

    manifest = read_collection_manifest(manifest_path)
    verified = verify_collection_artifacts(
        manifest,
        manifest_path,
        retain_payloads=frozenset({"raw_report"}),
    )
    raw_entry = _manifest_raw_report_entry(manifest)
    try:
        raw_artifact = verified[raw_entry.logical_name]
    except KeyError as exc:
        raise NormalizationError(
            "collection manifest raw_report artifact was not verified"
        ) from exc
    if raw_artifact.payload is None:
        raise NormalizationError(
            "collection manifest raw_report bytes were not retained"
        )
    report = normalize_collection_payload(
        raw_artifact.payload,
        manifest,
        label=safe_path_label(raw_artifact.path),
    )
    return report, tuple(item.path for item in verified.values())


def normalize_collection_manifest(manifest_path: str | Path) -> dict[str, Any]:
    """Verify and normalize the exact raw-report bytes bound by a manifest."""

    report, _ = normalize_collection_manifest_with_inputs(manifest_path)
    return report
