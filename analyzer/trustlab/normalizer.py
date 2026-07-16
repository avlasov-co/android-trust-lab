"""Normalize parsed Android Trust Lab artifacts into the report schema."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .artifacts import (
    ArtifactMetadata,
    ArtifactParseResult,
    CaptureStatus,
    CommandCapture,
    EvidenceFragments,
    InputKind,
    parse_artifact_text,
    parse_collection_payload_text,
)
from .bounded_io import read_bounded_regular_file
from .canonical_json import canonical_json_bytes
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
from .parser import KNOWN_SECTION_NAMES, MAX_RAW_TEXT_BYTES
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
MAX_RAW_ARTIFACT_BYTES = MAX_RAW_TEXT_BYTES


def unknown_mount(path: str) -> dict[str, Any]:
    return {
        "mount_point": path,
        "fs_type": "unknown",
        "options": [],
        "classification": "unknown",
        "raw": "",
    }


def select_mount(
    mounts: Sequence[Mapping[str, object]], mount_point: str
) -> dict[str, Any]:
    exact = [m for m in mounts if m.get("mount_point") == mount_point]
    if exact:
        return dict(exact[-1])
    nested = [
        m for m in mounts if str(m.get("mount_point", "")).startswith(mount_point + "/")
    ]
    if nested:
        return dict(nested[-1])
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
    is_emulator = bool(indicators)
    return {"is_emulator": is_emulator, "indicators": sorted(set(indicators))}


def normalize_mounts(mounts: Sequence[Mapping[str, object]]) -> dict[str, Any]:
    result: dict[str, Any] = {
        field: select_mount(mounts, path) for path, field in SENSITIVE_MOUNTS.items()
    }
    result["overlay_detected"] = any(
        m.get("classification") == "overlay" for m in mounts
    )
    writable = []
    for path, field in SENSITIVE_MOUNTS.items():
        mount = result[field]
        raw_options = mount.get("options", [])
        options = set(raw_options if isinstance(raw_options, list) else [])
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


def root_state(parsed: EvidenceFragments) -> dict[str, Any]:
    identity = parsed.identity
    uid = str(identity.get("uid", "unknown"))
    gid = str(identity.get("gid", "unknown"))
    su_paths = list(parsed.su_paths)
    su_present = bool(su_paths) or uid == "0"
    return {
        "su_present": su_present,
        "uid": uid,
        "gid": gid,
        "root_shell_available": uid == "0",
        "root_paths": su_paths,
    }


def magisk_state(parsed: EvidenceFragments) -> dict[str, Any]:
    raw = parsed.magisk_text or ""
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
    parsed: ArtifactParseResult,
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
    fragments = parsed.fragments
    observer = observer_spec(observer_type)
    props = dict(fragments.properties)
    boot_state_raw = dict(fragments.boot_state)
    mounts = list(fragments.mounts)
    timestamp = collection_timestamp
    cmdline = fragments.cmdline or boot_state_raw.get("kernel_cmdline", "") or ""
    emulator = detect_emulator(props, target_type)
    collection_errors = list(parsed.errors)
    if not props:
        collection_errors.append("missing getprop section")
    if not mounts:
        collection_errors.append("missing mount section")

    captured_names = set(parsed.parsed_capture_names)

    def capture_was_collected(*names: str) -> bool:
        return bool(captured_names.intersection(names))

    observed_probes = frozenset(
        probe
        for probe, observed in {
            "properties": capture_was_collected("properties", "getprop_selected"),
            "boot_state": capture_was_collected("boot_state"),
            "mounts": capture_was_collected("mountinfo", "mounts", "proc_mounts"),
            "identity": capture_was_collected("identity", "id"),
            "selinux": capture_was_collected("selinux_mode", "getenforce"),
            "cmdline": capture_was_collected("kernel_cmdline", "boot_state"),
            "su_paths": capture_was_collected("su_paths"),
            "magisk": capture_was_collected("magisk"),
            "processes": capture_was_collected("processes", "ps_selected"),
            "emulator_basis": capture_was_collected("properties", "getprop_selected"),
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
        "selinux": normalize_selinux(fragments.selinux_mode),
        "mounts": normalize_mounts(mounts),
        "properties": normalize_properties(props),
        "root_state": root_state(fragments),
        "magisk_state": magisk_state(fragments),
        "process_state": dict(fragments.processes),
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
    report = report_v3_from_v2_shape(
        report_v2,
        raw_artifacts=[raw_artifact],
        collection_event_id=collection_event_id,
        source_schema_version="raw",
        generator_name=generator_name,
    )
    report["provenance"]["command_results"] = [
        _capture_command_result(capture) for capture in parsed.captures
    ]
    adapter_extension: dict[str, Any] = {
        "input_kind": parsed.input_kind.value,
        "input_schema_version": parsed.metadata.schema_version,
        "collector_version": parsed.metadata.collector_version,
        "warnings": list(parsed.warnings),
        "errors": list(parsed.errors),
        "captures": [
            {
                "name": capture.name,
                "status": capture.status.value,
                "source_ref": capture.source_ref,
            }
            for capture in parsed.captures
        ],
    }
    unrecognized_sections = []
    unrecognized_names = (
        set(fragments.sections) | set(fragments.section_occurrences)
    ) - KNOWN_SECTION_NAMES
    for name in sorted(unrecognized_names):
        content = fragments.sections.get(name, "").encode("utf-8", errors="strict")
        unrecognized_sections.append(
            {
                "name": name,
                "occurrence_count": fragments.section_occurrences.get(name, 1),
                "byte_size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    if unrecognized_sections:
        adapter_extension["unrecognized_sections"] = unrecognized_sections
    report["extensions"]["org.androidtrustlab.adapter"] = adapter_extension
    return finalize_report_identity(report)


def _capture_command_result(capture: CommandCapture) -> dict[str, Any]:
    status = {
        CaptureStatus.OBSERVED: "observed",
        CaptureStatus.EMPTY: "observed_absent",
        CaptureStatus.NOT_COLLECTED: "not_collected",
        CaptureStatus.INACCESSIBLE: "inaccessible",
        CaptureStatus.COMMAND_ERROR: "command_error",
        CaptureStatus.TIMEOUT: "command_error",
        CaptureStatus.UNSUPPORTED: "unsupported",
        CaptureStatus.ERROR: "command_error",
    }[capture.status]
    detail = capture.stderr.strip() or None
    return {
        "command_id": capture.name,
        "status": status,
        "exit_code": capture.exit_code,
        "timed_out": capture.timed_out,
        "detail": detail,
    }


def normalize_raw_file(
    input_path: str | Path,
    *,
    experiment_id: str | None = None,
    target_type: str | None = None,
    observer_type: str | None = None,
    collection_method: str | None = None,
    collection_timestamp: str | None = None,
    raw_artifact_ref: str | None = None,
    raw_artifact_id: str | None = None,
    collector_name: str = "unknown",
    collector_version: str = "unknown",
    collection_id: str | None = None,
    redaction_state: str = "unknown",
    artifact_kind: str | None = None,
) -> dict[str, Any]:
    if observer_type is not None:
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
        artifact_kind=artifact_kind,
    )


def _normalize_raw_payload(
    payload: bytes,
    *,
    label: str,
    experiment_id: str | None,
    target_type: str | None,
    observer_type: str | None,
    collection_method: str | None,
    collection_timestamp: str | None,
    raw_artifact_ref: str | None,
    raw_artifact_id: str | None = None,
    collector_name: str = "unknown",
    collector_version: str = "unknown",
    collection_id: str | None = None,
    raw_status: str = "observed",
    redaction_state: str = "unknown",
    media_type: str | None = None,
    expected_sha256: str | None = None,
    expected_byte_size: int | None = None,
    generator_name: str = "trustlab",
    collection_manifest_sha256: str | None = None,
    artifact_kind: str | None = None,
    manifest_adapter_metadata: ArtifactMetadata | None = None,
) -> dict[str, Any]:
    """Normalize the exact bytes supplied by a caller after provenance checks."""

    if len(payload) > MAX_RAW_ARTIFACT_BYTES:
        raise CollectionError(f"raw input artifact exceeds the byte limit: {label}")
    raw_sha256 = hashlib.sha256(payload).hexdigest()
    if expected_sha256 is not None and raw_sha256 != expected_sha256:
        raise CollectionError("raw artifact digest does not match provenance")
    if expected_byte_size is not None and len(payload) != expected_byte_size:
        raise CollectionError("raw artifact byte size does not match provenance")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CollectionError(
            f"input artifact is not valid UTF-8 at byte {exc.start}: {label}"
        ) from exc
    try:
        if manifest_adapter_metadata is None:
            parsed = parse_artifact_text(
                text,
                source_ref=label,
                artifact_kind=artifact_kind,
            )
        else:
            if artifact_kind not in {None, "auto"}:
                raise NormalizationError(
                    "portable collection manifests select their artifact adapter"
                )
            parsed = parse_collection_payload_text(
                text,
                source_ref=label,
                metadata=manifest_adapter_metadata,
            )
    except (TypeError, ValueError) as exc:
        raise NormalizationError(
            f"could not normalize input artifact: {label}"
        ) from exc

    metadata = parsed.metadata
    if parsed.input_kind is not InputKind.LEGACY_SECTIONED_TEXT:
        declared_values = {
            "experiment_id": (experiment_id, metadata.experiment_id),
            "target_type": (target_type, metadata.target_type),
            "observer_type": (observer_type, metadata.observer_type),
            "collection_method": (
                collection_method,
                metadata.collection_method,
            ),
            "collection_timestamp": (
                collection_timestamp,
                metadata.collection_timestamp,
            ),
        }
        for field_name, (explicit, declared) in declared_values.items():
            if explicit is not None and declared is not None and explicit != declared:
                raise NormalizationError(
                    f"typed artifact {field_name} conflicts with declared metadata"
                )
        if (
            collector_version != "unknown"
            and collector_version != metadata.collector_version
        ):
            raise NormalizationError(
                "typed artifact collector_version conflicts with declared metadata"
            )
        if metadata.collection_timestamp is None:
            raise NormalizationError("typed artifact collection timestamp is required")
    resolved_experiment_id = experiment_id or metadata.experiment_id or "unknown"
    resolved_target_type = target_type or metadata.target_type or "unknown"
    resolved_observer_type = observer_type or metadata.observer_type or "adb_shell"
    resolved_collection_method = (
        collection_method or metadata.collection_method or "raw_artifact"
    )
    observer_spec(resolved_observer_type)
    timestamp = (
        collection_timestamp
        or metadata.collection_timestamp
        or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    resolved_collector_version = collector_version
    if (
        resolved_collector_version == "unknown"
        and parsed.input_kind is not InputKind.LEGACY_SECTIONED_TEXT
    ):
        resolved_collector_version = metadata.collector_version
    resolved_media_type = media_type or (
        "text/plain"
        if parsed.input_kind is InputKind.LEGACY_SECTIONED_TEXT
        else "application/json"
    )
    resolved_collection_id = collection_id or derive_collection_id(
        timestamp=timestamp,
        experiment_id=resolved_experiment_id,
        target_type=resolved_target_type,
        observer_type=resolved_observer_type,
        collection_method=resolved_collection_method,
        raw_sha256=raw_sha256,
    )
    raw_reference = make_raw_artifact_reference(
        payload,
        logical_id=raw_artifact_id,
        relative_path=raw_artifact_ref or label,
        media_type=resolved_media_type,
        collector_name=collector_name,
        collector_version=resolved_collector_version,
        collection_id=resolved_collection_id,
        status=raw_status,
        redaction_state=redaction_state,
        expected_sha256=expected_sha256,
        expected_byte_size=expected_byte_size,
    )
    event_id = collection_event_identity(
        collection_id=resolved_collection_id,
        timestamp=timestamp,
        experiment_id=resolved_experiment_id,
        target_type=resolved_target_type,
        observer_type=resolved_observer_type,
        collection_method=resolved_collection_method,
        collection_manifest_sha256=collection_manifest_sha256,
    )
    report = _normalize_parsed_report(
        parsed,
        experiment_id=resolved_experiment_id,
        target_type=resolved_target_type,
        observer_type=resolved_observer_type,
        collection_method=resolved_collection_method,
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
    media_type: str | None = None,
    expected_sha256: str | None = None,
    expected_byte_size: int | None = None,
    generator_name: str = "trustlab",
    artifact_kind: str | None = None,
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
        artifact_kind=artifact_kind,
    )


def _normalize_parsed_report(
    parsed: ArtifactParseResult,
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
        manifest_adapter_metadata=ArtifactMetadata(
            schema_version=manifest.schema_version,
            collector_version=manifest.collector.version,
            observer_type=manifest.observer.observer_type,
            collection_method=manifest.observer.collection_method,
            experiment_id=manifest.experiment_id,
            target_type=manifest.target.target_type,
            collection_timestamp=manifest.ended_at,
        ),
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
    raw_entry = _manifest_raw_report_entry(manifest)
    if raw_entry.byte_size is None or raw_entry.byte_size > MAX_RAW_ARTIFACT_BYTES:
        raise CollectionError("collection manifest raw_report exceeds the byte limit")
    verified = verify_collection_artifacts(
        manifest,
        manifest_path,
        retain_payloads=frozenset({"raw_report"}),
    )
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
