"""Normalize parsed Android Trust Lab artifacts into the report schema."""

from __future__ import annotations

import hashlib
import json
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
    MountSourceAttempt,
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
from .comparison import COMPARISON_CONTEXT_EXTENSION, observer_protocol
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
from .privacy import (
    sanitize_boot_reason,
    sanitize_collection_id,
    sanitize_collection_method,
    sanitize_experiment_id,
    sanitize_metadata_value,
    sanitize_mount_model,
    sanitize_property_value,
    sanitize_raw_artifact_references,
)
from .report_v2 import report_v2_from_v1_shape
from .report_v3 import report_v3_from_v2_shape
from .report_v4 import report_v4_from_v3_shape
from .report_v5 import report_v5_from_v4_shape
from .report_v6 import report_v6_from_v5_shape
from .root_magisk import (
    structured_magisk_state,
    structured_root_state,
    verified_boot_confidence,
)
from .security_evidence import SELECTED_PROCESS_NAMES

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
        # Retain the legacy summary's last-observation behavior. The v4
        # system_resolution field separately records stacked mounts as ambiguous.
        return dict(exact[-1])
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


def _capture_for(
    captures: Sequence[CommandCapture], *names: str
) -> CommandCapture | None:
    candidates = [capture for capture in captures if capture.name in names]
    return next(
        (
            capture
            for capture in candidates
            if capture.status is not CaptureStatus.NOT_COLLECTED
        ),
        candidates[0] if candidates else None,
    )


def _portable_capture_status(capture: CommandCapture | None) -> str:
    if capture is None or capture.status is CaptureStatus.NOT_COLLECTED:
        return "not_collected"
    return {
        CaptureStatus.OBSERVED: "observed",
        CaptureStatus.EMPTY: "observed",
        CaptureStatus.INACCESSIBLE: "inaccessible",
        CaptureStatus.COMMAND_ERROR: "command_error",
        CaptureStatus.TIMEOUT: "command_error",
        CaptureStatus.UNSUPPORTED: "unsupported",
        CaptureStatus.ERROR: "command_error",
        CaptureStatus.NOT_COLLECTED: "not_collected",
    }[capture.status]


def _unavailable_evidence(status: str, reason: str) -> dict[str, Any]:
    return {"status": status, "value": None, "reason": reason}


def _capture_reason(status: str) -> str:
    return {
        "not_collected": "the capture was not collected",
        "inaccessible": "the observer could not access the capture",
        "command_error": "the capture command did not complete successfully",
        "unsupported": "the capture is unsupported for this observer",
    }.get(status, "the capture did not contain supported evidence")


def structured_selinux_state(
    parsed: ArtifactParseResult, *, observer_type: str
) -> dict[str, Any]:
    mode_capture = _capture_for(parsed.captures, "selinux_mode", "getenforce")
    mode_status = _portable_capture_status(mode_capture)
    mode = parsed.fragments.selinux_mode
    if mode_status == "observed" and mode in {"enforcing", "permissive", "disabled"}:
        policy_mode = {
            "status": "observed",
            "value": mode,
            "reason": None,
            "evidence_refs": [mode_capture.source_ref] if mode_capture else [],
        }
    else:
        if mode_status == "observed":
            mode_status = "command_error"
        policy_mode = {
            **_unavailable_evidence(mode_status, _capture_reason(mode_status)),
            "evidence_refs": [],
        }

    context_capture = _capture_for(
        parsed.captures,
        "selinux_context",
        "collector_context",
        "app_context",
        "selinux_self_context",
    )
    context_status = _portable_capture_status(context_capture)
    context = parsed.fragments.selinux_context
    if context_status == "observed" and context["parse_status"] == "parsed":
        current_context = {
            "status": "observed",
            "value": context["value"],
            "reason": None,
            "evidence_refs": [context_capture.source_ref] if context_capture else [],
        }
    elif (
        context_capture is not None
        and context_capture.status is CaptureStatus.EMPTY
        and context["parse_status"] == "empty"
    ):
        context_status = "observed_absent"
        current_context = {
            **_unavailable_evidence(
                context_status,
                "the context capture completed without a current context",
            ),
            "evidence_refs": [],
        }
    else:
        if context_status == "observed":
            context_status = "command_error"
        current_context = {
            **_unavailable_evidence(context_status, _capture_reason(context_status)),
            "evidence_refs": [],
        }

    denial_capture = _capture_for(parsed.captures, "selinux_denials")
    denial_status = _portable_capture_status(denial_capture)
    if denial_status == "observed":
        denial_collection = {
            "status": "observed",
            "reason": None,
            "evidence_refs": [denial_capture.source_ref] if denial_capture else [],
        }
    else:
        denial_collection = {
            "status": denial_status,
            "reason": _capture_reason(denial_status),
            "evidence_refs": [],
        }
    limitations = ["complete_policy_not_inspected"]
    if denial_status != "observed":
        limitations.append("denials_not_collected")
    if context_status != "observed":
        limitations.append("current_context_not_observed")
    return {
        "source_observer": observer_type,
        "policy_mode": policy_mode,
        "current_context": current_context,
        "denial_collection": denial_collection,
        "limitations": limitations,
    }


def structured_process_state(
    parsed: ArtifactParseResult, *, observer_type: str
) -> dict[str, Any]:
    capture = _capture_for(parsed.captures, "processes", "ps_selected")
    capture_status = _portable_capture_status(capture)
    evidence = parsed.fragments.process_evidence
    scope = evidence["scope"]
    if observer_type == "unprivileged_app" and capture is not None:
        scope = "app_sandbox"
    observed = {item["name"]: item for item in evidence["observations"]}
    absence_capable = (
        capture_status == "observed"
        and scope == "complete"
        and evidence["parse_status"] == "complete"
    )
    selected_processes = []
    for name in SELECTED_PROCESS_NAMES:
        item = observed.get(name)
        if item is not None:
            visibility = {"status": "observed", "value": True, "reason": None}
            contexts = item["contexts"]
            if len(contexts) == 1:
                context = {
                    "status": "observed",
                    "value": contexts[0],
                    "reason": None,
                }
            elif len(contexts) > 1:
                context = _unavailable_evidence(
                    "unsupported",
                    "multiple sanitized contexts were observed for this process",
                )
            else:
                context = _unavailable_evidence(
                    "not_collected", "a process context was not included"
                )
            refs = [capture.source_ref] if capture is not None else []
        elif absence_capable:
            visibility = {
                "status": "observed_absent",
                "value": False,
                "reason": "the exact name was absent from a complete process table",
            }
            context = _unavailable_evidence(
                "observed_absent", "the process was observed absent"
            )
            refs = []
        else:
            status = capture_status if capture_status != "observed" else "not_collected"
            reason = (
                _capture_reason(status)
                if status != "not_collected" or capture_status != "observed"
                else "the capture scope cannot prove process absence"
            )
            visibility = _unavailable_evidence(status, reason)
            context = _unavailable_evidence(status, reason)
            refs = []
        selected_processes.append(
            {
                "name": name,
                "visibility": visibility,
                "context": context,
                "evidence_refs": refs,
            }
        )

    limitations = ["observer_scoped_visibility"]
    if scope == "selected":
        limitations.append("selected_filter_not_exhaustive")
    if scope == "app_sandbox":
        limitations.append("app_sandbox_visibility")
    if evidence["parse_status"] == "partial":
        limitations.append("partial_process_table")
    if evidence["parse_status"] == "unsupported":
        limitations.append("unsupported_ps_format")
    if any(not item["contexts"] for item in evidence["observations"]):
        limitations.append("process_contexts_not_collected")
    return {
        "source_observer": observer_type,
        "capture_status": capture_status,
        "source_format": evidence["format"],
        "scope": scope,
        "completeness": evidence["parse_status"]
        if capture_status == "observed"
        else "unknown",
        "evidence_refs": (
            [capture.source_ref] if capture_status == "observed" and capture else []
        ),
        "selected_processes": selected_processes,
        "limitations": limitations,
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


def _portable_app_status(status: CaptureStatus) -> str:
    return {
        CaptureStatus.OBSERVED: "observed",
        CaptureStatus.INACCESSIBLE: "inaccessible",
        CaptureStatus.UNSUPPORTED: "unsupported",
        CaptureStatus.ERROR: "command_error",
        CaptureStatus.EMPTY: "observed_absent",
        CaptureStatus.NOT_COLLECTED: "not_collected",
        CaptureStatus.COMMAND_ERROR: "command_error",
        CaptureStatus.TIMEOUT: "command_error",
    }[status]


def _portable_app_reason(status: str) -> str | None:
    return {
        "observed": None,
        "observed_absent": "the selected app-visible value was absent",
        "inaccessible": "the app sandbox could not access this capability",
        "unsupported": "the selected capability is unsupported",
        "command_error": "the app probe did not produce trustworthy evidence",
        "not_collected": "the app probe was not collected",
    }[status]


def _portable_app_value(value: object) -> object:
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for key, item in value.items():
            if key == "diagnostic":
                continue
            if key == "status" and item == "error":
                result[key] = "command_error"
            else:
                result[key] = _portable_app_value(item)
        return result
    if isinstance(value, list):
        return [_portable_app_value(item) for item in value]
    return value


def _app_probe_extension(parsed: ArtifactParseResult) -> dict[str, Any] | None:
    app = parsed.fragments.app_probe
    if app is None:
        return None
    projected = []
    refs = []
    for evidence in app.evidence:
        status = _portable_app_status(evidence.status)
        projected.append(
            {
                "probe_id": evidence.probe_id,
                "status": status,
                "value": (
                    _portable_app_value(evidence.value)
                    if evidence.status is CaptureStatus.OBSERVED
                    else None
                ),
                "reason": _portable_app_reason(status),
                "evidence_refs": [evidence.source_ref],
            }
        )
        refs.append(evidence.source_ref)
    return {
        "status": "observed",
        "value": {
            "schema_version": "2.0.0",
            "probes": projected,
        },
        "reason": None,
        "evidence_refs": refs,
    }


def _apply_app_probe_evidence(
    report: dict[str, Any], parsed: ArtifactParseResult
) -> None:
    app = parsed.fragments.app_probe
    if app is None:
        return
    evidence_by_id = {item.probe_id: item for item in app.evidence}
    build = evidence_by_id["build_version"]
    build_status = _portable_app_status(build.status)
    if build.status is CaptureStatus.OBSERVED:
        report["target"]["android_version"] = {
            "status": "observed",
            "value": app.android_version,
            "reason": None,
        }
        report["target"]["sdk"] = {
            "status": "observed",
            "value": app.sdk,
            "reason": None,
        }
    else:
        unavailable = {
            "status": build_status,
            "value": None,
            "reason": _portable_app_reason(build_status),
        }
        report["target"]["android_version"] = dict(unavailable)
        report["target"]["sdk"] = dict(unavailable)

    emulator = evidence_by_id["emulator_indicators"]
    emulator_status = _portable_app_status(emulator.status)
    if emulator.status is CaptureStatus.OBSERVED:
        indicators = list(app.emulator_indicators or ())
        if indicators:
            report["limitations"]["emulator_target"] = True
            report["emulator_state"] = {
                "is_emulator": {
                    "status": "observed",
                    "value": True,
                    "reason": None,
                },
                "indicators": {
                    "status": "observed",
                    "value": indicators,
                    "reason": None,
                },
            }
        else:
            report["limitations"]["emulator_target"] = False
            reason = "no selected emulator indicator was observed"
            report["emulator_state"] = {
                "is_emulator": {
                    "status": "observed_absent",
                    "value": False,
                    "reason": reason,
                },
                "indicators": {
                    "status": "observed_absent",
                    "value": [],
                    "reason": reason,
                },
            }
    else:
        report["limitations"]["emulator_target"] = False
        unavailable = {
            "status": emulator_status,
            "value": None,
            "reason": _portable_app_reason(emulator_status),
        }
        report["emulator_state"] = {
            "is_emulator": dict(unavailable),
            "indicators": dict(unavailable),
        }

    extension = _app_probe_extension(parsed)
    if extension is not None:
        report["extensions"]["org.androidtrustlab.app-probe"] = extension


def _mount_attempt(attempt: MountSourceAttempt) -> dict[str, Any]:
    return {
        "name": attempt.name,
        "format": attempt.format,
        "capture_status": attempt.capture_status.value,
        "parse_status": attempt.parse_status,
        "source_ref": attempt.source_ref,
        "record_count": attempt.record_count,
        "malformed_line_count": attempt.malformed_line_count,
        "warnings": list(attempt.warnings),
    }


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _record_index(record: Mapping[str, object]) -> int:
    value = record.get("record_index")
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _mount_record(record: Mapping[str, object]) -> dict[str, Any]:
    propagation = record.get("propagation", {})
    if not isinstance(propagation, Mapping):
        propagation = {}
    return {
        "record_index": record.get("record_index", 0),
        "source_line": record.get("source_line", 0),
        "format": record.get("format", "mount"),
        "mount_id": record.get("mount_id"),
        "parent_id": record.get("parent_id"),
        "major_minor": record.get("major_minor"),
        "root": record.get("root"),
        "mount_point": record.get("mount_point"),
        "mount_options": _string_list(record.get("mount_options")),
        "optional_fields": _string_list(record.get("optional_fields")),
        "fs_type": record.get("fs_type"),
        "source": record.get("source"),
        "super_options": _string_list(record.get("super_options")),
        "propagation": dict(propagation),
        "access": record.get("access", "unknown"),
        "overlay_state": record.get("overlay_state", "unknown"),
        "bind_state": record.get("bind_state", "unknown"),
        "parse_status": record.get("parse_status", "partial"),
        "raw": record.get("raw", ""),
        "evidence_path": record.get("evidence_path", "unknown"),
    }


def _system_mount_resolution(
    mounts: Sequence[Mapping[str, object]],
    *,
    complete: bool,
) -> dict[str, Any]:
    system_records = [
        _record_index(mount)
        for mount in mounts
        if mount.get("mount_point") == "/system"
    ]
    root_records = [
        _record_index(mount) for mount in mounts if mount.get("mount_point") == "/"
    ]
    if len(system_records) == 1:
        return {
            "state": "explicit_system",
            "system_root": "/system",
            "record_indices": system_records,
            "reason": "one exact /system mount was observed",
        }
    if len(system_records) > 1:
        return {
            "state": "ambiguous",
            "system_root": None,
            "record_indices": system_records,
            "reason": "multiple exact /system mounts were observed",
        }
    if complete and len(root_records) == 1:
        return {
            "state": "system_as_root",
            "system_root": "/",
            "record_indices": root_records,
            "reason": "no /system mount was observed; one root mount is the system root",
        }
    if complete and len(root_records) > 1:
        return {
            "state": "ambiguous",
            "system_root": None,
            "record_indices": root_records,
            "reason": "multiple root mounts were observed without an exact /system mount",
        }
    if root_records:
        return {
            "state": "unresolved",
            "system_root": None,
            "record_indices": root_records,
            "reason": "partial evidence cannot establish that /system is absent",
        }
    return {
        "state": "unresolved",
        "system_root": None,
        "record_indices": [],
        "reason": "neither an exact /system mount nor a root mount was observed",
    }


def _apex_mount_set(mounts: Sequence[Mapping[str, object]]) -> dict[str, Any]:
    apex_records = [
        mount
        for mount in mounts
        if mount.get("mount_point") == "/apex"
        or str(mount.get("mount_point", "")).startswith("/apex/")
    ]
    packages = sorted(
        {
            str(mount["mount_point"])
            .removeprefix("/apex/")
            .split("/", 1)[0]
            .split("@", 1)[0]
            for mount in apex_records
            if mount.get("mount_point") not in {None, "/apex"}
        }
    )
    accesses = [mount.get("access", "unknown") for mount in apex_records]
    return {
        "packages": packages,
        "record_indices": [_record_index(mount) for mount in apex_records],
        "mount_count": len(apex_records),
        "package_count": len(packages),
        "read_only_count": accesses.count("read_only"),
        "writable_count": accesses.count("writable"),
        "unknown_access_count": accesses.count("unknown"),
        "overlay_count": sum(
            mount.get("overlay_state") == "detected" for mount in apex_records
        ),
        "bind_count": sum(
            mount.get("bind_state") == "detected" for mount in apex_records
        ),
    }


def normalize_mounts(
    mounts: Sequence[Mapping[str, object]],
    *,
    attempts: Sequence[MountSourceAttempt] = (),
    selected_source: str | None = None,
    selection_reason: str = "no mount capture was usable",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        field: select_mount(mounts, path) for path, field in SENSITIVE_MOUNTS.items()
    }
    result["overlay_detected"] = any(
        mount.get("overlay_state") == "detected" for mount in mounts
    )
    writable = []
    for path, field in SENSITIVE_MOUNTS.items():
        mount = result[field]
        if path != "/data" and mount.get("access") == "writable":
            writable.append(path)
    result["writable_sensitive_mounts"] = writable
    result["integrity_summary"] = {
        "overlay_detected": result["overlay_detected"],
        "writable_sensitive_mounts": writable,
        "bind_mounts_detected": sum(
            mount.get("bind_state") == "detected" for mount in mounts
        ),
        "unknown_sensitive_mounts": sorted(
            path
            for path, field in SENSITIVE_MOUNTS.items()
            if result[field].get("classification") == "unknown"
        ),
        "assessment": "not_assessed",
        "reason": "mount access is contextual evidence, not an integrity verdict",
    }
    selected_attempt = next(
        (attempt for attempt in attempts if attempt.name == selected_source), None
    )
    result["observation"] = {
        "scope": "observer_self",
        "selected_source": selected_source,
        "selected_format": selected_attempt.format if selected_attempt else None,
        "parse_status": selected_attempt.parse_status
        if selected_attempt
        else "not_parsed",
        "selection_reason": selection_reason,
        "attempts": [_mount_attempt(attempt) for attempt in attempts],
        "evidence_paths": sorted(
            {
                str(mount.get("evidence_path"))
                for mount in mounts
                if mount.get("evidence_path")
            }
        ),
    }
    result["records"] = [_mount_record(mount) for mount in mounts]
    complete_mount_set = bool(
        selected_attempt and selected_attempt.parse_status == "complete"
    )
    result["system_resolution"] = _system_mount_resolution(
        mounts,
        complete=complete_mount_set,
    )
    dynamic_records = [
        mount
        for mount in mounts
        if str(mount.get("source", "")).startswith(
            ("/dev/block/mapper/", "/dev/block/dm-")
        )
        or str(mount.get("major_minor", "")).startswith("253:")
    ]
    result["dynamic_partitions"] = {
        "state": "detected"
        if dynamic_records
        else "not_detected"
        if complete_mount_set
        else "unknown",
        "record_indices": [_record_index(mount) for mount in dynamic_records],
        "sources": sorted(
            {
                str(mount["source"])
                for mount in dynamic_records
                if mount.get("source") is not None
            }
        ),
    }
    result["apex_set"] = _apex_mount_set(mounts)
    return result


def root_state(parsed: EvidenceFragments) -> dict[str, Any]:
    identity = parsed.identity
    uid = str(identity.get("uid", "unknown"))
    gid = str(identity.get("gid", "unknown"))
    su_paths = list(parsed.su_paths)
    su_present = bool(su_paths)
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
        "confidence": (
            "medium"
            if all(value != "unknown" for value in values.values())
            else "low"
            if any(value != "unknown" for value in values.values())
            else "unassessed"
        ),
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
    raw_props = dict(fragments.properties)
    raw_boot_state = dict(fragments.boot_state)
    props = {
        key: sanitize_property_value(key, value, scope=collection_event_id)
        for key, value in raw_props.items()
    }
    boot_state_raw = {
        key: sanitize_property_value(key, value, scope=collection_event_id)
        for key, value in raw_boot_state.items()
        if key != "kernel_cmdline"
    }
    mounts = list(fragments.mounts)
    timestamp = collection_timestamp
    cmdline = fragments.cmdline or raw_boot_state.get("kernel_cmdline", "") or ""
    emulator = detect_emulator(raw_props, target_type)
    collection_errors = [
        f"capture issue {index:03d} withheld"
        for index, _error in enumerate(parsed.errors, start=1)
    ]
    if not props and fragments.app_probe is None:
        collection_errors.append("missing getprop section")
    if not mounts and fragments.app_probe is None:
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
    modern_mounts = sanitize_mount_model(
        normalize_mounts(
            mounts,
            attempts=fragments.mount_attempts,
            selected_source=fragments.mount_selected_source,
            selection_reason=fragments.mount_selection_reason,
        ),
        scope=collection_event_id,
    )
    modern_selinux = structured_selinux_state(
        parsed,
        observer_type=observer.observer_id,
    )
    modern_processes = structured_process_state(
        parsed,
        observer_type=observer.observer_id,
    )
    modern_root = structured_root_state(
        parsed,
        observer_type=observer.observer_id,
    )
    modern_magisk = structured_magisk_state(
        parsed,
        processes=modern_processes,
        pseudonym_scope=collection_event_id,
        observer_type=observer.observer_id,
    )
    verified_model = verified_boot_state(props, target_type, boot_state_raw)

    legacy_shape = {
        "report_id": "atl-" + "0" * 16,
        "schema_version": "1.0.0",
        "collection_timestamp": timestamp,
        "experiment_id": experiment_id,
        "target": {
            "target_type": target_type,
            "device_codename": sanitize_metadata_value(
                props.get("ro.product.device", "unknown"),
                category="device-codename",
                scope=collection_event_id,
            ),
            "manufacturer": sanitize_metadata_value(
                props.get("ro.product.manufacturer", "unknown"),
                category="manufacturer",
                scope=collection_event_id,
            ),
            "model": sanitize_metadata_value(
                props.get("ro.product.model", "unknown"),
                category="model",
                scope=collection_event_id,
            ),
            "android_version": props.get("ro.build.version.release", "unknown"),
            "sdk": props.get("ro.build.version.sdk", "unknown"),
            "build_fingerprint": sanitize_metadata_value(
                props.get("ro.build.fingerprint", "unknown"),
                category="build-fingerprint",
                scope=collection_event_id,
            ),
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
            "boot_reason": sanitize_boot_reason(
                raw_props.get(
                    "ro.boot.bootreason",
                    raw_props.get(
                        "sys.boot.reason",
                        raw_boot_state.get("ro.boot.bootreason", "unknown"),
                    ),
                ),
                scope=collection_event_id,
            ),
            "slot_suffix": props.get(
                "ro.boot.slot_suffix",
                boot_state_raw.get("ro.boot.slot_suffix", "unknown"),
            ),
            "kernel_cmdline_present": bool(cmdline.strip()),
        },
        "verified_boot": verified_model,
        "selinux": normalize_selinux(fragments.selinux_mode),
        "mounts": modern_mounts,
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
    report_v3 = report_v3_from_v2_shape(
        report_v2,
        raw_artifacts=[raw_artifact],
        collection_event_id=collection_event_id,
        source_schema_version="raw",
        generator_name=generator_name,
    )
    report_v4 = report_v4_from_v3_shape(report_v3, modern_mounts=modern_mounts)
    report_v5 = report_v5_from_v4_shape(
        report_v4,
        structured_selinux=modern_selinux,
        structured_processes=modern_processes,
    )
    report_v5["raw_artifacts"] = sanitize_raw_artifact_references(
        report_v5["raw_artifacts"],
        scope=collection_event_id,
    )
    report = report_v6_from_v5_shape(
        report_v5,
        structured_root=modern_root,
        structured_magisk=modern_magisk,
        confidence=verified_boot_confidence(
            parsed,
            observer_privilege=observer.privilege_level,
            target_type=target_type,
            values={
                key: str(value)
                for key, value in verified_model.items()
                if key != "raw_properties" and key != "confidence"
            },
        ),
    )
    report["provenance"]["command_results"] = [
        _capture_command_result(capture) for capture in parsed.captures
    ]
    adapter_extension: dict[str, Any] = {
        "input_kind": parsed.input_kind.value,
        "input_schema_version": parsed.metadata.schema_version,
        "collector_version": parsed.metadata.collector_version,
        "warnings": [
            f"adapter warning {index:03d} withheld"
            for index, _warning in enumerate(parsed.warnings, start=1)
        ],
        "errors": [
            f"adapter error {index:03d} withheld"
            for index, _error in enumerate(parsed.errors, start=1)
        ],
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
    for ordinal, name in enumerate(sorted(unrecognized_names), start=1):
        content = fragments.sections.get(name, "").encode("utf-8", errors="strict")
        unrecognized_sections.append(
            {
                "name": f"unrecognized-section-{ordinal:03d}",
                "occurrence_count": fragments.section_occurrences.get(name, 1),
                "byte_size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    if unrecognized_sections:
        adapter_extension["unrecognized_sections"] = unrecognized_sections
    report["extensions"]["org.androidtrustlab.adapter"] = adapter_extension
    report["extensions"][COMPARISON_CONTEXT_EXTENSION] = {
        "target_pseudonym": "unknown",
        "target_class": report["target"]["target_type"],
        "state_id": "unknown",
        "experiment_id": report["experiment_id"],
        "protocol": observer_protocol(report["observer"]["observer_type"]),
        "observer": report["observer"]["observer_type"],
        "observer_privilege": report["observer"]["privilege_level"],
        "report_schema_version": report["schema_version"],
        "environment_context": "unknown",
        "measurement_id": report["collection_event_id"],
    }
    _apply_app_probe_evidence(report, parsed)
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
    detail = {
        CaptureStatus.INACCESSIBLE: "capture was inaccessible",
        CaptureStatus.COMMAND_ERROR: "capture command failed",
        CaptureStatus.TIMEOUT: "capture command timed out",
        CaptureStatus.UNSUPPORTED: "capture is unsupported",
        CaptureStatus.ERROR: "capture failed",
    }.get(capture.status)
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
    resolved_experiment_id = sanitize_experiment_id(
        resolved_experiment_id,
        scope=raw_sha256,
    )
    resolved_collection_method = sanitize_collection_method(
        resolved_collection_method,
        scope=raw_sha256,
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
    resolved_collection_id = sanitize_collection_id(
        resolved_collection_id,
        scope=raw_sha256,
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
    report["extensions"][COMPARISON_CONTEXT_EXTENSION]["measurement_id"] = report[
        "collection_event_id"
    ]
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
    expected_media_types = (
        {"application/json", "text/plain"}
        if manifest.collector.name == "trustlab-app"
        else {"text/plain"}
    )
    raw_entries = [
        artifact
        for artifact in manifest.artifacts
        if artifact.logical_name == "raw_report"
        and artifact.media_type in expected_media_types
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


def _validate_app_probe_manifest_binding(
    payload: bytes, manifest: CollectionManifest, *, media_type: str
) -> None:
    if manifest.collector.name != "trustlab-app" or media_type == "text/plain":
        return
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CollectionError("app probe artifact must be valid UTF-8") from exc
    parsed = parse_artifact_text(text, source_ref="app_probe.json")
    if (
        parsed.input_kind is not InputKind.APP_PROBE_JSON
        or parsed.metadata.schema_version != "2.0.0"
    ):
        raise NormalizationError(
            "app collection manifest must bind a typed v2 app probe"
        )
    document = json.loads(text)
    if not isinstance(document, dict):
        raise NormalizationError("app probe artifact must be an object")
    expected_metadata = {
        "collector": {
            "name": manifest.collector.name,
            "version": manifest.collector.version,
        },
        "observer": {
            "observer_type": manifest.observer.observer_type,
            "privilege_level": manifest.observer.privilege_level,
            "collection_method": manifest.observer.collection_method,
        },
        "collection_id": manifest.collection_id,
        "experiment_id": manifest.experiment_id,
        "target": {
            "pseudonymous_id": manifest.target.pseudonymous_id,
            "target_type": manifest.target.target_type,
        },
        "started_at": manifest.started_at,
        "ended_at": manifest.ended_at,
        "completion_status": manifest.completion_status,
        "environment": {
            "platform": manifest.environment.platform,
            "transport": manifest.environment.transport,
            "execution_context": manifest.environment.execution_context,
        },
    }
    mismatch = next(
        (
            name
            for name, expected in expected_metadata.items()
            if document.get(name) != expected
        ),
        None,
    )
    if mismatch is not None:
        raise NormalizationError(
            f"app probe {mismatch} does not match its collection manifest"
        )
    redaction = document.get("redaction_policy")
    manifest_redaction = manifest.redaction_policy
    expected_redaction = {
        "policy_id": manifest_redaction.policy_id,
        "redaction_state": manifest_redaction.redaction_state,
        "direct_identifiers_removed": manifest_redaction.direct_identifiers_removed,
        "serials_removed": manifest_redaction.serials_removed,
        "secrets_removed": manifest_redaction.secrets_removed,
    }
    if not isinstance(redaction, dict) or any(
        redaction.get(name) != value for name, value in expected_redaction.items()
    ):
        raise NormalizationError(
            "app probe redaction policy does not match its collection manifest"
        )
    if dict(manifest.tool_versions) != {"trustlab_app": manifest.collector.version}:
        raise NormalizationError(
            "app collection manifest tool version does not match its collector"
        )

    expected_outcomes = []
    status_map = {
        CaptureStatus.INACCESSIBLE: "inaccessible",
        CaptureStatus.UNSUPPORTED: "unsupported",
        CaptureStatus.ERROR: "command_error",
    }
    for capture in parsed.captures:
        if capture.status is CaptureStatus.OBSERVED:
            continue
        try:
            status = status_map[capture.status]
        except KeyError as exc:
            raise NormalizationError(
                "app probe contains a non-portable outcome"
            ) from exc
        expected_outcomes.append(
            {
                "logical_name": f"probe_outcome.{capture.name}",
                "relative_path": None,
                "media_type": "application/json",
                "byte_size": None,
                "sha256": None,
                "probe_id": f"app.{capture.name}",
                "status": status,
                "exit_code": None,
                "timed_out": False,
                "sensitivity": "internal",
                "redaction_state": "withheld",
                "detail": None,
            }
        )
    manifest_outcomes = [
        artifact.to_dict()
        for artifact in manifest.artifacts
        if artifact.logical_name != "raw_report"
    ]
    if manifest_outcomes != expected_outcomes:
        raise NormalizationError(
            "app probe outcomes do not match their collection manifest"
        )


def _manifest_collection_errors(manifest: CollectionManifest) -> list[str]:
    errors: list[str] = []
    if manifest.completion_status != "complete":
        errors.append(
            f"collection manifest completion status: {manifest.completion_status}"
        )
    errors.extend(
        f"collection warning {index:03d} withheld"
        for index, _warning in enumerate(manifest.warnings, start=1)
    )
    for index, artifact in enumerate(manifest.artifacts, start=1):
        if artifact.status in {EvidenceStatus.OBSERVED, EvidenceStatus.OBSERVED_ABSENT}:
            continue
        errors.append(f"probe {index:03d}: {artifact.status.value}"[:1024])
    return list(dict.fromkeys(errors))[:256]


def normalize_collection_payload(
    payload: bytes,
    manifest: CollectionManifest,
    *,
    label: str,
    generator_name: str = "trustlab",
) -> dict[str, Any]:
    """Normalize exact bytes through their complete collection-manifest binding."""

    manifest_data = manifest.to_dict()
    # Typed dataclasses can be instantiated directly by API callers.  Recheck
    # the complete portable contract here so arbitrary warning/detail text
    # cannot bypass CollectionManifest.from_dict and enter a report.
    from .validators import validate_collection_manifest

    validate_collection_manifest(manifest_data)
    raw_entry = _manifest_raw_report_entry(manifest)
    _validate_app_probe_manifest_binding(
        payload, manifest, media_type=raw_entry.media_type
    )
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
    portable_results = [
        {
            "command_id": f"artifact-{index:03d}",
            "status": artifact.status,
            "exit_code": artifact.exit_code,
            "timed_out": artifact.timed_out,
            "detail": None,
        }
        for index, artifact in enumerate(manifest.artifacts, start=1)
    ]
    report["provenance"]["command_results"] = portable_results
    manifest_errors = _manifest_collection_errors(manifest)
    report["limitations"]["collection_errors"] = list(
        dict.fromkeys(
            [
                *report["limitations"]["collection_errors"],
                *manifest_errors,
            ]
        )
    )[:256]
    report["extensions"]["org.androidtrustlab.collection"] = {
        "canonicalization": "atl-canonical-json-v1",
        "canonical_manifest_sha256": manifest_digest,
        "portable_binding": {
            "collection_id": report["raw_artifacts"][0]["collection_id"],
            "completion_status": manifest.completion_status,
            "collection_errors": manifest_errors,
            "raw_artifact_sha256": report["raw_artifacts"][0]["sha256"],
            "raw_artifact_status": report["raw_artifacts"][0]["status"],
            "redaction_state": report["raw_artifacts"][0]["redaction_state"],
            "artifact_results": [dict(result) for result in portable_results],
        },
    }
    report["extensions"][COMPARISON_CONTEXT_EXTENSION] = {
        "target_pseudonym": manifest.target.pseudonymous_id,
        "target_class": report["target"]["target_type"],
        "state_id": "unknown",
        "experiment_id": report["experiment_id"],
        "protocol": observer_protocol(report["observer"]["observer_type"]),
        "observer": report["observer"]["observer_type"],
        "observer_privilege": report["observer"]["privilege_level"],
        "report_schema_version": report["schema_version"],
        "environment_context": manifest.environment.execution_context,
        "measurement_id": report["collection_event_id"],
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
