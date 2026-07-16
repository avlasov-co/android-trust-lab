"""Build strict v2 reports from normalized v1-shaped evidence."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from ._version import __version__
from .compatibility import EvidenceStatus
from .migration_codec import encode_legacy_report, legacy_report_digest

ABSENT_REASON = "collection completed and the signal was absent"
MISSING_REASON = "source did not provide a usable observation"
INACCESSIBLE_REASON = "source recorded the signal as inaccessible"
UNREPRESENTABLE_REASON = "legacy value is outside v2 constraints; source is preserved"
REPORT_ID_RE = re.compile(r"^atl-[a-f0-9]{16}$")
EXPERIMENT_ID_RE = re.compile(r"^(?:unknown|E[0-9]{2}_[a-z0-9_]+)$")
COLLECTION_METHOD_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
REPORT_V1_VERSION = "1.0.0"
REPORT_V2_VERSION = "2.0.0"
MAX_CANONICAL_INTEGER = 9_007_199_254_740_991


def string_evidence(
    value: object, *, inaccessible_sentinel: bool = False
) -> dict[str, Any]:
    if inaccessible_sentinel and value == "inaccessible":
        return {
            "status": EvidenceStatus.INACCESSIBLE,
            "value": None,
            "reason": INACCESSIBLE_REASON,
        }
    if not isinstance(value, str) or not value or value == "unknown":
        return {
            "status": EvidenceStatus.NOT_COLLECTED,
            "value": None,
            "reason": MISSING_REASON,
        }
    if len(value) > 4096:
        return {
            "status": EvidenceStatus.NOT_COLLECTED,
            "value": None,
            "reason": UNREPRESENTABLE_REASON,
        }
    return {"status": EvidenceStatus.OBSERVED, "value": value, "reason": None}


def boolean_evidence(
    value: object, *, absence_was_observed: bool = False
) -> dict[str, Any]:
    if value is True:
        return {"status": EvidenceStatus.OBSERVED, "value": True, "reason": None}
    if value is False and absence_was_observed:
        return {
            "status": EvidenceStatus.OBSERVED_ABSENT,
            "value": False,
            "reason": ABSENT_REASON,
        }
    return {
        "status": EvidenceStatus.NOT_COLLECTED,
        "value": None,
        "reason": MISSING_REASON,
    }


def unavailable_boolean(status: EvidenceStatus, reason: str) -> dict[str, Any]:
    return {"status": status, "value": None, "reason": reason}


def string_list_evidence(
    value: object, *, absence_was_observed: bool = False
) -> dict[str, Any]:
    if not isinstance(value, list):
        return {
            "status": EvidenceStatus.NOT_COLLECTED,
            "value": None,
            "reason": MISSING_REASON,
        }
    if len(value) > 1024 or any(
        not isinstance(item, str) or not item or len(item) > 4096 for item in value
    ):
        return {
            "status": EvidenceStatus.NOT_COLLECTED,
            "value": None,
            "reason": UNREPRESENTABLE_REASON,
        }
    normalized = list(dict.fromkeys(value))
    if normalized:
        return {
            "status": EvidenceStatus.OBSERVED,
            "value": normalized,
            "reason": None,
        }
    if absence_was_observed:
        return {
            "status": EvidenceStatus.OBSERVED_ABSENT,
            "value": [],
            "reason": ABSENT_REASON,
        }
    return {
        "status": EvidenceStatus.NOT_COLLECTED,
        "value": None,
        "reason": MISSING_REASON,
    }


def string_map_evidence(
    value: object,
    *,
    absence_was_observed: bool = False,
    ambiguous_magic_values: bool = False,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {
            "status": EvidenceStatus.NOT_COLLECTED,
            "value": None,
            "reason": MISSING_REASON,
        }
    if len(value) > 4096 or any(
        not isinstance(key, str)
        or len(key) > 4096
        or not isinstance(item, str)
        or len(item) > 4096
        for key, item in value.items()
    ):
        return {
            "status": EvidenceStatus.NOT_COLLECTED,
            "value": None,
            "reason": UNREPRESENTABLE_REASON,
        }
    normalized = dict(value)
    if ambiguous_magic_values and any(
        item in {"unknown", "inaccessible"} for item in normalized.values()
    ):
        return {
            "status": EvidenceStatus.NOT_COLLECTED,
            "value": None,
            "reason": "legacy map contains ambiguous sentinel values; source is preserved",
        }
    if normalized:
        return {
            "status": EvidenceStatus.OBSERVED,
            "value": normalized,
            "reason": None,
        }
    if absence_was_observed:
        return {
            "status": EvidenceStatus.OBSERVED_ABSENT,
            "value": {},
            "reason": ABSENT_REASON,
        }
    return {
        "status": EvidenceStatus.NOT_COLLECTED,
        "value": None,
        "reason": MISSING_REASON,
    }


def integer_evidence(
    value: object, *, zero_was_observed: bool = False
) -> dict[str, Any]:
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_CANONICAL_INTEGER
        and (value > 0 or zero_was_observed)
    ):
        return {"status": EvidenceStatus.OBSERVED, "value": value, "reason": None}
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value > MAX_CANONICAL_INTEGER
    ):
        reason = UNREPRESENTABLE_REASON
    else:
        reason = MISSING_REASON
    return {
        "status": EvidenceStatus.NOT_COLLECTED,
        "value": None,
        "reason": reason,
    }


def mount_evidence(value: object, mount_point: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        value = {}
    fs_type = value.get("fs_type")
    classification = value.get("classification")
    raw = value.get("raw")
    options = value.get("options")
    options_valid = (
        isinstance(options, list)
        and len(options) <= 256
        and all(
            isinstance(item, str) and re.fullmatch(r"[^,\s]{1,128}", item) is not None
            for item in options
        )
    )
    observed = (
        isinstance(fs_type, str)
        and fs_type not in {"", "unknown"}
        and len(fs_type) <= 128
        and isinstance(classification, str)
        and classification not in {"", "unknown"}
        and isinstance(raw, str)
        and bool(raw)
        and len(raw) <= 16384
        and options_valid
    )
    if not observed:
        return {
            "status": EvidenceStatus.NOT_COLLECTED,
            "mount_point": mount_point,
            "fs_type": None,
            "options": [],
            "classification": None,
            "raw": None,
            "reason": MISSING_REASON,
        }
    allowed_classifications = {
        "read-only",
        "read-write",
        "overlay",
        "tmpfs",
        "other",
    }
    normalized_options = (
        list(dict.fromkeys(item for item in options if isinstance(item, str)))
        if isinstance(options, list)
        else []
    )
    return {
        "status": EvidenceStatus.OBSERVED,
        "mount_point": mount_point,
        "fs_type": fs_type,
        "options": normalized_options,
        "classification": classification
        if classification in allowed_classifications
        else "other",
        "raw": raw,
        "reason": None,
    }


def _object(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _bool(value: object) -> bool:
    return value if isinstance(value, bool) else False


def _report_id(source: dict[str, Any]) -> str:
    candidate = source.get("report_id")
    if isinstance(candidate, str) and REPORT_ID_RE.fullmatch(candidate):
        return candidate
    stable_source = json.dumps(
        source,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return "atl-" + hashlib.sha256(stable_source.encode("utf-8")).hexdigest()[:16]


def _experiment_id(value: object) -> str:
    if isinstance(value, str) and EXPERIMENT_ID_RE.fullmatch(value):
        return value
    return "unknown"


def _collection_method(value: object) -> str:
    if isinstance(value, str) and COLLECTION_METHOD_RE.fullmatch(value):
        return value
    return "legacy_migration"


def _raw_artifacts(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return list(
        dict.fromkeys(
            item for item in value if isinstance(item, str) and 1 <= len(item) <= 1024
        )
    )[:128]


def report_v2_from_v1_shape(
    source: dict[str, Any],
    *,
    preserve_legacy_source: bool,
    observed_probes: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Convert validated or freshly normalized v1-shaped data into report v2."""

    target = _object(source.get("target"))
    observer = _object(source.get("observer"))
    boot = _object(source.get("boot_state"))
    verified = _object(source.get("verified_boot"))
    selinux = _object(source.get("selinux"))
    mounts = _object(source.get("mounts"))
    properties = _object(source.get("properties"))
    root = _object(source.get("root_state"))
    magisk = _object(source.get("magisk_state"))
    processes = _object(source.get("process_state"))
    emulator = _object(source.get("emulator_state"))
    limitations = _object(source.get("limitations"))
    target_type = target.get("target_type")
    privilege_level = observer.get("privilege_level")
    selinux_mode = selinux.get("mode")
    if selinux_mode == "inaccessible":
        policy_visible = unavailable_boolean(
            EvidenceStatus.INACCESSIBLE, INACCESSIBLE_REASON
        )
    elif selinux_mode in {None, "", "unknown"}:
        policy_visible = unavailable_boolean(
            EvidenceStatus.NOT_COLLECTED, MISSING_REASON
        )
    else:
        policy_visible = boolean_evidence(
            selinux.get("policy_visible"),
            absence_was_observed="selinux" in observed_probes,
        )
    denials_collected = (
        boolean_evidence(True)
        if selinux.get("denials_collected") is True
        else unavailable_boolean(
            EvidenceStatus.NOT_COLLECTED, "SELinux denials were not collected"
        )
    )
    migration_history = (
        [
            {
                "migration_id": "report-v1-to-v2",
                "source_schema_version": REPORT_V1_VERSION,
                "target_schema_version": REPORT_V2_VERSION,
            }
        ]
        if preserve_legacy_source
        else []
    )
    if preserve_legacy_source:
        encoded_source = encode_legacy_report(source)
        extensions = {
            "org.androidtrustlab.migration": {
                "encoding": "canonical-json-text-v1",
                "source_report_json": encoded_source,
                "source_sha256": legacy_report_digest(encoded_source),
            }
        }
    else:
        extensions = {}

    properties_observed = "properties" in observed_probes
    mounts_observed = "mounts" in observed_probes
    processes_observed = "processes" in observed_probes

    return {
        "report_id": _report_id(source),
        "schema_version": REPORT_V2_VERSION,
        "collection_timestamp": source.get("collection_timestamp"),
        "experiment_id": _experiment_id(source.get("experiment_id")),
        "target": {
            "target_type": target_type
            if target_type in {"avd", "physical"}
            else "unspecified",
            "device_codename": string_evidence(target.get("device_codename")),
            "manufacturer": string_evidence(target.get("manufacturer")),
            "model": string_evidence(target.get("model")),
            "android_version": string_evidence(target.get("android_version")),
            "sdk": string_evidence(target.get("sdk")),
            "build_fingerprint": string_evidence(target.get("build_fingerprint")),
        },
        "observer": {
            "observer_type": observer.get("observer_type"),
            "privilege_level": privilege_level
            if privilege_level in {"host", "shell", "app_sandbox", "root"}
            else "unspecified",
            "collection_method": _collection_method(observer.get("collection_method")),
        },
        "boot_state": {
            "boot_completed": string_evidence(boot.get("boot_completed")),
            "boot_reason": string_evidence(boot.get("boot_reason")),
            "slot_suffix": string_evidence(boot.get("slot_suffix")),
            "kernel_cmdline_present": boolean_evidence(
                boot.get("kernel_cmdline_present"),
                absence_was_observed="cmdline" in observed_probes,
            ),
        },
        "verified_boot": {
            "verified_boot_state": string_evidence(verified.get("verified_boot_state")),
            "flash_locked": string_evidence(verified.get("flash_locked")),
            "vbmeta_device_state": string_evidence(verified.get("vbmeta_device_state")),
            "verity_mode": string_evidence(verified.get("verity_mode")),
            "raw_properties": string_map_evidence(
                verified.get("raw_properties"),
                absence_was_observed=properties_observed
                or "boot_state" in observed_probes,
                ambiguous_magic_values=preserve_legacy_source,
            ),
            "confidence": verified.get("confidence")
            if verified.get("confidence") in {"low", "medium", "high"}
            else "unassessed",
        },
        "selinux": {
            "mode": string_evidence(selinux_mode, inaccessible_sentinel=True),
            "policy_visible": policy_visible,
            "denials_collected": denials_collected,
        },
        "mounts": {
            "system_mount": mount_evidence(mounts.get("system_mount"), "/system"),
            "vendor_mount": mount_evidence(mounts.get("vendor_mount"), "/vendor"),
            "product_mount": mount_evidence(mounts.get("product_mount"), "/product"),
            "system_ext_mount": mount_evidence(
                mounts.get("system_ext_mount"), "/system_ext"
            ),
            "odm_mount": mount_evidence(mounts.get("odm_mount"), "/odm"),
            "data_mount": mount_evidence(mounts.get("data_mount"), "/data"),
            "apex_mount": mount_evidence(mounts.get("apex_mount"), "/apex"),
            "integrity_summary": {
                "overlay_detected": boolean_evidence(
                    mounts.get("overlay_detected"),
                    absence_was_observed=mounts_observed,
                ),
                "writable_sensitive_mounts": string_list_evidence(
                    mounts.get("writable_sensitive_mounts"),
                    absence_was_observed=mounts_observed,
                ),
            },
        },
        "properties": {
            "boot": string_map_evidence(
                properties.get("boot"),
                absence_was_observed=properties_observed,
                ambiguous_magic_values=preserve_legacy_source,
            ),
            "build": string_map_evidence(
                properties.get("build"),
                absence_was_observed=properties_observed,
                ambiguous_magic_values=preserve_legacy_source,
            ),
            "product": string_map_evidence(
                properties.get("product"),
                absence_was_observed=properties_observed,
                ambiguous_magic_values=preserve_legacy_source,
            ),
            "crypto": string_map_evidence(
                properties.get("crypto"),
                absence_was_observed=properties_observed,
                ambiguous_magic_values=preserve_legacy_source,
            ),
            "security": string_map_evidence(
                properties.get("security"),
                absence_was_observed=properties_observed,
                ambiguous_magic_values=preserve_legacy_source,
            ),
            "all_count": integer_evidence(
                properties.get("all_count"), zero_was_observed=properties_observed
            ),
        },
        "root_state": {
            "su_present": boolean_evidence(
                root.get("su_present"),
                absence_was_observed={"identity", "su_paths"} <= observed_probes,
            ),
            "uid": string_evidence(root.get("uid")),
            "gid": string_evidence(root.get("gid")),
            "root_shell_available": boolean_evidence(
                root.get("root_shell_available"),
                absence_was_observed="identity" in observed_probes,
            ),
            "root_paths": string_list_evidence(
                root.get("root_paths"),
                absence_was_observed="su_paths" in observed_probes,
            ),
        },
        "magisk_state": {
            "magisk_binary_present": boolean_evidence(
                magisk.get("magisk_binary_present"),
                absence_was_observed="magisk" in observed_probes,
            ),
            "magisk_version": string_evidence(magisk.get("magisk_version")),
            "magisk_path": string_evidence(magisk.get("magisk_path")),
            "zygisk_visible_indicators": string_list_evidence(
                magisk.get("zygisk_visible_indicators"),
                absence_was_observed="magisk" in observed_probes,
            ),
            "module_context": string_evidence(magisk.get("module_context")),
        },
        "process_state": {
            "adbd_visible": boolean_evidence(
                processes.get("adbd_visible"),
                absence_was_observed=processes_observed,
            ),
            "init_visible": boolean_evidence(
                processes.get("init_visible"),
                absence_was_observed=processes_observed,
            ),
            "magisk_processes_visible": boolean_evidence(
                processes.get("magisk_processes_visible"),
                absence_was_observed=processes_observed,
            ),
            "process_contexts_available": (
                boolean_evidence(True)
                if processes.get("process_contexts_available") is True
                else boolean_evidence(
                    processes.get("process_contexts_available"),
                    absence_was_observed=processes_observed,
                )
            ),
            "system_server_visible": boolean_evidence(
                processes.get("system_server_visible"),
                absence_was_observed=processes_observed,
            ),
            "zygote_visible": boolean_evidence(
                processes.get("zygote_visible"),
                absence_was_observed=processes_observed,
            ),
            "raw_line_count": integer_evidence(
                processes.get("raw_line_count"),
                zero_was_observed=processes_observed,
            ),
        },
        "emulator_state": {
            "is_emulator": boolean_evidence(
                emulator.get("is_emulator"),
                absence_was_observed="emulator_basis" in observed_probes,
            ),
            "indicators": string_list_evidence(
                emulator.get("indicators"),
                absence_was_observed="emulator_basis" in observed_probes,
            ),
        },
        "provenance": {
            "source_schema_version": REPORT_V1_VERSION
            if preserve_legacy_source
            else "raw",
            "normalizer": {"name": "trustlab", "version": __version__},
            "migration_history": migration_history,
            "command_results": [],
        },
        "limitations": {
            "emulator_target": _bool(limitations.get("emulator_target")),
            "missing_real_bootloader": _bool(
                limitations.get("missing_real_bootloader")
            ),
            "missing_tee_validation": _bool(limitations.get("missing_tee_validation")),
            "incomplete_permissions": _bool(limitations.get("incomplete_permissions")),
            "collection_errors": list(
                dict.fromkeys(
                    item
                    for item in limitations.get("collection_errors", [])
                    if isinstance(item, str) and 1 <= len(item) <= 1024
                )
            )[:256]
            if isinstance(limitations.get("collection_errors"), list)
            else [],
        },
        "raw_artifacts": _raw_artifacts(source.get("raw_artifacts")),
        "extensions": extensions,
    }
