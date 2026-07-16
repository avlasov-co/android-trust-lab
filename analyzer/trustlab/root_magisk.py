"""Structured root, Magisk, and evidence-confidence normalization."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from .artifacts import ArtifactParseResult, CaptureStatus, CommandCapture, InputKind
from .privacy import sanitize_metadata_value

_MAGISK_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:+-]{1,128}$", flags=re.ASCII)
_ROOT_PROBE_GRAMMAR = {
    "observer_effective_uid_is_root": frozenset({"observed", "observed_absent"}),
    "root_shell_available": frozenset({"observed", "observed_absent"}),
    "su_binary_observed": frozenset({"observed", "observed_absent"}),
    "su_invocation_tested": frozenset({"observed", "observed_absent"}),
    "su_invocation_result": frozenset(
        {"succeeded", "non_root", "denied", "failed", "not_tested"}
    ),
    "root_management_artifact_observed": frozenset({"observed", "observed_absent"}),
}
_MAGISK_VISIBILITY = frozenset({"observed", "observed_absent"})


def parse_root_probe(text: str) -> dict[str, str]:
    """Parse one fixed-grammar, value-free root probe."""

    result: dict[str, str] = {}
    for line in text.splitlines():
        if line.count("=") != 1:
            return {}
        key, value = line.strip().split("=", 1)
        allowed = _ROOT_PROBE_GRAMMAR.get(key)
        if allowed is None or value not in allowed or key in result:
            return {}
        result[key] = value
    if set(result) != set(_ROOT_PROBE_GRAMMAR):
        return {}
    tested = result["su_invocation_tested"] == "observed"
    has_result = result["su_invocation_result"] != "not_tested"
    return result if tested == has_result else {}


def parse_magisk_probe(text: str) -> dict[str, str]:
    """Parse bounded Magisk facts without accepting arbitrary text or paths."""

    result: dict[str, str] = {}
    for line in text.splitlines():
        if line.count("=") != 1:
            return {}
        key, value = line.strip().split("=", 1)
        if key in result:
            return {}
        if key in {"magisk_binary_visibility", "zygisk_visibility"}:
            if value not in _MAGISK_VISIBILITY:
                return {}
        elif key == "magisk_version_code":
            if re.fullmatch(r"[0-9]{1,12}", value) is None:
                return {}
        elif key in {"magisk_version_name", "module_context"}:
            if _MAGISK_TOKEN_RE.fullmatch(value) is None:
                return {}
        else:
            return {}
        result[key] = value
    required = {"magisk_binary_visibility", "zygisk_visibility"}
    return result if required <= set(result) else {}


def root_probe_syntax_is_valid(text: str) -> bool:
    return bool(parse_root_probe(text))


def magisk_probe_syntax_is_valid(text: str) -> bool:
    return bool(parse_magisk_probe(text))


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


def _portable_status(capture: CommandCapture | None) -> str:
    if capture is None:
        return "not_collected"
    return {
        CaptureStatus.OBSERVED: "observed",
        CaptureStatus.EMPTY: "observed",
        CaptureStatus.NOT_COLLECTED: "not_collected",
        CaptureStatus.INACCESSIBLE: "inaccessible",
        CaptureStatus.COMMAND_ERROR: "command_error",
        CaptureStatus.TIMEOUT: "command_error",
        CaptureStatus.UNSUPPORTED: "unsupported",
        CaptureStatus.ERROR: "command_error",
    }[capture.status]


def _unavailable(status: str, *, kind: str) -> dict[str, Any]:
    if status in {"observed", "observed_absent"}:
        status = "not_collected"
    reason = {
        "not_collected": f"the {kind} evidence was not collected",
        "inaccessible": f"the observer could not access {kind} evidence",
        "command_error": f"the {kind} probe did not complete successfully",
        "unsupported": f"the {kind} probe is unsupported for this observer",
    }.get(status, f"the {kind} evidence was unavailable")
    return {"status": status, "value": None, "reason": reason, "evidence_refs": []}


def _boolean(
    value: bool,
    *,
    capture: CommandCapture,
    absent_reason: str,
) -> dict[str, Any]:
    return {
        "status": "observed" if value else "observed_absent",
        "value": value,
        "reason": None if value else absent_reason,
        "evidence_refs": [capture.source_ref],
    }


def _string(value: str, *, capture: CommandCapture) -> dict[str, Any]:
    return {
        "status": "observed",
        "value": value,
        "reason": None,
        "evidence_refs": [capture.source_ref],
    }


def _status_observation(capture: CommandCapture | None, *, kind: str) -> dict[str, Any]:
    status = _portable_status(capture)
    if status == "observed" and capture is not None:
        return {"status": status, "reason": None, "evidence_refs": [capture.source_ref]}
    unavailable = _unavailable(status, kind=kind)
    return {
        "status": unavailable["status"],
        "reason": unavailable["reason"],
        "evidence_refs": [],
    }


def _root_probe_value(
    facts: Mapping[str, str],
    key: str,
    *,
    capture: CommandCapture | None,
) -> dict[str, Any]:
    status = _portable_status(capture)
    if status != "observed" or capture is None or key not in facts:
        return _unavailable(status, kind=key.replace("_", " "))
    return _boolean(
        facts[key] == "observed",
        capture=capture,
        absent_reason=f"the {key.replace('_', ' ')} condition was not observed",
    )


def structured_root_state(
    parsed: ArtifactParseResult, *, observer_type: str
) -> dict[str, Any]:
    """Keep observer identity, root shell, su, and management facts independent."""

    root_capture = _capture_for(parsed.captures, "root_probe")
    facts = parse_root_probe(root_capture.stdout) if root_capture else {}
    identity = _capture_for(parsed.captures, "identity", "id")
    identity_status = _portable_status(identity)
    if root_capture is not None and facts:
        uid_is_root = _root_probe_value(
            facts, "observer_effective_uid_is_root", capture=root_capture
        )
        root_shell = _root_probe_value(
            facts, "root_shell_available", capture=root_capture
        )
        su_binary = _root_probe_value(facts, "su_binary_observed", capture=root_capture)
        su_tested = _root_probe_value(
            facts, "su_invocation_tested", capture=root_capture
        )
        management = _root_probe_value(
            facts, "root_management_artifact_observed", capture=root_capture
        )
        result_value = facts["su_invocation_result"]
        su_result = (
            _unavailable("not_collected", kind="su invocation result")
            if result_value == "not_tested"
            else _string(result_value, capture=root_capture)
        )
    else:
        uid = parsed.fragments.identity.get("uid", "unknown")
        uid_is_root = (
            _boolean(
                uid == "0",
                capture=identity,
                absent_reason="the observer effective UID was not root",
            )
            if identity_status == "observed"
            and identity is not None
            and uid != "unknown"
            else _unavailable(identity_status, kind="observer effective UID")
        )
        root_shell = _unavailable("not_collected", kind="root shell availability")
        su_capture = _capture_for(parsed.captures, "su_paths")
        su_status = _portable_status(su_capture)
        if su_status == "observed" and su_capture is not None:
            su_binary = _boolean(
                bool(parsed.fragments.su_paths),
                capture=su_capture,
                absent_reason="the su binary was not observed",
            )
        else:
            su_binary = _unavailable(su_status, kind="su binary")
        su_tested = _unavailable("not_collected", kind="su invocation test")
        su_result = _unavailable("not_collected", kind="su invocation result")
        management = _unavailable("not_collected", kind="root-management artifact")
    limitations = []
    if root_shell["status"] == "not_collected":
        limitations.append("root_shell_not_tested")
    if su_tested["status"] == "not_collected":
        limitations.append("su_not_tested")
    if root_capture is None or root_capture.status is not CaptureStatus.OBSERVED:
        limitations.append("independent_root_probe_not_collected")
    return {
        "source_observer": observer_type,
        "observer_effective_uid_is_root": uid_is_root,
        "root_shell_available": root_shell,
        "su_binary_observed": su_binary,
        "su_invocation_tested": su_tested,
        "su_invocation_result": su_result,
        "root_management_artifact_observed": management,
        "limitations": sorted(limitations),
    }


def _process_visibility(
    processes: Mapping[str, Any], names: frozenset[str], *, label: str
) -> dict[str, Any]:
    selected = {
        item.get("name"): item
        for item in processes.get("selected_processes", [])
        if isinstance(item, Mapping) and item.get("name") in names
    }
    observations = [selected[name] for name in sorted(names) if name in selected]
    true_items = [
        item for item in observations if item["visibility"]["status"] == "observed"
    ]
    refs = sorted(
        {ref for item in observations for ref in item.get("evidence_refs", [])}
    )
    if not refs:
        refs = sorted(
            ref for ref in processes.get("evidence_refs", []) if isinstance(ref, str)
        )
    if true_items:
        return {
            "status": "observed",
            "value": True,
            "reason": None,
            "evidence_refs": refs,
        }
    if observations and all(
        item["visibility"]["status"] == "observed_absent" for item in observations
    ):
        return {
            "status": "observed_absent",
            "value": False,
            "reason": f"the {label} was not visible in the complete process evidence",
            "evidence_refs": refs,
        }
    status = processes.get("capture_status", "not_collected")
    return _unavailable(status, kind=label)


def structured_magisk_state(
    parsed: ArtifactParseResult,
    *,
    processes: Mapping[str, Any],
    pseudonym_scope: str,
    observer_type: str,
) -> dict[str, Any]:
    """Normalize Magisk dimensions without substring or path inference."""

    capture = _capture_for(parsed.captures, "magisk")
    status = _portable_status(capture)
    facts = parse_magisk_probe(capture.stdout) if capture else {}
    if status == "observed" and capture is not None and facts:
        binary = _boolean(
            facts["magisk_binary_visibility"] == "observed",
            capture=capture,
            absent_reason="the Magisk binary was not visible",
        )
        zygisk = _boolean(
            facts["zygisk_visibility"] == "observed",
            capture=capture,
            absent_reason="a Zygisk indicator was not visible",
        )
        version_name = (
            _string(
                sanitize_metadata_value(
                    facts["magisk_version_name"],
                    category="magisk-version-name",
                    scope=pseudonym_scope,
                ),
                capture=capture,
            )
            if "magisk_version_name" in facts
            else _unavailable("not_collected", kind="Magisk version name")
        )
        version_code = (
            _string(facts["magisk_version_code"], capture=capture)
            if "magisk_version_code" in facts
            else _unavailable("not_collected", kind="Magisk version code")
        )
        module_context = (
            _string(
                sanitize_metadata_value(
                    facts["module_context"],
                    category="module-context",
                    scope=pseudonym_scope,
                ),
                capture=capture,
            )
            if "module_context" in facts
            else _unavailable("not_collected", kind="Magisk module context")
        )
    elif capture is not None and (
        capture.status is CaptureStatus.EMPTY
        or capture.stdout.strip().lower() == "magisk: not found in path"
    ):
        binary = _boolean(
            False,
            capture=capture,
            absent_reason="the Magisk binary was not visible",
        )
        zygisk = _unavailable("not_collected", kind="Zygisk visibility")
        version_name = _unavailable("not_collected", kind="Magisk version name")
        version_code = _unavailable("not_collected", kind="Magisk version code")
        module_context = _unavailable("not_collected", kind="Magisk module context")
    else:
        binary = _unavailable(status, kind="Magisk binary visibility")
        zygisk = _unavailable(status, kind="Zygisk visibility")
        version_name = _unavailable(status, kind="Magisk version name")
        version_code = _unavailable(status, kind="Magisk version code")
        module_context = _unavailable(status, kind="Magisk module context")
    daemon = _process_visibility(
        processes, frozenset({"magiskd"}), label="Magisk daemon"
    )
    process = _process_visibility(
        processes, frozenset({"magisk", "magiskd"}), label="Magisk process"
    )
    limitations = ["zygisk_indicator_not_runtime_proof"]
    if processes.get("scope") != "complete":
        limitations.append("process_visibility_scoped")
    if daemon["status"] not in {"observed", "observed_absent"}:
        limitations.append("daemon_visibility_inconclusive")
    if status != "observed":
        limitations.append("magisk_command_unavailable")
    return {
        "source_observer": observer_type,
        "binary_visibility": binary,
        "daemon_visibility": daemon,
        "process_visibility": process,
        "zygisk_visibility": zygisk,
        "version_name": version_name,
        "version_code": version_code,
        "module_context": module_context,
        "command_status": _status_observation(capture, kind="Magisk command"),
        "limitations": sorted(limitations),
    }


def verified_boot_confidence(
    parsed: ArtifactParseResult,
    *,
    observer_privilege: str,
    target_type: str,
    values: Mapping[str, str],
) -> dict[str, Any]:
    """Assess evidence quality from traceable factors, never target type alone."""

    relevant = [
        capture
        for capture in parsed.captures
        if capture.name in {"properties", "getprop_selected", "boot_state"}
    ]
    observed = [
        capture
        for capture in relevant
        if capture.status in {CaptureStatus.OBSERVED, CaptureStatus.EMPTY}
    ]
    has_legacy_inferred_status = any(
        capture.source_ref.startswith("legacy-sections/") for capture in relevant
    )
    failures = [
        capture
        for capture in relevant
        if capture.status
        in {
            CaptureStatus.INACCESSIBLE,
            CaptureStatus.COMMAND_ERROR,
            CaptureStatus.TIMEOUT,
            CaptureStatus.ERROR,
        }
    ]
    count = sum(value != "unknown" for value in values.values())
    source_quality = (
        "structured_capture"
        if parsed.input_kind is not InputKind.LEGACY_SECTIONED_TEXT
        and observed
        and not has_legacy_inferred_status
        else "legacy_inferred"
        if observed
        else "unavailable"
    )
    command_success = (
        "complete"
        if observed and not failures and count == len(values)
        else "partial"
        if observed and count
        else "failed"
        if failures
        else "not_collected"
    )
    observer_capability = (
        observer_privilege
        if observer_privilege in {"host", "shell", "app_sandbox", "root"}
        else "unspecified"
    )
    limitations = ["hardware_attestation_not_collected"]
    if target_type == "avd":
        limitations.append("virtual_target_not_hardware_backed")
    if (
        parsed.input_kind is InputKind.LEGACY_SECTIONED_TEXT
        or has_legacy_inferred_status
    ):
        limitations.append("legacy_capture_status_inferred")
    if observer_capability in {"app_sandbox", "unspecified"}:
        limitations.append("observer_capability_limited")
    if count == 0:
        level = "unassessed"
    elif (
        source_quality == "structured_capture"
        and command_success == "complete"
        and observer_capability in {"shell", "root"}
    ):
        level = "medium"
    else:
        level = "low"
    return {
        "level": level,
        "source_quality": source_quality,
        "command_success": command_success,
        "observer_capability": observer_capability,
        "corroborating_signal_count": count,
        "target_limitations": sorted(limitations),
        "evidence_refs": sorted({capture.source_ref for capture in observed}),
    }
