"""Build and verify the linked synthetic Step 35 cross-observer fixture."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from trustlab.collection_manifest import CollectionManifest
from trustlab.comparison import (
    COMPARISON_CONTEXT_EXTENSION,
    attach_comparison_context,
)
from trustlab.dataset_manifest import (
    MAX_DATASET_ARTIFACT_BYTES,
    MAX_DATASET_JSON_BYTES,
    parse_dataset_json,
    read_regular_file_beneath,
    stable_pretty_json_bytes,
)
from trustlab.diff import make_diff
from trustlab.dimension_registry import (
    TRUST_DIMENSIONS_BY_ID,
    comparison_value,
    extract_dimension,
)
from trustlab.dimension_rendering import dimension_label, render_dimension
from trustlab.exceptions import SchemaValidationError
from trustlab.normalizer import normalize_collection_payload
from trustlab.validators import validate_diff, validate_report

CROSS_OBSERVER_RELATIVE = Path("tests/fixtures/cross_observer_bundle")
CROSS_OBSERVER_MATRIX_RELATIVE = Path("results/figures/cross_observer_matrix.md")

_OBSERVER_LAYOUT = {
    "app": {
        "observer_type": "unprivileged_app",
        "visibility_protocol": "app",
        "raw_path": "app/app_probe.json",
        "manifest_path": "app/collection_manifest.json",
        "report_path": "generated/reports/app_report.json",
    },
    "adb": {
        "observer_type": "adb_shell",
        "visibility_protocol": "adb",
        "raw_path": "adb/adb_snapshot.txt",
        "manifest_path": "adb/collection_manifest.json",
        "report_path": "generated/reports/adb_report.json",
    },
    "root": {
        "observer_type": "root_collector",
        "visibility_protocol": "root",
        "raw_path": "root/raw.txt",
        "manifest_path": "root/collection_manifest.json",
        "report_path": "generated/reports/root_report.json",
    },
}

_PAIR_LAYOUT = {
    "app-vs-adb": {
        "base_observer_id": "app",
        "compare_observer_id": "adb",
        "diff_path": "generated/diffs/app_vs_adb.json",
    },
    "app-vs-root": {
        "base_observer_id": "app",
        "compare_observer_id": "root",
        "diff_path": "generated/diffs/app_vs_root.json",
    },
    "adb-vs-root": {
        "base_observer_id": "adb",
        "compare_observer_id": "root",
        "diff_path": "generated/diffs/adb_vs_root.json",
    },
}

_MANIFEST_TRANSPORTS = {
    "app": "app_api",
    "adb": "adb",
    "root": "on_device",
}

_MATRIX_DIMENSIONS = (
    "verified_boot_state",
    "selinux_mode",
    "selinux_current_context",
    "mount_integrity",
    "su_binary_visibility",
    "root_shell_availability",
    "magisk_binary_visibility",
    "emulator_state",
)

_EXPECTED_VISIBILITY_TRANSITIONS = {
    ("app-vs-adb", "selinux_current_context"),
    ("app-vs-root", "selinux_current_context"),
}
_EXPECTED_SHARED_OBSERVERS = {
    "emulator_state": frozenset({"app", "adb", "root"}),
    "verified_boot_state": frozenset({"adb", "root"}),
    "mount_integrity": frozenset({"adb", "root"}),
    "su_binary_visibility": frozenset({"adb", "root"}),
}
_EXPECTED_CONTRADICTIONS = {("adb-vs-root", "selinux_mode")}


@dataclass(frozen=True, slots=True)
class CrossObserverArtifacts:
    """Validated in-memory source graph plus deterministic generated outputs."""

    contract: dict[str, Any]
    reports_by_observer: dict[str, dict[str, Any]]
    diffs_by_pair: dict[str, dict[str, Any]]
    diff_entries: list[tuple[dict[str, Any], dict[str, Any]]]
    outputs: dict[Path, bytes]


def _contract_error(detail: str) -> SchemaValidationError:
    return SchemaValidationError(f"cross-observer fixture contract failed: {detail}")


def _exact_object(value: object, fields: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise _contract_error(f"{label} has unexpected fields")
    return value


def _string(value: object, *, label: str, pattern: str | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise _contract_error(f"{label} must be a non-empty string")
    if pattern is not None and re.fullmatch(pattern, value) is None:
        raise _contract_error(f"{label} has an invalid value")
    return value


def _string_list(value: object, *, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
        or len(value) != len(set(value))
    ):
        raise _contract_error(f"{label} must contain unique strings")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read(bundle_root: Path, relative_path: str, *, json_input: bool) -> bytes:
    return read_regular_file_beneath(
        bundle_root,
        relative_path,
        limit=MAX_DATASET_JSON_BYTES if json_input else MAX_DATASET_ARTIFACT_BYTES,
        label="cross-observer fixture input",
    )


def _validate_contract_identity(contract: dict[str, Any]) -> None:
    if contract["schema_version"] != "1.0.0":
        raise _contract_error("unsupported expectations schema version")
    _string(contract["bundle_id"], label="bundle ID", pattern=r"[a-z][a-z0-9-]{2,127}")
    if contract["origin_classification"] != "synthetic":
        raise _contract_error("fixture origin must remain synthetic")
    _string(
        contract["experimental_protocol_id"],
        label="experimental protocol ID",
        pattern=r"[a-z][a-z0-9_]{2,63}",
    )
    _string(
        contract["experiment_id"],
        label="experiment ID",
        pattern=r"E[0-9]{2}_[a-z0-9_]+",
    )
    target = _exact_object(
        contract["target"],
        {"pseudonymous_id", "target_type", "state_id"},
        label="target",
    )
    _string(
        target["pseudonymous_id"],
        label="target pseudonym",
        pattern=r"target-[a-f0-9]{16}",
    )
    if target["target_type"] != "avd":
        raise _contract_error("synthetic cross-observer target must be an AVD model")
    _string(target["state_id"], label="state ID", pattern=r"state-[a-z0-9-]{3,127}")
    limitations = _string_list(contract["limitations"], label="limitations")
    if not any(
        "does not represent physical OEM behavior" in item for item in limitations
    ):
        raise _contract_error("limitations must reject physical OEM inference")


def _validate_observer_layout(contract: dict[str, Any]) -> None:
    observers = contract["observers"]
    if not isinstance(observers, list) or len(observers) != 3:
        raise _contract_error("exactly three observers are required")
    seen_observers: set[str] = set()
    seen_hashes: set[str] = set()
    for raw_entry in observers:
        entry = _exact_object(
            raw_entry,
            {
                "observer_id",
                "observer_type",
                "visibility_protocol",
                "raw_path",
                "manifest_path",
                "report_path",
                "raw_sha256",
                "manifest_sha256",
            },
            label="observer entry",
        )
        observer_id = _string(entry["observer_id"], label="observer ID")
        expected = _OBSERVER_LAYOUT.get(observer_id)
        if expected is None or any(
            entry.get(key) != value for key, value in expected.items()
        ):
            raise _contract_error("observer layout does not match the fixed bundle")
        if observer_id in seen_observers:
            raise _contract_error("observer IDs must be unique")
        seen_observers.add(observer_id)
        for field in ("raw_sha256", "manifest_sha256"):
            digest = _string(entry[field], label=field, pattern=r"[a-f0-9]{64}")
            if digest in seen_hashes:
                raise _contract_error("source and manifest hashes must be independent")
            seen_hashes.add(digest)
    if seen_observers != set(_OBSERVER_LAYOUT):
        raise _contract_error("app, ADB, and root observers are required")


def _validate_pair_layout(contract: dict[str, Any]) -> None:
    pairs = contract["pairs"]
    if not isinstance(pairs, list) or len(pairs) != 3:
        raise _contract_error("exactly three observer pairs are required")
    seen_pairs: set[str] = set()
    for raw_entry in pairs:
        entry = _exact_object(
            raw_entry,
            {
                "pair_id",
                "title",
                "base_observer_id",
                "compare_observer_id",
                "diff_path",
            },
            label="pair entry",
        )
        pair_id = _string(entry["pair_id"], label="pair ID")
        expected = _PAIR_LAYOUT.get(pair_id)
        if expected is None or any(
            entry.get(key) != value for key, value in expected.items()
        ):
            raise _contract_error("pair layout does not match the fixed bundle")
        _string(entry["title"], label="pair title")
        if pair_id in seen_pairs:
            raise _contract_error("pair IDs must be unique")
        seen_pairs.add(pair_id)
    if seen_pairs != set(_PAIR_LAYOUT):
        raise _contract_error("all pairwise observer comparisons are required")


def _validate_expectation_shape(contract: dict[str, Any]) -> None:
    expectations = _exact_object(
        contract["expectations"],
        {
            "comparison_axis",
            "forbidden_directions",
            "visibility_transitions",
            "shared_dimensions",
            "contradictions",
        },
        label="expectations",
    )
    if expectations["comparison_axis"] != "same_state_observer_change":
        raise _contract_error("observer pairs must use the observer-change axis")
    if expectations["forbidden_directions"] != ["improvement", "regression"]:
        raise _contract_error("target-state directions must remain forbidden")
    for field in ("visibility_transitions", "shared_dimensions", "contradictions"):
        if not isinstance(expectations[field], list) or not expectations[field]:
            raise _contract_error(f"{field} expectations are required")


def _validate_contract_shape(contract: dict[str, Any]) -> None:
    _exact_object(
        contract,
        {
            "schema_version",
            "bundle_id",
            "origin_classification",
            "experimental_protocol_id",
            "experiment_id",
            "target",
            "observers",
            "pairs",
            "expectations",
            "limitations",
        },
        label="root",
    )
    _validate_contract_identity(contract)
    _validate_observer_layout(contract)
    _validate_pair_layout(contract)
    _validate_expectation_shape(contract)


def _reject_unowned_generated_entries(
    bundle_root: Path, contract: dict[str, Any]
) -> None:
    generated_root = bundle_root / "generated"
    if generated_root.is_symlink():
        raise _contract_error("generated output root must be a regular directory")
    if not generated_root.exists():
        return
    if not generated_root.is_dir():
        raise _contract_error("generated output root must be a regular directory")

    expected_by_directory = {
        "reports": {Path(entry["report_path"]).name for entry in contract["observers"]},
        "diffs": {Path(entry["diff_path"]).name for entry in contract["pairs"]},
    }
    root_entries = {entry.name: entry for entry in generated_root.iterdir()}
    if not set(root_entries) <= set(expected_by_directory):
        raise _contract_error("generated output root contains an unowned entry")
    for directory_name, expected_names in expected_by_directory.items():
        directory = generated_root / directory_name
        if directory.is_symlink():
            raise _contract_error("generated output directory is not regular")
        if not directory.exists():
            continue
        if not directory.is_dir():
            raise _contract_error("generated output directory is not regular")
        for entry in directory.iterdir():
            if (
                entry.name not in expected_names
                or entry.is_symlink()
                or not entry.is_file()
            ):
                raise _contract_error(
                    "generated output directory contains an unowned entry"
                )


def _evidence_refs(value: object) -> list[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        raw_refs = value.get("evidence_refs")
        if isinstance(raw_refs, list):
            refs.update(item for item in raw_refs if isinstance(item, str))
        for nested in value.values():
            refs.update(_evidence_refs(nested))
    elif isinstance(value, list):
        for nested in value:
            refs.update(_evidence_refs(nested))
    return sorted(refs)


def _dimension(report: dict[str, Any], dimension_id: str) -> Any:
    try:
        definition = TRUST_DIMENSIONS_BY_ID[dimension_id]
    except KeyError as exc:
        raise _contract_error("expectation names an unregistered dimension") from exc
    return extract_dimension(report, definition)


def _changed(diff: dict[str, Any], dimension_id: str) -> dict[str, Any]:
    matches = [
        item for item in diff["changed_dimensions"] if item["dimension"] == dimension_id
    ]
    if len(matches) != 1:
        raise _contract_error("expected changed dimension is absent or duplicated")
    return cast(dict[str, Any], matches[0])


def _validate_manual_expectations(  # noqa: C901 - fixed expectation dispatch
    contract: dict[str, Any],
    reports: dict[str, dict[str, Any]],
    diffs: dict[str, dict[str, Any]],
) -> None:
    expectations = contract["expectations"]
    axis = expectations["comparison_axis"]
    forbidden = set(expectations["forbidden_directions"])
    for diff in diffs.values():
        if diff["comparison"]["axis"] != axis:
            raise _contract_error("pairwise diff does not use the expected axis")
        if forbidden & {item["direction"] for item in diff["changed_dimensions"]}:
            raise _contract_error(
                "observer-axis diff contains a target-state direction"
            )

    visibility_coverage: list[tuple[str, str]] = []
    for raw_entry in expectations["visibility_transitions"]:
        entry = _exact_object(
            raw_entry,
            {
                "pair_id",
                "dimension",
                "before_status",
                "after_status",
                "classification",
                "direction",
                "confidence_level",
            },
            label="visibility transition expectation",
        )
        pair_id = _string(entry["pair_id"], label="visibility pair ID")
        dimension_id = _string(
            entry["dimension"], label="visibility transition dimension"
        )
        if pair_id not in diffs:
            raise _contract_error("visibility expectation references an unknown pair")
        visibility_coverage.append((pair_id, dimension_id))
        change = _changed(diffs[pair_id], dimension_id)
        observed = {
            "before_status": change["transition"]["before_status"],
            "after_status": change["transition"]["after_status"],
            "classification": change["transition"]["classification"],
            "direction": change["direction"],
            "confidence_level": change["confidence"]["level"],
        }
        if any(observed[key] != entry[key] for key in observed):
            raise _contract_error("visibility transition does not match expectations")
    if (
        len(visibility_coverage) != len(_EXPECTED_VISIBILITY_TRANSITIONS)
        or set(visibility_coverage) != _EXPECTED_VISIBILITY_TRANSITIONS
    ):
        raise _contract_error("visibility expectations do not cover both app pairs")

    shared_coverage: dict[str, frozenset[str]] = {}
    for raw_entry in expectations["shared_dimensions"]:
        entry = _exact_object(
            raw_entry,
            {"dimension", "observer_ids", "expected"},
            label="shared dimension expectation",
        )
        dimension_id = _string(entry["dimension"], label="shared dimension")
        observer_ids = _string_list(entry["observer_ids"], label="shared observers")
        if not set(observer_ids) <= set(reports):
            raise _contract_error("shared expectation references an unknown observer")
        if dimension_id in shared_coverage:
            raise _contract_error("shared dimension expectations must be unique")
        shared_coverage[dimension_id] = frozenset(observer_ids)
        for observer_id in observer_ids:
            observed = comparison_value(_dimension(reports[observer_id], dimension_id))
            if observed != entry["expected"]:
                raise _contract_error("shared evidence differs across observers")
    if shared_coverage != _EXPECTED_SHARED_OBSERVERS:
        raise _contract_error("shared expectations do not cover the fixed evidence set")

    pair_entries = {entry["pair_id"]: entry for entry in contract["pairs"]}
    contradiction_coverage: list[tuple[str, str]] = []
    for raw_entry in expectations["contradictions"]:
        entry = _exact_object(
            raw_entry,
            {
                "pair_id",
                "dimension",
                "before",
                "after",
                "classification",
                "direction",
                "confidence_level",
                "before_evidence_refs",
                "after_evidence_refs",
            },
            label="contradiction expectation",
        )
        pair_id = _string(entry["pair_id"], label="contradiction pair ID")
        pair = pair_entries.get(pair_id)
        if pair is None:
            raise _contract_error("contradiction references an unknown pair")
        dimension_id = _string(entry["dimension"], label="contradiction dimension")
        contradiction_coverage.append((pair_id, dimension_id))
        change = _changed(diffs[pair_id], dimension_id)
        observed = {
            "before": change["before"],
            "after": change["after"],
            "classification": change["transition"]["classification"],
            "direction": change["direction"],
            "confidence_level": change["confidence"]["level"],
        }
        if any(observed[key] != entry[key] for key in observed):
            raise _contract_error("contradiction value or confidence changed")
        base_id = pair["base_observer_id"]
        compare_id = pair["compare_observer_id"]
        before_refs = _evidence_refs(_dimension(reports[base_id], dimension_id))
        after_refs = _evidence_refs(_dimension(reports[compare_id], dimension_id))
        if (
            before_refs != entry["before_evidence_refs"]
            or after_refs != entry["after_evidence_refs"]
        ):
            raise _contract_error("contradiction evidence provenance changed")
    if (
        len(contradiction_coverage) != len(_EXPECTED_CONTRADICTIONS)
        or set(contradiction_coverage) != _EXPECTED_CONTRADICTIONS
    ):
        raise _contract_error("contradiction expectations do not cover ADB versus root")


def _matrix_markdown(
    contract: dict[str, Any], reports: dict[str, dict[str, Any]]
) -> bytes:
    lines = [
        "# Cross-observer evidence matrix",
        "",
        "Generated from one project-authored synthetic target state. This is not an AVD capture and does not represent physical OEM behavior.",
        "",
        f"Shared experimental protocol: `{contract['experimental_protocol_id']}`; experiment: `{contract['experiment_id']}`; state: `{contract['target']['state_id']}`.",
        "Observer visibility protocols remain distinct (`app`, `adb`, and `root`) by design.",
        "",
        "| Dimension | App sandbox | ADB shell | Root collector |",
        "|---|---|---|---|",
    ]
    for dimension_id in _MATRIX_DIMENSIONS:
        rendered = [
            render_dimension(reports[observer_id], dimension_id).replace("|", "\\|")
            for observer_id in ("app", "adb", "root")
        ]
        lines.append(
            f"| {dimension_label(dimension_id)} | {rendered[0]} | {rendered[1]} | {rendered[2]} |"
        )
    lines += [
        "",
        "All three pairwise diffs classify as `same_state_observer_change`. App-inaccessible SELinux context becomes `context_change`, not regression. The ADB/root SELinux-mode disagreement remains a provenance-bound, moderate-confidence contradiction.",
        "",
    ]
    return "\n".join(lines).encode()


def build_cross_observer_artifacts(root: Path) -> CrossObserverArtifacts:
    """Validate source links and return all deterministic cross-observer outputs."""

    bundle_root = root / CROSS_OBSERVER_RELATIVE
    contract_payload = _read(bundle_root, "expectations.json", json_input=True)
    contract = parse_dataset_json(contract_payload, label="cross-observer expectations")
    _validate_contract_shape(contract)
    _reject_unowned_generated_entries(bundle_root, contract)

    reports: dict[str, dict[str, Any]] = {}
    outputs: dict[Path, bytes] = {}
    collection_ids: set[str] = set()
    raw_hashes: set[str] = set()
    target = contract["target"]
    for observer_entry in contract["observers"]:
        observer_id = observer_entry["observer_id"]
        raw_payload = _read(
            bundle_root,
            observer_entry["raw_path"],
            json_input=observer_id == "app",
        )
        manifest_payload = _read(
            bundle_root, observer_entry["manifest_path"], json_input=True
        )
        if _sha256(raw_payload) != observer_entry["raw_sha256"]:
            raise _contract_error("raw source hash does not match expectations")
        if _sha256(manifest_payload) != observer_entry["manifest_sha256"]:
            raise _contract_error("manifest hash does not match expectations")
        manifest_document = parse_dataset_json(
            manifest_payload, label="cross-observer collection manifest"
        )
        manifest = CollectionManifest.from_dict(manifest_document)
        raw_entries = [
            artifact
            for artifact in manifest.artifacts
            if artifact.logical_name == "raw_report"
        ]
        if len(raw_entries) != 1:
            raise _contract_error("manifest must bind exactly one raw report")
        raw_entry = raw_entries[0]
        if (
            manifest.experiment_id != contract["experiment_id"]
            or manifest.target.pseudonymous_id != target["pseudonymous_id"]
            or manifest.target.target_type != target["target_type"]
            or manifest.observer.observer_type != observer_entry["observer_type"]
            or manifest.environment.transport != _MANIFEST_TRANSPORTS[observer_id]
            or raw_entry.relative_path != Path(observer_entry["raw_path"]).name
            or raw_entry.sha256 != observer_entry["raw_sha256"]
            or raw_entry.byte_size != len(raw_payload)
        ):
            raise _contract_error("collection manifest does not match its bundle link")
        expected_media_type = (
            "application/json" if observer_id == "app" else "text/plain"
        )
        if raw_entry.media_type != expected_media_type:
            raise _contract_error("raw artifact media type is not observer-appropriate")
        if manifest.collection_id in collection_ids:
            raise _contract_error("collection IDs must be independent")
        collection_ids.add(manifest.collection_id)
        raw_hashes.add(observer_entry["raw_sha256"])

        report = normalize_collection_payload(
            raw_payload,
            manifest,
            label=Path(observer_entry["raw_path"]).name,
        )
        report = attach_comparison_context(
            report,
            target_pseudonym=target["pseudonymous_id"],
            state_id=target["state_id"],
            environment_context=contract["origin_classification"],
        )
        validate_report(report)
        comparison = report["extensions"][COMPARISON_CONTEXT_EXTENSION]
        if (
            comparison["protocol"] != observer_entry["visibility_protocol"]
            or comparison["state_id"] != target["state_id"]
            or report["raw_artifacts"][0]["sha256"] != observer_entry["raw_sha256"]
        ):
            raise _contract_error(
                "normalized report lost observer or source provenance"
            )
        reports[observer_id] = report
        outputs[bundle_root / observer_entry["report_path"]] = stable_pretty_json_bytes(
            report
        )
    if len(raw_hashes) != 3:
        raise _contract_error("each observer requires an independent source hash")

    diffs: dict[str, dict[str, Any]] = {}
    diff_entries: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for pair in contract["pairs"]:
        base = reports[pair["base_observer_id"]]
        compare = reports[pair["compare_observer_id"]]
        diff = make_diff(base, compare)
        validate_diff(diff)
        if (
            diff["base_report"]["report_id"] != base["report_id"]
            or diff["compare_report"]["report_id"] != compare["report_id"]
            or diff["provenance"]["base"]["common_report"] != diff["base_report"]
            or diff["provenance"]["compare"]["common_report"] != diff["compare_report"]
        ):
            raise _contract_error("diff provenance does not bind both reports")
        pair_id = pair["pair_id"]
        diffs[pair_id] = diff
        diff_entries.append((pair, diff))
        outputs[bundle_root / pair["diff_path"]] = stable_pretty_json_bytes(diff)

    _validate_manual_expectations(contract, reports, diffs)
    outputs[root / CROSS_OBSERVER_MATRIX_RELATIVE] = _matrix_markdown(contract, reports)
    return CrossObserverArtifacts(
        contract=contract,
        reports_by_observer=reports,
        diffs_by_pair=diffs,
        diff_entries=diff_entries,
        outputs=outputs,
    )
