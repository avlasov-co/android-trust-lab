#!/usr/bin/env python3
"""Generate Android Trust Lab sample reports, diffs, and markdown result tables.

This script intentionally uses checked-in synthetic/AVD-limited samples. It is not a
replacement for real device collection. It keeps derived artifacts reproducible so
reviewers can see that results are derived from checked-in data rather than hand-written summaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from trustlab import __version__
from trustlab.collection_manifest import CollectionManifest
from trustlab.comparison import attach_comparison_context
from trustlab.dataset_manifest import (
    MAX_DATASET_ARTIFACT_BYTES,
    MAX_DATASET_JSON_BYTES,
    MAX_DATASET_TOTAL_BYTES,
    parse_dataset_json,
    read_regular_file_beneath,
    stable_pretty_json_bytes,
    validate_dataset_collection_relationships,
)
from trustlab.diff import make_diff
from trustlab.exceptions import MissingFileError
from trustlab.normalizer import normalize_collection_payload, normalize_raw_bytes
from trustlab.validators import (
    validate_collection_manifest,
    validate_dataset_manifest,
    validate_dataset_source,
    validate_diff,
    validate_report,
)


def stable_json(data: Any) -> str:
    return stable_pretty_json_bytes(data).decode("utf-8")


def load_source() -> tuple[dict[str, Any], bytes]:
    dataset_dir = ROOT / "datasets"
    source_path = dataset_dir / "source.json"
    payload = read_regular_file_beneath(
        dataset_dir,
        "source.json",
        limit=MAX_DATASET_JSON_BYTES,
        label=source_path.name,
    )
    source = parse_dataset_json(payload, label=source_path.name)
    validate_dataset_source(source)
    return source, payload


def manifest_from_source(
    source: dict[str, Any], artifact_payloads: dict[str, bytes]
) -> dict[str, Any]:
    manifest = deepcopy(source)
    manifest["schema_version"] = "2.0.0"
    manifest["artifacts"] = [
        {
            **artifact,
            "byte_size": len(artifact_payloads[artifact["artifact_id"]]),
            "sha256": hashlib.sha256(
                artifact_payloads[artifact["artifact_id"]]
            ).hexdigest(),
        }
        for artifact in source["artifacts"]
    ]
    validate_dataset_manifest(manifest)
    return manifest


def broad_artifact_manifest(
    outputs: dict[Path, bytes], artifact_specs: list[tuple[Path, str]]
) -> dict[str, Any]:
    return {
        "project": "android-trust-lab",
        "repository": "https://github.com/avlasov-co/android-trust-lab",
        "version": __version__,
        "artifacts": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "type": artifact_type,
                "generated_by": "python tools/generate_report.py",
                "sha256": hashlib.sha256(outputs[path]).hexdigest(),
                "status": "checked",
            }
            for path, artifact_type in artifact_specs
        ],
        "notes": [
            "Artifact hashes cover checked-in generated outputs only.",
            "Dataset source evidence is bound separately by datasets/manifest.json.",
            "No standalone Magisk zip is stored as a checked-in repository artifact.",
            "Current sample evidence is synthetic / AVD-limited and does not claim physical-device validation.",
            "Use the complete repository gate for validation results; this generated manifest does not attest to test execution.",
        ],
    }


def _open_output_parent(path: Path) -> tuple[int, str]:
    try:
        relative = path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError("generated output must remain beneath the repository") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("generated output path must be normalized and relative")
    if (
        os.open not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
        or os.rename not in os.supports_dir_fd
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise OSError("safe generated-output publication is unsupported")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    current = os.open(ROOT, directory_flags)
    try:
        for part in relative.parts[:-1]:
            try:
                following = os.open(part, directory_flags, dir_fd=current)
            except FileNotFoundError:
                os.mkdir(part, mode=0o755, dir_fd=current)
                following = os.open(part, directory_flags, dir_fd=current)
            os.close(current)
            current = following
        return current, relative.name
    except Exception:
        os.close(current)
        raise


def atomic_write(path: Path, payload: bytes) -> None:
    parent_descriptor, output_name = _open_output_parent(path)
    temporary_name = f".{output_name}.{os.urandom(8).hex()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    temporary_descriptor: int | None = None
    temporary_exists = False
    try:
        temporary_descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        temporary_exists = True
        view = memoryview(payload)
        while view:
            written = os.write(temporary_descriptor, view)
            if written <= 0:
                raise OSError("generated-output write made no progress")
            view = view[written:]
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = None
        os.rename(
            temporary_name,
            output_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_exists = False
        os.fsync(parent_descriptor)
    finally:
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
        if temporary_exists:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def _existing_output(path: Path) -> bytes | None:
    relative = path.relative_to(ROOT).as_posix()
    try:
        return read_regular_file_beneath(
            ROOT,
            relative,
            limit=MAX_DATASET_ARTIFACT_BYTES,
            label="generated output",
        )
    except MissingFileError:
        return None


def publish_outputs(
    outputs: dict[Path, bytes], *, check: bool, manifest_path: Path
) -> list[str]:
    existing = {path: _existing_output(path) for path in outputs}
    changed = [
        path.relative_to(ROOT).as_posix()
        for path, payload in outputs.items()
        if existing[path] != payload
    ]
    if check:
        return changed
    ordered = [path for path in outputs if path != manifest_path]
    if manifest_path in outputs:
        ordered.append(manifest_path)
    for path in ordered:
        payload = outputs[path]
        if existing[path] != payload:
            atomic_write(path, payload)
    return changed


def presence(value: Any) -> str:
    if value is True:
        return "present"
    if value is False:
        return "absent"
    return str(value)


def evidence_value(value: Any) -> Any:
    if isinstance(value, dict) and {"status", "value", "reason"} <= value.keys():
        if value["status"] in {"observed", "observed_absent"}:
            return value["value"]
        return value["status"]
    return value


def fmt(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(map(str, value)) if value else "none"
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def sample_report(
    sample: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    raw_payload: bytes,
    source_documents: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    raw = artifacts[sample["raw_artifact_id"]]
    collection_relationship = sample["collection_manifest"]
    if collection_relationship["status"] == "observed":
        collection = CollectionManifest.from_dict(
            source_documents[collection_relationship["artifact_id"]]
        )
        report = normalize_collection_payload(
            raw_payload,
            collection,
            label=Path(raw["relative_path"]).name,
            generator_name="trustlab",
        )
    else:
        report = normalize_raw_bytes(
            raw_payload,
            label=Path(raw["relative_path"]).name,
            experiment_id=sample["experiment_id"],
            target_type=sample["target_type"],
            observer_type=sample["observer_type"],
            collection_method=sample["collection_method"],
            collection_timestamp=sample["collection_timestamp"],
            raw_artifact_ref=f"datasets/{raw['relative_path']}",
            raw_artifact_id=raw["artifact_id"],
            collector_name=raw["producer"]["name"],
            collector_version=raw["producer"]["version"],
            collection_id=None,
            redaction_state=raw["redaction_state"],
            media_type=raw["media_type"],
            generator_name="trustlab",
        )
    report = attach_comparison_context(
        report,
        target_pseudonym=(
            f"target-{sample['origin_classification'].replace('_', '-')}-{sample['target_type']}"
        ),
        state_id=f"state-{sample['experiment_id'].lower().replace('_', '-')}",
        environment_context=sample["origin_classification"],
    )
    validate_report(report)
    return report


def summary_table(reports: list[dict[str, Any]]) -> str:
    lines = [
        "# Summary Table",
        "",
        "This table is generated from checked-in sample reports. Current samples are synthetic / AVD-limited and do not support physical-device boot-chain claims.",
        "",
        "| experiment | target | observer | method | root shell | Magisk binary | selinux | writable sensitive mounts | overlay | verified boot | bootloader locked | confidence | status |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for report in reports:
        mounts = report["mounts"]["integrity_summary"]
        verified = report["verified_boot"]
        lines.append(
            "| {experiment} | {target} | {observer} | {method} | {root} | {magisk} | {selinux} | {writable} | {overlay} | {vb} | {locked} | {confidence} | sample |".format(
                experiment=report["experiment_id"],
                target=report["target"]["target_type"],
                observer=report["observer"]["observer_type"],
                method=report["observer"]["collection_method"],
                root=presence(
                    evidence_value(report["root_state"]["root_shell_available"])
                ),
                magisk=presence(
                    evidence_value(report["magisk_state"]["binary_visibility"])
                ),
                selinux=evidence_value(report["selinux"]["policy_mode"]),
                writable=fmt(evidence_value(mounts["writable_sensitive_mounts"])),
                overlay=str(evidence_value(mounts["overlay_detected"])).lower(),
                vb=evidence_value(verified["verified_boot_state"]),
                locked=evidence_value(verified["flash_locked"]),
                confidence=verified["confidence"]["level"],
            )
        )
    return "\n".join(lines) + "\n"


def diff_markdown(
    diff_entries: list[tuple[dict[str, Any], dict[str, Any]]],
) -> str:
    lines = [
        "# Trust State Diffs",
        "",
        "These diffs are generated from checked-in sample reports with `tools/generate_report.py`. They are useful for validating the analyzer pipeline, not for claiming hardware-backed trust behavior.",
        "",
    ]
    axis_order = (
        "same_target_state_change",
        "same_state_observer_change",
        "repeat_measurement",
        "different_target_context",
        "mixed_change",
        "incomparable",
    )
    for axis in axis_order:
        grouped = [
            (meta, diff)
            for meta, diff in diff_entries
            if diff["comparison"]["axis"] == axis
        ]
        if not grouped:
            continue
        lines += [f"## Comparison axis: `{axis}`", ""]
        for meta, diff in grouped:
            compatibility = diff["compatibility"]
            comparison = diff["comparison"]
            versions = compatibility["input_schema_versions"]
            lines += [
                f"### {meta['title']}",
                "",
                diff["summary"],
                "",
                f"Comparability: `{comparison['comparability']}`. Reasons: {', '.join(comparison['reasons'])}.",
                f"Input schemas: base `{versions['base']}`, compare `{versions['compare']}`; canonical comparison schema: `{compatibility['canonical_comparison_schema_version']}`; migration mode: `{compatibility['migration_mode']}`.",
                "",
            ]
            for warning in comparison["warnings"]:
                lines += [f"> **Comparison warning:** `{warning}`", ""]
            lines += [
                "| Dimension | Severity | Transition | Before | After | Interpretation |",
                "|---|---|---|---|---|---|",
            ]
            for item in diff["changed_dimensions"]:
                transition = item["transition"]
                lines.append(
                    f"| {item['dimension']} | {item['severity']} | "
                    f"{transition['classification']} "
                    f"({transition['before_status']} → {transition['after_status']}) | "
                    f"`{fmt(item['before'])}` | `{fmt(item['after'])}` | "
                    f"{item['interpretation']} |"
                )
            if not diff["changed_dimensions"]:
                lines.append(
                    "| none | info | unchanged | `unchanged` | `unchanged` | No measured default dimension changed. |"
                )
            lines.append("")
            for label, field in (
                ("Signals became available", "new_signals"),
                ("Signals became unavailable", "missing_signals"),
            ):
                signals = diff[field]
                if not signals:
                    continue
                lines += [f"#### {label}", ""]
                lines += [
                    "| Dimension | Status transition | Classification | Confidence impact | Observed values | Source evidence | Interpretation |",
                    "|---|---|---|---|---|---|---|",
                ]
                for signal in signals:
                    lines.append(
                        f"| {signal['dimension']} | {signal['before_status']} → "
                        f"{signal['after_status']} | {signal['classification']} | "
                        f"{signal['confidence_impact']} | "
                        f"`{fmt(signal['observed_values'])}` | "
                        f"`{fmt(signal['source_evidence'])}` | "
                        f"{signal['interpretation']} |"
                    )
                lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def dimension_value(report: dict[str, Any], dimension: str) -> str:
    if dimension == "bootloader_lock_state":
        return str(evidence_value(report["verified_boot"]["flash_locked"]))
    if dimension == "verified_boot_state":
        return str(evidence_value(report["verified_boot"]["verified_boot_state"]))
    if dimension == "vbmeta_state":
        return str(evidence_value(report["verified_boot"]["vbmeta_device_state"]))
    if dimension == "verity_mode":
        return str(evidence_value(report["verified_boot"]["verity_mode"]))
    if dimension == "selinux_mode":
        return str(evidence_value(report["selinux"]["policy_mode"]))
    if dimension == "mount_integrity":
        integrity = report["mounts"]["integrity_summary"]
        writable = evidence_value(integrity["writable_sensitive_mounts"])
        overlay = evidence_value(integrity["overlay_detected"])
        return f"writable={fmt(writable)}; overlay={str(overlay).lower()}"
    if dimension == "root_shell_availability":
        return presence(evidence_value(report["root_state"]["root_shell_available"]))
    if dimension == "magisk_binary_visibility":
        return presence(evidence_value(report["magisk_state"]["binary_visibility"]))
    if dimension == "property_consistency":
        return fmt(evidence_value(report["properties"]["security"]))
    return "unknown"


def matrix_markdown(reports_by_exp: dict[str, dict[str, Any]]) -> str:
    classes = [
        ("Class A stock virtual", "E01_stock_avd"),
        ("Class B rooted virtual", "E02_rooted_avd"),
        ("Class C writable modified", "E03_writable_system_avd"),
        ("Class D Magisk collector", "E05_magisk_collector"),
        ("Class E physical baseline", None),
        ("Class F physical rooted", None),
    ]
    dimensions = [
        "bootloader_lock_state",
        "verified_boot_state",
        "vbmeta_state",
        "verity_mode",
        "selinux_mode",
        "mount_integrity",
        "root_shell_availability",
        "magisk_binary_visibility",
        "property_consistency",
    ]
    lines = [
        "# Trust Dimensions Matrix",
        "",
        "This matrix is generated from sample reports for classes A-D. Classes E-F are intentionally unclaimed until physical-device artifacts exist.",
        "",
        "| Dimension | " + " | ".join(label for label, _ in classes) + " |",
        "|---" + "|---" * len(classes) + "|",
    ]
    for dimension in dimensions:
        row = [dimension]
        for _, exp in classes:
            if exp is None:
                row.append("not collected")
            else:
                row.append(dimension_value(reports_by_exp[exp], dimension))
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


def build_outputs() -> dict[Path, bytes]:
    """Compute every generated byte string without mutating the repository."""

    source, source_payload = load_source()
    dataset_dir = ROOT / "datasets"
    manifest_path = dataset_dir / "manifest.json"
    if source["creation_tooling"]["version"] != __version__:
        raise ValueError("dataset creation-tool version does not match the package")
    artifacts = {artifact["artifact_id"]: artifact for artifact in source["artifacts"]}
    artifact_payloads: dict[str, bytes] = {}
    source_documents: dict[str, dict[str, Any]] = {}
    outputs: dict[Path, bytes] = {}
    retained_artifact_bytes = 0

    def retain_artifact(artifact_id: str, payload: bytes) -> None:
        nonlocal retained_artifact_bytes
        if len(payload) > MAX_DATASET_ARTIFACT_BYTES:
            raise ValueError("dataset artifact exceeds generation limit")
        retained_artifact_bytes += len(payload)
        if retained_artifact_bytes > MAX_DATASET_TOTAL_BYTES:
            raise ValueError("dataset artifacts exceed cumulative generation limit")
        artifact_payloads[artifact_id] = payload

    for artifact in source["artifacts"]:
        artifact_id = artifact["artifact_id"]
        role = artifact["role"]
        if role == "declarative_source":
            retain_artifact(artifact_id, source_payload)
        elif role in {"raw_artifact", "collection_manifest"}:
            payload = read_regular_file_beneath(
                dataset_dir,
                artifact["relative_path"],
                limit=MAX_DATASET_ARTIFACT_BYTES,
                label="dataset source artifact",
            )
            retain_artifact(artifact_id, payload)
            if role == "collection_manifest":
                document = parse_dataset_json(
                    payload, label="collection manifest source"
                )
                validate_collection_manifest(document)
                source_documents[artifact_id] = document

    reports: list[dict[str, Any]] = []
    reports_by_sample: dict[str, dict[str, Any]] = {}
    reports_by_exp: dict[str, dict[str, Any]] = {}
    for sample in source["samples"]:
        report = sample_report(
            sample,
            artifacts,
            artifact_payloads[sample["raw_artifact_id"]],
            source_documents,
        )
        report_payload = stable_pretty_json_bytes(report)
        report_id = sample["normalized_report_artifact_id"]
        retain_artifact(report_id, report_payload)
        outputs[dataset_dir / artifacts[report_id]["relative_path"]] = report_payload
        reports.append(report)
        reports_by_sample[sample["sample_id"]] = report
        reports_by_exp.setdefault(sample["experiment_id"], report)
        if sample["observer_type"] == "adb_shell":
            reports_by_exp[sample["experiment_id"]] = report

    diff_entries: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for derivation in source["derived_diffs"]:
        diff = make_diff(
            reports_by_sample[derivation["base_sample_id"]],
            reports_by_sample[derivation["compare_sample_id"]],
            allow_mixed=(
                derivation["derivation_id"] == "rooted-adb-vs-magisk-root-collector"
            ),
        )
        validate_diff(diff)
        diff_payload = stable_pretty_json_bytes(diff)
        artifact_id = derivation["artifact_id"]
        retain_artifact(artifact_id, diff_payload)
        outputs[dataset_dir / artifacts[artifact_id]["relative_path"]] = diff_payload
        diff_entries.append((derivation, diff))

    if set(artifact_payloads) != set(artifacts):
        raise ValueError(
            "dataset source contains an unsupported or unresolved artifact"
        )
    dataset_manifest = manifest_from_source(source, artifact_payloads)
    manifest_artifacts = {
        artifact["artifact_id"]: artifact for artifact in dataset_manifest["artifacts"]
    }
    validate_dataset_collection_relationships(
        dataset_manifest,
        manifest_artifacts,
        source_documents,
    )
    manifest_payload = stable_pretty_json_bytes(dataset_manifest)
    if len(manifest_payload) > MAX_DATASET_JSON_BYTES:
        raise ValueError("dataset manifest exceeds generation limit")
    outputs[manifest_path] = manifest_payload

    fixture_raw = read_regular_file_beneath(
        ROOT,
        "tests/fixtures/sample_raw_report.txt",
        limit=MAX_DATASET_ARTIFACT_BYTES,
        label="sample raw fixture",
    )
    fixture_report = normalize_raw_bytes(
        fixture_raw,
        label="sample_raw_report.txt",
        experiment_id="E01_stock_avd",
        target_type="avd",
        observer_type="adb_shell",
        collection_method="raw_artifact",
        collection_timestamp="2026-04-25T15:06:21Z",
        raw_artifact_ref="tests/fixtures/sample_raw_report.txt",
        raw_artifact_id="fixture-sample-raw-report",
        collector_name="trustlab-fixture-authors",
        collector_version="1.0.0",
        redaction_state="not_required",
        generator_name="trustlab",
    )
    validate_report(fixture_report)
    outputs[ROOT / "tests/fixtures/sample_normalized_report.json"] = (
        stable_pretty_json_bytes(fixture_report)
    )
    if diff_entries:
        outputs[ROOT / "tests/fixtures/sample_diff.json"] = stable_pretty_json_bytes(
            diff_entries[0][1]
        )

    outputs[ROOT / "results/summary_table.md"] = summary_table(reports).encode()
    outputs[ROOT / "results/trust_state_diffs.md"] = diff_markdown(
        diff_entries
    ).encode()
    outputs[ROOT / "results/figures/trust_dimensions_matrix.md"] = matrix_markdown(
        reports_by_exp
    ).encode()

    artifact_specs: list[tuple[Path, str]] = [
        (manifest_path, "verifiable_dataset_manifest"),
        (
            ROOT / "tests/fixtures/sample_normalized_report.json",
            "generated_test_report",
        ),
        (ROOT / "tests/fixtures/sample_diff.json", "generated_test_diff"),
    ]
    artifact_specs.extend(
        (
            dataset_dir / artifact["relative_path"],
            "normalized_sample_report"
            if artifact["role"] == "normalized_report"
            else "generated_diff",
        )
        for artifact in source["artifacts"]
        if artifact["role"] in {"normalized_report", "derived_diff"}
    )
    artifact_specs.extend(
        [
            (ROOT / "results/summary_table.md", "generated_table"),
            (ROOT / "results/trust_state_diffs.md", "generated_report"),
            (
                ROOT / "results/figures/trust_dimensions_matrix.md",
                "generated_matrix",
            ),
        ]
    )
    outputs[ROOT / "results/artifact_manifest.json"] = stable_pretty_json_bytes(
        broad_artifact_manifest(outputs, artifact_specs)
    )
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate sample reports and results.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if generated artifacts differ from checked-in files",
    )
    args = parser.parse_args(argv)

    outputs = build_outputs()
    changed = publish_outputs(
        outputs,
        check=args.check,
        manifest_path=ROOT / "datasets/manifest.json",
    )
    if args.check and changed:
        print("Generated artifacts are stale:", file=sys.stderr)
        for path in changed:
            print(f"  {path}", file=sys.stderr)
        return 1
    for path in changed:
        print(f"updated {path}")
    if not changed:
        print("generated artifacts are up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
