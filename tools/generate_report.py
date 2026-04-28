#!/usr/bin/env python3
"""Generate Android Trust Lab sample reports, diffs, and markdown result tables.

This script intentionally uses checked-in synthetic/AVD-limited samples. It is not a
replacement for real device collection. It keeps derived artifacts reproducible so
reviewers can see that results are derived from checked-in data rather than hand-written summaries.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from trustlab.normalizer import normalize_raw_file
from trustlab.diff import make_diff
from trustlab.report_writer import write_json
from trustlab.validators import validate_report, validate_diff

SAMPLES = [
    {
        "sample_id": "stock-avd-adb-sample",
        "experiment_id": "E01_stock_avd",
        "target_type": "avd",
        "observer_type": "adb_shell",
        "collection_method": "adb_shell_snapshot",
        "timestamp": "2026-04-25T15:06:21Z",
        "raw": "datasets/samples/stock_avd/raw_sample.txt",
        "report": "datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json",
        "limitations": ["synthetic sample", "emulator target", "no hardware-backed boot conclusion"],
    },
    {
        "sample_id": "rooted-avd-adb-sample",
        "experiment_id": "E02_rooted_avd",
        "target_type": "avd",
        "observer_type": "adb_shell",
        "collection_method": "synthetic_rooted_adb_snapshot",
        "timestamp": "2026-04-25T15:07:21Z",
        "raw": "datasets/samples/rooted_avd/raw_adb_sample.txt",
        "report": "datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json",
        "limitations": ["synthetic rooted ADB-visible sample", "emulator target", "no hardware-backed boot conclusion"],
    },
    {
        "sample_id": "rooted-avd-root-sample",
        "experiment_id": "E02_rooted_avd",
        "target_type": "avd",
        "observer_type": "root_collector",
        "collection_method": "synthetic_root_collector_snapshot",
        "timestamp": "2026-04-25T15:07:51Z",
        "raw": "datasets/samples/rooted_avd/raw_root_sample.txt",
        "report": "datasets/samples/rooted_avd/E02_rooted_avd__observer-root__sample.json",
        "limitations": ["synthetic rooted root-observer sample", "emulator target", "no hardware-backed boot conclusion"],
    },
    {
        "sample_id": "writable-system-avd-adb-sample",
        "experiment_id": "E03_writable_system_avd",
        "target_type": "avd",
        "observer_type": "adb_shell",
        "collection_method": "synthetic_writable_system_snapshot",
        "timestamp": "2026-04-25T15:08:21Z",
        "raw": "datasets/samples/writable_system_avd/raw_sample.txt",
        "report": "datasets/samples/writable_system_avd/E03_writable_system_avd__observer-adb__sample.json",
        "limitations": ["synthetic writable-system sample", "emulator target", "overlay evidence only", "no hardware-backed boot conclusion"],
    },
    {
        "sample_id": "magisk-collector-root-sample",
        "experiment_id": "E05_magisk_collector",
        "target_type": "avd",
        "observer_type": "root_collector",
        "collection_method": "magisk_module_manual",
        "timestamp": "2026-04-25T15:50:00Z",
        "raw": "datasets/samples/magisk_collector/raw_sample.txt",
        "report": "datasets/samples/magisk_collector/E05_magisk_collector__observer-root__sample.json",
        "limitations": ["synthetic Magisk collector sample", "emulator target", "no hardware-backed boot conclusion"],
    },
]

DIFFS = [
    {
        "name": "stock_adb_vs_rooted_adb",
        "title": "E01 stock AVD ADB observer vs E02 rooted AVD ADB observer",
        "base": "datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json",
        "compare": "datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json",
        "output": "results/diffs/stock_adb_vs_rooted_adb.json",
    },
    {
        "name": "rooted_adb_vs_rooted_root",
        "title": "E02 rooted AVD ADB observer vs E02 rooted AVD root observer",
        "base": "datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json",
        "compare": "datasets/samples/rooted_avd/E02_rooted_avd__observer-root__sample.json",
        "output": "results/diffs/rooted_adb_vs_rooted_root.json",
    },
    {
        "name": "stock_vs_writable_system",
        "title": "E01 stock AVD vs E03 writable-system AVD",
        "base": "datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json",
        "compare": "datasets/samples/writable_system_avd/E03_writable_system_avd__observer-adb__sample.json",
        "output": "results/diffs/stock_vs_writable_system.json",
    },
    {
        "name": "rooted_adb_vs_magisk_root_collector",
        "title": "E02 rooted ADB observer vs E05 Magisk root collector",
        "base": "datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json",
        "compare": "datasets/samples/magisk_collector/E05_magisk_collector__observer-root__sample.json",
        "output": "results/diffs/rooted_adb_vs_magisk_root_collector.json",
    },
]


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def write_if_changed(path: Path, content: str, *, check: bool, changed: List[str]) -> None:
    old = path.read_text(encoding="utf-8") if path.exists() else None
    if old != content:
        changed.append(str(path.relative_to(ROOT)))
        if not check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")


def write_json_if_changed(path: Path, data: Any, *, check: bool, changed: List[str]) -> None:
    write_if_changed(path, stable_json(data), check=check, changed=changed)


def presence(value: bool) -> str:
    return "present" if value else "absent"


def fmt(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(map(str, value)) if value else "none"
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def sample_report(sample: Dict[str, str]) -> Dict[str, Any]:
    report = normalize_raw_file(
        ROOT / sample["raw"],
        experiment_id=sample["experiment_id"],
        target_type=sample["target_type"],
        observer_type=sample["observer_type"],
        collection_method=sample["collection_method"],
        collection_timestamp=sample["timestamp"],
        raw_artifact_ref=sample["raw"],
    )
    validate_report(report)
    return report


def manifest(samples: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "samples": [
            {
                "sample_id": sample["sample_id"],
                "experiment_id": sample["experiment_id"],
                "target_type": sample["target_type"],
                "observer_type": sample["observer_type"],
                "collection_method": sample["collection_method"],
                "report_path": sample["report"],
                "raw_artifact_path": sample["raw"],
                "known_limitations": sample["limitations"],
                "collection_date": sample["timestamp"],
            }
            for sample in samples
        ],
    }


def summary_table(reports: List[Dict[str, Any]]) -> str:
    lines = [
        "# Summary Table",
        "",
        "This table is generated from checked-in sample reports. Current samples are synthetic / AVD-limited and do not support physical-device boot-chain claims.",
        "",
        "| experiment | target | observer | method | root | magisk | selinux | writable sensitive mounts | overlay | verified boot | bootloader locked | confidence | status |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for report in reports:
        mounts = report["mounts"]
        verified = report["verified_boot"]
        lines.append(
            "| {experiment} | {target} | {observer} | {method} | {root} | {magisk} | {selinux} | {writable} | {overlay} | {vb} | {locked} | {confidence} | sample |".format(
                experiment=report["experiment_id"],
                target=report["target"]["target_type"],
                observer=report["observer"]["observer_type"],
                method=report["observer"]["collection_method"],
                root=presence(report["root_state"]["su_present"]),
                magisk=presence(report["magisk_state"]["magisk_binary_present"]),
                selinux=report["selinux"]["mode"],
                writable=fmt(mounts["writable_sensitive_mounts"]),
                overlay=str(mounts["overlay_detected"]).lower(),
                vb=verified["verified_boot_state"],
                locked=verified["flash_locked"],
                confidence=verified["confidence"],
            )
        )
    return "\n".join(lines) + "\n"


def diff_markdown(diff_entries: List[Tuple[Dict[str, str], Dict[str, Any]]]) -> str:
    lines = [
        "# Trust State Diffs",
        "",
        "These diffs are generated from checked-in sample reports with `tools/generate_report.py`. They are useful for validating the analyzer pipeline, not for claiming hardware-backed trust behavior.",
        "",
    ]
    for meta, diff in diff_entries:
        lines += [
            f"## {meta['title']}",
            "",
            diff["summary"],
            "",
            "| Dimension | Severity | Before | After | Interpretation |",
            "|---|---|---|---|---|",
        ]
        for item in diff["changed_dimensions"]:
            lines.append(
                f"| {item['dimension']} | {item['severity']} | `{fmt(item['before'])}` | `{fmt(item['after'])}` | {item['interpretation']} |"
            )
        if not diff["changed_dimensions"]:
            lines.append("| none | info | `unchanged` | `unchanged` | No measured default dimension changed. |")
        lines.append("")
    return "\n".join(lines) + "\n"


def dimension_value(report: Dict[str, Any], dimension: str) -> str:
    if dimension == "bootloader_lock_state":
        return report["verified_boot"]["flash_locked"]
    if dimension == "verified_boot_state":
        return report["verified_boot"]["verified_boot_state"]
    if dimension == "vbmeta_state":
        return report["verified_boot"]["vbmeta_device_state"]
    if dimension == "verity_mode":
        return report["verified_boot"]["verity_mode"]
    if dimension == "selinux_mode":
        return report["selinux"]["mode"]
    if dimension == "mount_integrity":
        writable = report["mounts"]["writable_sensitive_mounts"]
        overlay = report["mounts"]["overlay_detected"]
        return f"writable={fmt(writable)}; overlay={str(overlay).lower()}"
    if dimension == "root_presence":
        return presence(report["root_state"]["su_present"])
    if dimension == "magisk_presence":
        return presence(report["magisk_state"]["magisk_binary_present"])
    if dimension == "property_consistency":
        return fmt(report["properties"]["security"])
    if dimension == "observer_privilege":
        return report["observer"]["privilege_level"]
    return "unknown"


def matrix_markdown(reports_by_exp: Dict[str, Dict[str, Any]]) -> str:
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
        "root_presence",
        "magisk_presence",
        "property_consistency",
        "observer_privilege",
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


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate sample reports and results.")
    parser.add_argument("--check", action="store_true", help="Fail if generated artifacts differ from checked-in files")
    args = parser.parse_args(argv)

    changed: List[str] = []
    reports: List[Dict[str, Any]] = []
    reports_by_exp: Dict[str, Dict[str, Any]] = {}

    for sample in SAMPLES:
        report = sample_report(sample)
        reports.append(report)
        reports_by_exp.setdefault(sample["experiment_id"], report)
        if sample["observer_type"] == "adb_shell":
            reports_by_exp[sample["experiment_id"]] = report
        write_json_if_changed(ROOT / sample["report"], report, check=args.check, changed=changed)

    write_json_if_changed(ROOT / "datasets/manifest.json", manifest(SAMPLES), check=args.check, changed=changed)

    diff_entries: List[Tuple[Dict[str, str], Dict[str, Any]]] = []
    for meta in DIFFS:
        base = load_json(ROOT / meta["base"])
        compare = load_json(ROOT / meta["compare"])
        diff = make_diff(base, compare)
        validate_diff(diff)
        diff_entries.append((meta, diff))
        write_json_if_changed(ROOT / meta["output"], diff, check=args.check, changed=changed)
        if meta["name"] == "stock_adb_vs_rooted_adb":
            write_json_if_changed(ROOT / "tests/fixtures/sample_diff.json", diff, check=args.check, changed=changed)

    write_if_changed(ROOT / "results/summary_table.md", summary_table(reports), check=args.check, changed=changed)
    write_if_changed(ROOT / "results/trust_state_diffs.md", diff_markdown(diff_entries), check=args.check, changed=changed)
    write_if_changed(ROOT / "results/figures/trust_dimensions_matrix.md", matrix_markdown(reports_by_exp), check=args.check, changed=changed)

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
