from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = json.loads(
    (ROOT / "tests/golden/cli_expectations.json").read_text(encoding="utf-8")
)


def installed_entry_point() -> Path:
    name = "trustlab.exe" if os.name == "nt" else "trustlab"
    entry_point = Path(sys.executable).parent / name
    assert entry_point.is_file(), (
        "install analyzer[dev] before running repository tests"
    )
    return entry_point


def run_installed(*arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [str(installed_entry_point()), *arguments],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def test_installed_entry_point_success_flow_matches_manual_goldens(tmp_path):
    report_path = tmp_path / "report.json"
    diff_path = tmp_path / "diff.json"
    normalize = run_installed(
        "normalize",
        "--input",
        str(ROOT / "tests/fixtures/sample_raw_report.txt"),
        "--output",
        str(report_path),
        "--experiment-id",
        "E10_golden",
        "--target-type",
        "avd",
        "--observer",
        "adb_shell",
        "--collection-method",
        "golden_fixture",
        "--collection-timestamp",
        "2026-01-02T03:04:05Z",
        "--raw-artifact-ref",
        "tests/golden/raw_observation.txt",
        cwd=tmp_path,
    )
    assert normalize.returncode == 0, normalize.stderr
    assert normalize.stdout == normalize.stderr == ""

    report = json.loads(report_path.read_text(encoding="utf-8"))
    expected_report = GOLDEN["normalize"]
    for key in (
        "report_id",
        "collection_timestamp",
        "experiment_id",
        "target",
        "observer",
    ):
        assert report[key] == expected_report[key]
    assert report["selinux"]["mode"] == expected_report["selinux_mode"]
    assert {
        key: report["mounts"]["system_mount"][key]
        for key in ("mount_point", "fs_type", "options", "classification")
    } == expected_report["system_mount"]
    assert report["root_state"] == expected_report["root_state"]
    assert report["raw_artifacts"] == expected_report["raw_artifacts"]

    validate_report = run_installed("validate-report", str(report_path), cwd=tmp_path)
    assert validate_report.returncode == 0
    assert validate_report.stdout == "valid report\n"
    assert validate_report.stderr == ""

    diff = run_installed(
        "diff",
        "--base",
        str(report_path),
        "--compare",
        str(
            ROOT
            / "datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json"
        ),
        "--output",
        str(diff_path),
        cwd=tmp_path,
    )
    assert diff.returncode == 0, diff.stderr
    assert diff.stdout == diff.stderr == ""

    diff_document = json.loads(diff_path.read_text(encoding="utf-8"))
    expected_diff = GOLDEN["diff"]
    assert diff_document["diff_id"] == expected_diff["diff_id"]
    assert diff_document["summary"] == expected_diff["summary"]
    projected_changes = [
        {
            key: change[key]
            for key in ("dimension", "before", "after", "severity", "evidence_paths")
        }
        for change in diff_document["changed_dimensions"]
    ]
    assert projected_changes == expected_diff["changed_dimensions"]

    validate_diff = run_installed("validate-diff", str(diff_path), cwd=tmp_path)
    assert validate_diff.returncode == 0
    assert validate_diff.stdout == "valid diff\n"
    assert validate_diff.stderr == ""

    summarize = run_installed("summarize", str(diff_path), cwd=tmp_path)
    assert summarize.returncode == 0
    expected_summary = (ROOT / "tests/golden/expected_diff_summary.md").read_text(
        encoding="utf-8"
    )
    assert summarize.stdout.rstrip() + "\n" == expected_summary
    assert summarize.stderr == ""


def test_installed_entry_point_failure_paths_are_stable(tmp_path):
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"schema_version": "1.0.0"}\n', encoding="utf-8")
    missing = tmp_path / "missing.raw"
    valid_report = ROOT / "tests/fixtures/sample_normalized_report.json"
    output = tmp_path / "unused.json"
    cases = (
        (
            ("normalize", "--input", str(missing), "--output", str(output)),
            3,
            "error: input file not found: missing.raw\n",
        ),
        (
            (
                "diff",
                "--base",
                str(invalid),
                "--compare",
                str(valid_report),
                "--output",
                str(output),
            ),
            6,
            "error: report schema validation failed",
        ),
        (
            ("validate-report", str(invalid)),
            6,
            "error: report schema validation failed",
        ),
        (
            ("validate-diff", str(invalid)),
            6,
            "error: diff schema validation failed",
        ),
        (
            ("summarize", str(invalid)),
            6,
            "error: unrecognized JSON artifact\n",
        ),
    )

    for arguments, expected_code, expected_error in cases:
        result = run_installed(*arguments, cwd=tmp_path)
        assert result.returncode == expected_code
        assert result.stdout == ""
        assert expected_error in result.stderr
        assert "Traceback" not in result.stderr
