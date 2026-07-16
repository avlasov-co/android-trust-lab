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
    migrated_path = tmp_path / "migrated.json"
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
        "collection_event_id",
        "content_digest",
        "collection_timestamp",
        "experiment_id",
        "observer",
    ):
        assert report[key] == expected_report[key]
    target = {"target_type": report["target"]["target_type"]}
    target.update(
        {
            key: report["target"][key]["value"]
            for key in (
                "device_codename",
                "manufacturer",
                "model",
                "android_version",
                "sdk",
                "build_fingerprint",
            )
        }
    )
    assert target == expected_report["target"]
    assert report["selinux"]["policy_mode"]["value"] == expected_report["selinux_mode"]
    assert {
        key: report["mounts"]["system_mount"][key]
        for key in ("mount_point", "fs_type", "options", "classification")
    } == expected_report["system_mount"]
    assert {
        "observer_uid_is_root": report["root_state"]["observer_effective_uid_is_root"][
            "value"
        ],
        "root_shell_available": report["root_state"]["root_shell_available"]["value"],
        "su_binary_observed": report["root_state"]["su_binary_observed"]["value"],
        "su_invocation_tested": report["root_state"]["su_invocation_tested"]["value"],
    } == expected_report["root_state"]
    assert report["root_state"]["su_binary_observed"]["status"] == ("observed_absent")
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
    assert diff_document["compatibility"] == expected_diff["compatibility"]
    projected_changes = [
        {
            "dimension": change["dimension"],
            "before": change["before"]["value"],
            "after": change["after"]["value"],
            "severity": change["severity"],
            "evidence_paths": change["evidence_paths"],
        }
        for change in diff_document["changed_dimensions"]
    ]
    assert projected_changes == expected_diff["changed_dimensions"]
    assert diff_document["changed_dimensions"][0]["before"]["status"] == (
        "observed_absent"
    )
    assert diff_document["changed_dimensions"][0]["after"]["status"] == "observed"

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

    v1_source = ROOT / "tests/fixtures/report_v1_historical.json"
    before = v1_source.read_bytes()
    migrate = run_installed(
        "migrate-report",
        "--input",
        str(v1_source),
        "--output",
        str(migrated_path),
        cwd=tmp_path,
    )
    assert migrate.returncode == 0, migrate.stderr
    assert migrate.stdout == migrate.stderr == ""
    assert v1_source.read_bytes() == before
    migrated = json.loads(migrated_path.read_text(encoding="utf-8"))
    assert migrated["schema_version"] == "6.0.0"
    assert len(migrated["provenance"]["migration_history"]) == 5

    collection_manifest = (
        ROOT / "datasets/samples/magisk_collector/collector_manifest_sample.json"
    )
    validate_manifest = run_installed(
        "validate-collection-manifest",
        str(collection_manifest),
        cwd=tmp_path,
    )
    assert validate_manifest.returncode == 0
    assert validate_manifest.stdout == "valid collection manifest\n"
    assert validate_manifest.stderr == ""

    manifest_report = tmp_path / "manifest-report.json"
    normalize_manifest = run_installed(
        "normalize",
        "--manifest",
        str(collection_manifest),
        "--output",
        str(manifest_report),
        cwd=tmp_path,
    )
    assert normalize_manifest.returncode == 0, normalize_manifest.stderr
    assert normalize_manifest.stdout == normalize_manifest.stderr == ""
    assert (
        json.loads(manifest_report.read_text(encoding="utf-8"))["observer"][
            "observer_type"
        ]
        == "root_collector"
    )

    dataset_verify = run_installed(
        "dataset",
        "verify",
        str(ROOT / "datasets/manifest.json"),
        cwd=tmp_path,
    )
    assert dataset_verify.returncode == 0, dataset_verify.stderr
    assert dataset_verify.stdout == "dataset verified\n"
    assert dataset_verify.stderr == ""


def test_installed_entry_point_failure_paths_are_stable(tmp_path):
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"schema_version": "1.0.0"}\n', encoding="utf-8")
    unsupported = tmp_path / "unsupported.json"
    unsupported.write_text('{"schema_version": "7.0.0"}\n', encoding="utf-8")
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
            (
                "migrate-report",
                "--input",
                str(unsupported),
                "--output",
                str(output),
            ),
            5,
            "error: unsupported report schema version\n",
        ),
        (
            ("validate-diff", str(invalid)),
            6,
            "error: diff schema validation failed",
        ),
        (
            (
                "validate-collection-manifest",
                str(
                    ROOT
                    / "tests/fixtures/collection_manifest_invalid_absolute_path.json"
                ),
            ),
            6,
            "error: collection manifest schema validation failed",
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
        if arguments[0] == "migrate-report":
            assert result.stderr == expected_error
        else:
            assert expected_error in result.stderr
        assert "Traceback" not in result.stderr
