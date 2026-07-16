from __future__ import annotations

from pathlib import Path

from trustlab.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_valid_normalize_validate_diff_summarize_flow(tmp_path, capsys):
    report_path = tmp_path / "report.json"
    diff_path = tmp_path / "diff.json"

    assert (
        main(
            [
                "normalize",
                "--input",
                str(ROOT / "tests" / "fixtures" / "sample_raw_report.txt"),
                "--output",
                str(report_path),
                "--experiment-id",
                "E01_stock_avd",
                "--target-type",
                "avd",
                "--observer",
                "adb_shell",
                "--collection-timestamp",
                "2026-04-25T15:06:21Z",
                "--raw-artifact-ref",
                "tests/fixtures/sample_raw_report.txt",
            ]
        )
        == 0
    )
    assert main(["validate-report", str(report_path)]) == 0
    assert (
        main(
            [
                "diff",
                "--base",
                str(report_path),
                "--compare",
                str(
                    ROOT
                    / "datasets"
                    / "samples"
                    / "rooted_avd"
                    / "E02_rooted_avd__observer-adb__sample.json"
                ),
                "--output",
                str(diff_path),
            ]
        )
        == 0
    )
    assert main(["validate-diff", str(diff_path)]) == 0
    assert main(["summarize", str(diff_path)]) == 0

    output = capsys.readouterr().out
    assert "valid report\n" in output
    assert "valid diff\n" in output
    assert str(tmp_path) not in output
    assert "# Trust Diff" in output
    assert "su_binary_visibility" in output
