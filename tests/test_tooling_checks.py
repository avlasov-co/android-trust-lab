from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_tool(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / f"tools/{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_coverage = load_tool("check_coverage")
check_python_support = load_tool("check_python_support")
check_schema_consistency = load_tool("check_schema_consistency")
check_schemas = load_tool("check_schemas")
generate_report = load_tool("generate_report")
package_magisk_module = load_tool("package_magisk_module")


def coverage_payload(
    *, analyzer_lines=90, analyzer_branches=80, tool_lines=70, tool_branches=60
):
    def entry(covered_lines, covered_branches):
        return {
            "summary": {
                "covered_lines": covered_lines,
                "num_statements": 100,
                "covered_branches": covered_branches,
                "num_branches": 100,
            }
        }

    return {
        "files": {
            "analyzer/trustlab/core.py": entry(analyzer_lines, analyzer_branches),
            "tools/check.py": entry(tool_lines, tool_branches),
            "tests/test_irrelevant.py": entry(0, 0),
        }
    }


def test_coverage_policy_measures_statements_and_branches_independently(
    tmp_path, capsys
):
    payload = coverage_payload()
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert check_coverage.coverage_errors(payload) == []
    assert check_coverage.main([str(path)]) == 0
    output = capsys.readouterr().out
    assert "analyzer/trustlab: statements 90.00%, branches 80.00%" in output
    assert "tools: statements 70.00%, branches 60.00%" in output


def test_coverage_policy_fails_each_meaningful_floor():
    errors = check_coverage.coverage_errors(
        coverage_payload(
            analyzer_lines=84,
            analyzer_branches=79,
            tool_lines=69,
            tool_branches=59,
        )
    )
    assert errors == [
        "analyzer/trustlab statement coverage 84.00% is below 85.00%",
        "analyzer/trustlab branch coverage 79.00% is below 80.00%",
        "tools statement coverage 69.00% is below 70.00%",
        "tools branch coverage 59.00% is below 60.00%",
    ]


@pytest.mark.parametrize(
    "payload, message",
    (
        ({}, "files object"),
        ({"files": {}}, "no measurable code"),
        (
            {"files": {"tools/example.py": {"summary": {"covered_lines": "1"}}}},
            "summary is malformed",
        ),
    ),
)
def test_coverage_policy_rejects_malformed_measurements(payload, message):
    with pytest.raises(ValueError, match=message):
        check_coverage.group_metrics(payload, "tools/")


def test_repository_tool_entry_points_pass(capsys):
    assert check_python_support.main([]) == 0
    assert check_schema_consistency.main([]) == 0
    assert check_schemas.main() == 0
    assert package_magisk_module.main(["--check-only"]) == 0
    output = capsys.readouterr().out
    assert "Python support policy is consistent" in output
    assert "schema resources are consistent" in output
    assert "validated 2 schemas" in output
    assert "Magisk module safety checks passed" in output


def test_ci_gate_enforces_baseline_aware_secret_detection():
    check_script = (ROOT / "scripts/check.sh").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "detect_secrets.pre_commit_hook" in check_script
    assert check_script.index("detect_secrets.pre_commit_hook") < check_script.index(
        'echo "repository checks passed"'
    )
    assert "run: bash scripts/check.sh" in workflow


def test_secret_detector_rejects_new_unbaselined_credential(tmp_path):
    candidate = "AK" + "IA" + "QWERTYUIOPASDFGH"
    source = tmp_path / "--no-verify"
    source.write_text(candidate + "\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "detect_secrets.pre_commit_hook",
            "--baseline",
            str(ROOT / ".secrets.baseline"),
            "--no-verify",
            "--",
            source.name,
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 1
    assert "AWS Access Key" in result.stdout


@pytest.fixture
def isolated_generated_tree(tmp_path, monkeypatch):
    for relative in ("datasets", "results", "tests/fixtures"):
        source = ROOT / relative
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, destination)
    monkeypatch.setattr(generate_report, "ROOT", tmp_path)
    return tmp_path


def test_generator_check_accepts_fresh_tree(isolated_generated_tree, capsys):
    assert generate_report.main(["--check"]) == 0
    assert capsys.readouterr().out == "generated artifacts are up to date\n"


def test_generator_check_detects_and_repairs_stale_outputs(
    isolated_generated_tree, capsys
):
    summary = isolated_generated_tree / "results/summary_table.md"
    summary.write_text("stale output\n", encoding="utf-8")

    assert generate_report.main(["--check"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "results/summary_table.md" in captured.err
    assert summary.read_text(encoding="utf-8") == "stale output\n"

    assert generate_report.main([]) == 0
    assert "updated results/summary_table.md" in capsys.readouterr().out
    assert generate_report.main(["--check"]) == 0
    assert capsys.readouterr().out == "generated artifacts are up to date\n"
