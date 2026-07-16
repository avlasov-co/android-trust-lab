from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from trustlab.dataset_manifest import stable_pretty_json_bytes
from trustlab.exceptions import CollectionError, InvalidJSONError, SchemaValidationError

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
    assert "validated 17 schemas, 8 reports, 6 diffs" in output
    assert "1 collection manifest" in output
    assert "Magisk module safety checks passed" in output


def test_ci_gate_enforces_baseline_aware_secret_detection():
    check_script = (ROOT / "scripts/check.sh").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    pre_commit = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert "detect_secrets.pre_commit_hook" in check_script
    assert check_script.index("detect_secrets.pre_commit_hook") < check_script.index(
        'echo "repository checks passed"'
    )
    check_line_filter = next(
        line for line in check_script.splitlines() if "--exclude-lines" in line
    )
    check_file_filter = next(
        line for line in check_script.splitlines() if "--exclude-files" in line
    )
    pre_commit_line_filter = next(
        line for line in pre_commit.splitlines() if "--exclude-lines" in line
    )
    assert '"sha256"' in check_line_filter
    assert '"sha256"' in pre_commit_line_filter
    assert "datasets/manifest" not in check_file_filter
    assert "datasets/manifest" not in pre_commit_line_filter
    assert "results/artifact_manifest" not in check_file_filter
    assert "results/artifact_manifest" not in pre_commit_line_filter
    assert "run: bash scripts/check.sh" in workflow


def test_secret_detector_rejects_new_unbaselined_credential(tmp_path):
    candidate = "AK" + "IA" + "QWERTYUIOPASDFGH"
    source = tmp_path / "--no-verify"
    source.write_text(candidate + "\n", encoding="utf-8")
    baseline = tmp_path / ".secrets.baseline"
    baseline.write_bytes((ROOT / ".secrets.baseline").read_bytes())
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True, timeout=30)
    subprocess.run(["git", "add", baseline.name], cwd=tmp_path, check=True, timeout=30)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "detect_secrets.pre_commit_hook",
            "--baseline",
            baseline.name,
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


def test_secret_detector_scans_manifest_metadata_but_ignores_digest_lines(tmp_path):
    baseline = tmp_path / ".secrets.baseline"
    baseline.write_bytes((ROOT / ".secrets.baseline").read_bytes())
    manifest = tmp_path / "datasets/manifest.json"
    manifest.parent.mkdir()
    manifest.write_bytes((ROOT / "datasets/manifest.json").read_bytes())
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True, timeout=30)
    subprocess.run(["git", "add", baseline.name], cwd=tmp_path, check=True, timeout=30)

    command = [
        sys.executable,
        "-m",
        "detect_secrets.pre_commit_hook",
        "--baseline",
        baseline.name,
        "--exclude-lines",
        r'^\s+"sha256": "[a-f0-9]{64}",?\s*$',
        "--no-verify",
        "--",
        "datasets/manifest.json",
    ]
    clean = subprocess.run(
        command,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert clean.returncode == 0

    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["authorization"]["statement"] = "AK" + "IA" + "QWERTYUIOPASDFGH"
    manifest.write_bytes(stable_pretty_json_bytes(document))
    detected = subprocess.run(
        command,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert detected.returncode == 1
    assert "AWS Access Key" in detected.stdout


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


def test_generator_is_driven_by_validated_source_and_is_deterministic(
    isolated_generated_tree,
):
    first = generate_report.build_outputs()
    second = generate_report.build_outputs()

    assert first == second
    assert not hasattr(generate_report, "SAMPLES")
    assert not hasattr(generate_report, "DIFFS")
    source = json.loads(
        (isolated_generated_tree / "datasets/source.json").read_text(encoding="utf-8")
    )
    assert len(source["samples"]) == 5
    assert len(source["derived_diffs"]) == 4


def test_generator_validates_all_inputs_before_writing(isolated_generated_tree):
    outputs = generate_report.build_outputs()
    before = {path: path.read_bytes() for path in outputs}
    source_path = isolated_generated_tree / "datasets/source.json"
    source = json.loads(source_path.read_text(encoding="utf-8"))
    source["samples"][1]["sample_id"] = source["samples"][0]["sample_id"]
    source_path.write_bytes(stable_pretty_json_bytes(source))

    with pytest.raises(SchemaValidationError, match="sample IDs must be unique"):
        generate_report.main([])

    assert {path: path.read_bytes() for path in outputs} == before


@pytest.mark.parametrize("failure", ["malformed", "relationship", "extra_observed"])
def test_generator_validates_collection_sources_before_writing(
    isolated_generated_tree, failure
):
    outputs = generate_report.build_outputs()
    before = {path: path.read_bytes() for path in outputs}
    collection_path = (
        isolated_generated_tree
        / "datasets/samples/magisk_collector/collector_manifest_sample.json"
    )
    if failure == "malformed":
        collection_path.write_bytes(b"{\n")
        expected_error = InvalidJSONError
    elif failure == "relationship":
        document = json.loads(collection_path.read_text(encoding="utf-8"))
        document["artifacts"][0]["sha256"] = "0" * 64
        collection_path.write_bytes(stable_pretty_json_bytes(document))
        expected_error = CollectionError
    else:
        document = json.loads(collection_path.read_text(encoding="utf-8"))
        extra = document["artifacts"][0].copy()
        extra.update(
            {
                "logical_name": "extra_device_log",
                "relative_path": "extra_device.log",
                "byte_size": 5,
                "sha256": "0" * 64,
                "probe_id": "manual.extra_device_log",
            }
        )
        document["artifacts"].append(extra)
        collection_path.write_bytes(stable_pretty_json_bytes(document))
        expected_error = SchemaValidationError

    with pytest.raises(expected_error):
        generate_report.main([])

    assert {path: path.read_bytes() for path in outputs} == before


def test_generator_rejects_symlinked_source_artifact(isolated_generated_tree, tmp_path):
    raw = isolated_generated_tree / "datasets/samples/stock_avd/raw_sample.txt"
    outside = tmp_path / "outside-raw.txt"
    outside.write_bytes(raw.read_bytes())
    raw.unlink()
    raw.symlink_to(outside)

    with pytest.raises(CollectionError, match="non-directory or symlink"):
        generate_report.main(["--check"])


@pytest.mark.parametrize("arguments", [[], ["--check"]])
def test_generator_rejects_symlinked_output_parent_without_touching_target(
    isolated_generated_tree, tmp_path, arguments
):
    results = isolated_generated_tree / "results"
    outside = tmp_path / "outside-results"
    results.rename(outside)
    results.symlink_to(outside, target_is_directory=True)
    before = {
        path.relative_to(outside): path.read_bytes()
        for path in outside.rglob("*")
        if path.is_file()
    }

    with pytest.raises(CollectionError, match="non-directory or symlink"):
        generate_report.main(arguments)

    assert {
        path.relative_to(outside): path.read_bytes()
        for path in outside.rglob("*")
        if path.is_file()
    } == before


def test_generator_enforces_cumulative_artifact_limit(
    isolated_generated_tree, monkeypatch
):
    monkeypatch.setattr(generate_report, "MAX_DATASET_TOTAL_BYTES", 1)

    with pytest.raises(ValueError, match="cumulative generation limit"):
        generate_report.build_outputs()


def test_generator_publishes_dataset_manifest_last(tmp_path, monkeypatch):
    monkeypatch.setattr(generate_report, "ROOT", tmp_path)
    manifest = tmp_path / "datasets/manifest.json"
    other = tmp_path / "datasets/derived/report.json"
    order = []
    monkeypatch.setattr(
        generate_report,
        "atomic_write",
        lambda path, _payload: order.append(path),
    )

    changed = generate_report.publish_outputs(
        {manifest: b"manifest\n", other: b"report\n"},
        check=False,
        manifest_path=manifest,
    )

    assert changed == ["datasets/manifest.json", "datasets/derived/report.json"]
    assert order == [other, manifest]
