from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from trustlab.exceptions import UnsupportedObserverError
from trustlab.normalizer import normalize_raw_file
from trustlab.observers import OBSERVER_PRIVILEGE, OBSERVER_REGISTRY
from trustlab.report_writer import load_json
from trustlab.validators import validate_report

ROOT = Path(__file__).resolve().parents[1]
RAW_FIXTURE = ROOT / "tests/fixtures/sample_raw_report.txt"


@pytest.mark.parametrize(
    ("observer_id", "privilege_level"),
    [
        ("host", "host"),
        ("adb_shell", "shell"),
        ("unprivileged_app", "app_sandbox"),
        ("root_collector", "root"),
    ],
)
def test_every_supported_observer_normalizes_to_valid_privilege(
    observer_id, privilege_level
):
    report = normalize_raw_file(
        RAW_FIXTURE,
        observer_type=observer_id,
        collection_timestamp="2026-04-25T15:06:21Z",
        raw_artifact_ref="tests/fixtures/sample_raw_report.txt",
    )
    assert report["observer"] == {
        "observer_type": observer_id,
        "privilege_level": privilege_level,
        "collection_method": "raw_artifact",
    }
    validate_report(report)


def test_observer_registry_is_complete_and_matches_schema():
    schema = load_json(ROOT / "collector/schema/trust_report_v2_0_0.schema.json")
    observer_schema = schema["$defs"]["observerMetadata"]["properties"]

    assert list(OBSERVER_REGISTRY) == [
        "host",
        "adb_shell",
        "unprivileged_app",
        "root_collector",
    ]
    assert set(OBSERVER_REGISTRY) == set(observer_schema["observer_type"]["enum"])
    assert set(OBSERVER_PRIVILEGE.values()) <= set(
        observer_schema["privilege_level"]["enum"]
    )
    for observer_id, spec in OBSERVER_REGISTRY.items():
        assert spec.observer_id == observer_id
        assert spec.label
        assert spec.supported_artifact_adapters


def test_unsupported_observer_raises_typed_library_error():
    with pytest.raises(UnsupportedObserverError, match="unsupported observer"):
        normalize_raw_file(RAW_FIXTURE, observer_type="unsupported")


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "analyzer")
    return subprocess.run(
        [sys.executable, "-m", "trustlab.cli", *args],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_unprivileged_app_cli_writes_schema_valid_report(tmp_path):
    output = tmp_path / "app-report.json"
    result = run_cli(
        "normalize",
        "--input",
        str(RAW_FIXTURE),
        "--output",
        str(output),
        "--observer",
        "unprivileged_app",
        "--target-type",
        "avd",
        "--collection-timestamp",
        "2026-04-25T15:06:21Z",
        "--raw-artifact-ref",
        "tests/fixtures/sample_raw_report.txt",
    )
    assert result.returncode == 0
    assert result.stderr == ""
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["observer"]["privilege_level"] == "app_sandbox"
    validate_report(report)


def test_unsupported_observer_cli_is_clean_and_writes_nothing(tmp_path):
    output = tmp_path / "unsupported.json"
    result = run_cli(
        "normalize",
        "--input",
        str(RAW_FIXTURE),
        "--output",
        str(output),
        "--observer",
        "unsupported",
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "invalid choice" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()
