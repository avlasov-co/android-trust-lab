from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_python_support", ROOT / "tools/check_python_support.py"
)
check_python_support = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(check_python_support)


def test_python_support_declarations_are_consistent():
    assert check_python_support.support_errors() == []


def test_python_support_checker_detects_ci_drift(tmp_path):
    for relative in (
        ".github/workflows/ci.yml",
        "analyzer/pyproject.toml",
        "analyzer/trustlab/python_support.py",
        "README.md",
        "analyzer/README.md",
        "docs/python_support.md",
    ):
        source = ROOT / relative
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace("'3.14'", "'3.10'"),
        encoding="utf-8",
    )
    assert "CI Python matrix does not match" in "\n".join(
        check_python_support.support_errors(tmp_path)
    )


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    (
        (
            "python-version: ${{ matrix.python-version }}",
            "python-version: '3.11'",
            "CI setup-python must consume the Python matrix version",
        ),
        (
            "run: bash scripts/check.sh",
            "run: python -m pytest",
            "CI test matrix must run the complete repository gate",
        ),
    ),
)
def test_python_support_checker_detects_ci_execution_drift(
    tmp_path, old, new, expected
):
    for relative in (
        ".github/workflows/ci.yml",
        "analyzer/pyproject.toml",
        "analyzer/trustlab/python_support.py",
        "README.md",
        "analyzer/README.md",
        "docs/python_support.md",
    ):
        source = ROOT / relative
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(old, new),
        encoding="utf-8",
    )
    assert expected in check_python_support.support_errors(tmp_path)
