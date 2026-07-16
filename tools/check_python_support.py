#!/usr/bin/env python3
"""Check Python support declarations across package metadata, docs, and CI."""

from __future__ import annotations

import argparse
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from trustlab.python_support import (  # noqa: E402
    MINIMUM_PYTHON,
    SUPPORTED_PYTHON_TEXT,
    SUPPORTED_PYTHON_VERSIONS,
)


def support_errors(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    expected_floor = ">=" + ".".join(str(part) for part in MINIMUM_PYTHON)
    minimum_version = ".".join(str(part) for part in MINIMUM_PYTHON)
    if not SUPPORTED_PYTHON_VERSIONS or SUPPORTED_PYTHON_VERSIONS[0] != minimum_version:
        errors.append("the first supported Python version must match the minimum")
    pyproject = tomllib.loads(
        (root / "analyzer/pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    if pyproject.get("requires-python") != expected_floor:
        errors.append(f"requires-python must be {expected_floor}")
    expected_classifiers = {
        f"Programming Language :: Python :: {version}"
        for version in SUPPORTED_PYTHON_VERSIONS
    }
    actual_classifiers = set(pyproject.get("classifiers", []))
    missing_classifiers = sorted(expected_classifiers - actual_classifiers)
    if missing_classifiers:
        errors.append("missing Python classifiers: " + ", ".join(missing_classifiers))
    advertised_versions = {
        classifier.rsplit(" :: ", 1)[-1]
        for classifier in actual_classifiers
        if classifier.startswith("Programming Language :: Python :: 3.")
    }
    if advertised_versions != set(SUPPORTED_PYTHON_VERSIONS):
        errors.append("package classifiers advertise an unsupported Python matrix")

    workflow = yaml.safe_load(
        (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    test_job = workflow.get("jobs", {}).get("test", {})
    matrix = test_job.get("strategy", {}).get("matrix", {})
    ci_versions = tuple(str(value) for value in matrix.get("python-version", []))
    if ci_versions != SUPPORTED_PYTHON_VERSIONS:
        errors.append("CI Python matrix does not match the support policy")
    steps = test_job.get("steps", [])
    setup_steps = [
        step
        for step in steps
        if str(step.get("uses", "")).startswith("actions/setup-python@")
    ]
    if (
        len(setup_steps) != 1
        or setup_steps[0].get("with", {}).get("python-version")
        != "${{ matrix.python-version }}"
    ):
        errors.append("CI setup-python must consume the Python matrix version")
    if not any(step.get("run") == "bash scripts/check.sh" for step in steps):
        errors.append("CI test matrix must run the complete repository gate")

    for relative in ("README.md", "analyzer/README.md", "docs/python_support.md"):
        text = (root / relative).read_text(encoding="utf-8")
        if SUPPORTED_PYTHON_TEXT not in text:
            errors.append(f"{relative} does not state the supported Python matrix")
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    errors = support_errors()
    if errors:
        raise ValueError("Python support policy errors:\n- " + "\n- ".join(errors))
    print(f"Python support policy is consistent: {SUPPORTED_PYTHON_TEXT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
