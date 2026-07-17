#!/usr/bin/env python3
"""Verify that project-version surfaces agree with the Python version source."""

from __future__ import annotations

import ast
import importlib.metadata
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from trustlab import __version__ as PUBLIC_VERSION  # noqa: E402

DISTRIBUTION_NAME = "android-trust-lab-analyzer"
DYNAMIC_VERSION_ATTRIBUTE = "trustlab._version.__version__"


def source_version(root: Path = ROOT) -> str:
    path = root / "analyzer/trustlab/_version.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__version__":
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, str
                    ):
                        return node.value.value
    raise ValueError("_version.py must assign a string literal to __version__")


def normalized_version(value: str) -> Version:
    try:
        return Version(value)
    except InvalidVersion as exc:
        raise ValueError(f"invalid project version: {value!r}") from exc


def read_properties(path: Path) -> dict[str, str]:
    fields = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value
    return fields


def project_configuration_errors(root: Path) -> list[str]:
    errors: list[str] = []
    pyproject = tomllib.loads(
        (root / "analyzer/pyproject.toml").read_text(encoding="utf-8")
    )
    project = pyproject["project"]
    if "version" in project:
        errors.append("pyproject.toml must not contain a static project version")
    if "version" not in project.get("dynamic", []):
        errors.append("pyproject.toml must declare the project version dynamic")
    dynamic = pyproject.get("tool", {}).get("setuptools", {}).get("dynamic", {})
    if dynamic.get("version", {}).get("attr") != DYNAMIC_VERSION_ATTRIBUTE:
        errors.append(
            "setuptools must load the version from trustlab._version.__version__"
        )
    return errors


def version_surface_errors(
    root: Path,
    expected: Version,
    version_text: str,
    *,
    distribution_version: str | None,
    public_version: str | None,
) -> list[str]:
    errors: list[str] = []

    if distribution_version is None:
        try:
            distribution_version = importlib.metadata.version(DISTRIBUTION_NAME)
        except importlib.metadata.PackageNotFoundError:
            errors.append(f"installed distribution is missing: {DISTRIBUTION_NAME}")
    if public_version is None:
        public_version = PUBLIC_VERSION

    module = read_properties(root / "module/trustlab-magisk/module.prop")
    artifact_manifest = json.loads(
        (root / "results/artifact_manifest.json").read_text(encoding="utf-8")
    )
    citation = yaml.safe_load((root / "CITATION.cff").read_text(encoding="utf-8"))
    preferred = citation.get("preferred-citation", {})

    surfaces: dict[str, Any] = {
        "installed distribution": distribution_version,
        "trustlab.__version__": public_version,
        "Magisk module": module.get("version"),
        "artifact manifest": artifact_manifest.get("version"),
        "citation": citation.get("version"),
        "preferred citation": preferred.get("version"),
    }
    for label, value in surfaces.items():
        if not isinstance(value, str):
            errors.append(f"{label} version is missing or not a string")
            continue
        module_base = version_text.replace(".dev", "-dev", 1)
        if label == "Magisk module" and value.startswith(f"{module_base}.installfix."):
            continue
        try:
            actual = normalized_version(value)
        except ValueError as exc:
            errors.append(f"{label}: {exc}")
            continue
        if actual != expected:
            errors.append(f"{label} version {value!r} does not match {version_text!r}")

    expected_code = expected.major * 10000 + expected.minor * 100 + expected.micro
    try:
        actual_code = int(module.get("versionCode", ""))
    except ValueError:
        actual_code = -1
    if actual_code not in {expected_code, expected_code + 1}:
        errors.append(
            f"Magisk versionCode must be {expected_code}, found {module.get('versionCode')!r}"
        )

    if "date-released" in citation or "date-released" in preferred:
        errors.append("development citation metadata must not claim date-released")
    return errors


def release_note_errors(root: Path, version_text: str) -> list[str]:
    errors: list[str] = []

    release_notes = (root / "RELEASE_NOTES_v0.2.0.md").read_text(encoding="utf-8")
    release_notes_lower = release_notes.lower()
    if "untagged release candidate" not in release_notes_lower:
        errors.append("v0.2.0 notes must say untagged release candidate")
    if "not a released version" not in release_notes_lower:
        errors.append("v0.2.0 notes must say it is not a released version")
    if version_text not in release_notes:
        errors.append("v0.2.0 notes must identify the current development version")
    return errors


def check_errors(
    root: Path = ROOT,
    *,
    distribution_version: str | None = None,
    public_version: str | None = None,
) -> list[str]:
    version_text = source_version(root)
    expected = normalized_version(version_text)

    return [
        *project_configuration_errors(root),
        *version_surface_errors(
            root,
            expected,
            version_text,
            distribution_version=distribution_version,
            public_version=public_version,
        ),
        *release_note_errors(root, version_text),
    ]


def main() -> int:
    errors = check_errors()
    if errors:
        raise ValueError("version consistency errors:\n- " + "\n- ".join(errors))
    print(f"project version is consistent: {source_version()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
