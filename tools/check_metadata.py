#!/usr/bin/env python3
"""Check canonical project identifiers and citation structure."""

from __future__ import annotations

import json
import subprocess
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft7Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_URL = "https://github.com/avlasov-co/android-trust-lab"
SCHEMA_IDS = {
    "collection_manifest_v1_0_0.schema.json": (
        f"{REPOSITORY_URL}/schema/collection-manifest/1.0.0"
    ),
    "dataset_manifest_v1_0_0.schema.json": (
        f"{REPOSITORY_URL}/schema/dataset-manifest/1.0.0"
    ),
    "dataset_manifest_v2_0_0.schema.json": (
        f"{REPOSITORY_URL}/schema/dataset-manifest/2.0.0"
    ),
    "dataset_source_v1_0_0.schema.json": (
        f"{REPOSITORY_URL}/schema/dataset-source/1.0.0"
    ),
    "trust_diff.schema.json": f"{REPOSITORY_URL}/blob/main/collector/schema/trust_diff.schema.json",
    "trust_report_v1_0_0.schema.json": f"{REPOSITORY_URL}/blob/main/collector/schema/trust_report.schema.json",
    "trust_report_v2_0_0.schema.json": f"{REPOSITORY_URL}/schema/report/2.0.0",
}
CANONICAL_IDENTIFIERS = {
    "distribution": "android-trust-lab-analyzer",
    "import_package": "trustlab",
    "cli": "trustlab",
    "magisk_module": "androidtrustlab",
    "citation_title": "Android Trust Lab",
}
CFF_SCHEMA_PATH = ROOT / "tools/schemas/cff-1.2.0.schema.json"


class CffLoader(yaml.SafeLoader):
    """Load CFF dates as strings so JSON Schema format checks can inspect them."""


CffLoader.yaml_implicit_resolvers = {
    key: [
        resolver
        for resolver in resolvers
        if resolver[0] != "tag:yaml.org,2002:timestamp"
    ]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def retired_repository_slug() -> str:
    # Keep the retired slug out of tracked text so the scanner can inspect itself.
    return "aleksander" + "-vlasov/android-trust-lab"


def tracked_text_paths(root: Path = ROOT) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    paths: list[Path] = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        path = root / raw_path.decode("utf-8")
        try:
            content = path.read_bytes()
        except FileNotFoundError:
            # An unstaged working-tree deletion remains in `git ls-files
            # --cached`; it has no text left to scan.
            continue
        if b"\0" not in content:
            paths.append(path)
    return paths


def retired_slug_occurrences(paths: Iterable[Path]) -> list[Path]:
    retired = retired_repository_slug()
    matches: list[Path] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if retired in text:
            matches.append(path)
    return matches


def load_mapping(path: Path) -> dict[str, Any]:
    data = yaml.load(path.read_text(encoding="utf-8"), Loader=CffLoader)
    if not isinstance(data, dict):
        raise ValueError(f"expected a mapping in {path.relative_to(ROOT)}")
    return data


def validate_citation(citation: dict[str, Any]) -> None:
    schema = json.loads(CFF_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    validator = Draft7Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(citation), key=lambda error: list(error.path))
    if errors:
        error = errors[0]
        location = "/" + "/".join(map(str, error.path)) if error.path else "/"
        raise ValueError(
            f"CITATION.cff fails the CFF 1.2 schema at {location}: {error.message}"
        )

    required_values = {
        "cff-version": "1.2.0",
        "title": CANONICAL_IDENTIFIERS["citation_title"],
        "type": "software",
        "repository-code": REPOSITORY_URL,
    }
    for key, expected in required_values.items():
        if citation.get(key) != expected:
            raise ValueError(f"CITATION.cff {key!r} must equal {expected!r}")

    if not isinstance(citation.get("message"), str) or not citation["message"].strip():
        raise ValueError("CITATION.cff must contain a nonempty message")
    authors = citation.get("authors")
    if not isinstance(authors, list) or not authors:
        raise ValueError("CITATION.cff must contain at least one author")
    for author in authors:
        if (
            not isinstance(author, dict)
            or not author.get("family-names")
            or not author.get("given-names")
        ):
            raise ValueError("each CFF author must have family-names and given-names")

    preferred = citation.get("preferred-citation")
    if not isinstance(preferred, dict):
        raise ValueError("CITATION.cff must contain a preferred-citation mapping")
    if preferred.get("title") != CANONICAL_IDENTIFIERS["citation_title"]:
        raise ValueError("preferred citation title is not canonical")
    if preferred.get("repository-code") != REPOSITORY_URL:
        raise ValueError("preferred citation repository is not canonical")


def main(paths: Iterable[Path] | None = None) -> int:
    stale_paths = retired_slug_occurrences(
        paths if paths is not None else tracked_text_paths()
    )
    if stale_paths:
        rendered_paths = []
        for path in stale_paths:
            try:
                rendered_paths.append(str(path.relative_to(ROOT)))
            except ValueError:
                rendered_paths.append(path.name)
        rendered = ", ".join(rendered_paths)
        raise ValueError(f"retired repository slug found in tracked text: {rendered}")

    pyproject = tomllib.loads(
        (ROOT / "analyzer" / "pyproject.toml").read_text(encoding="utf-8")
    )
    project = pyproject["project"]
    if project["name"] != CANONICAL_IDENTIFIERS["distribution"]:
        raise ValueError("Python distribution name is not canonical")
    if project["scripts"].get(CANONICAL_IDENTIFIERS["cli"]) != "trustlab.cli:main":
        raise ValueError("CLI project metadata is not canonical")
    if project["urls"].get("Repository") != REPOSITORY_URL:
        raise ValueError("Python repository metadata is not canonical")
    if not (ROOT / "analyzer" / CANONICAL_IDENTIFIERS["import_package"]).is_dir():
        raise ValueError("Python import package is missing")

    module_fields = {}
    for line in (
        (ROOT / "module/trustlab-magisk/module.prop")
        .read_text(encoding="utf-8")
        .splitlines()
    ):
        if "=" in line:
            key, value = line.split("=", 1)
            module_fields[key] = value
    if module_fields.get("id") != CANONICAL_IDENTIFIERS["magisk_module"]:
        raise ValueError("Magisk module ID is not canonical")

    validate_citation(load_mapping(ROOT / "CITATION.cff"))

    for filename, expected_id in SCHEMA_IDS.items():
        schema = json.loads(
            (ROOT / "collector/schema" / filename).read_text(encoding="utf-8")
        )
        if schema.get("$id") != expected_id:
            raise ValueError(f"{filename} $id is not canonical")

    print("canonical project metadata is consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
