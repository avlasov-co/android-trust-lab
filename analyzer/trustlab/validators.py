"""JSON Schema validation helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

try:
    from jsonschema import Draft202012Validator
except Exception:  # pragma: no cover - fallback for minimal environments
    Draft202012Validator = None


def repo_root_from(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "collector" / "schema" / "trust_report.schema.json").exists():
            return candidate
    # Installed-package fallback: analyzer/trustlab/validators.py -> analyzer -> repo maybe not available.
    here = Path(__file__).resolve()
    for candidate in [here, *here.parents]:
        if (candidate / "collector" / "schema" / "trust_report.schema.json").exists():
            return candidate
    raise FileNotFoundError("Could not locate collector/schema. Run from repository root or pass valid paths.")


def load_schema(name: str) -> Dict[str, Any]:
    path = repo_root_from() / "collector" / "schema" / name
    return json.loads(path.read_text(encoding="utf-8"))


def validate_with_schema(data: Dict[str, Any], schema_name: str) -> None:
    schema = load_schema(schema_name)
    if Draft202012Validator is None:
        missing = [key for key in schema.get("required", []) if key not in data]
        if missing:
            raise ValueError(f"Missing required fields for {schema_name}: {missing}")
        return
    Draft202012Validator(schema).validate(data)


def validate_report(data: Dict[str, Any]) -> None:
    validate_with_schema(data, "trust_report.schema.json")


def validate_diff(data: Dict[str, Any]) -> None:
    validate_with_schema(data, "trust_diff.schema.json")
