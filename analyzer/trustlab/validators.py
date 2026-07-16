"""JSON Schema validation helpers."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, Dict

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JSONSchemaValidationError

from .exceptions import SchemaValidationError, UnsupportedSchemaVersionError

SUPPORTED_REPORT_SCHEMA_VERSIONS = frozenset({"1.0.0"})
SUPPORTED_DIFF_SCHEMA_VERSIONS = frozenset({"1.0.0"})


def load_schema(name: str) -> Dict[str, Any]:
    """Load a canonical schema from the installed analyzer package."""

    resource = files("trustlab.schemas").joinpath(name)
    return json.loads(resource.read_text(encoding="utf-8"))


def _json_pointer(parts: Any) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped) if escaped else "/"


def _constraint_message(error: JSONSchemaValidationError) -> str:
    if error.validator == "required":
        return "required property is missing"
    if error.validator == "enum":
        return "value is not permitted"
    if error.validator == "type":
        return f"expected type {error.validator_value}"
    return f"{error.validator} constraint failed"


def validate_with_schema(
    data: Dict[str, Any],
    schema_name: str,
    *,
    artifact_name: str,
    supported_versions: frozenset[str],
) -> None:
    if not isinstance(data, dict):
        raise SchemaValidationError(f"{artifact_name} must be a JSON object")
    version = data.get("schema_version")
    if not isinstance(version, str):
        raise SchemaValidationError(f"{artifact_name} schema_version is required")
    if version not in supported_versions:
        raise UnsupportedSchemaVersionError(
            f"unsupported {artifact_name} schema version"
        )

    schema = load_schema(schema_name)
    try:
        Draft202012Validator(schema).validate(data)
    except JSONSchemaValidationError as exc:
        location = _json_pointer(exc.absolute_path)
        raise SchemaValidationError(
            f"{artifact_name} schema validation failed at {location}: "
            f"{_constraint_message(exc)}"
        ) from exc


def validate_report(data: Dict[str, Any]) -> None:
    validate_with_schema(
        data,
        "trust_report.schema.json",
        artifact_name="report",
        supported_versions=SUPPORTED_REPORT_SCHEMA_VERSIONS,
    )


def validate_diff(data: Dict[str, Any]) -> None:
    validate_with_schema(
        data,
        "trust_diff.schema.json",
        artifact_name="diff",
        supported_versions=SUPPORTED_DIFF_SCHEMA_VERSIONS,
    )
