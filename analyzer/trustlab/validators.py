"""JSON Schema validation helpers."""

from __future__ import annotations

import json
import re
import secrets
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError as JSONSchemaSchemaError
from jsonschema.exceptions import ValidationError as JSONSchemaValidationError

from .compatibility import (
    SchemaFamily,
    current_write_version,
    schema_resource_name,
    supported_schema_versions,
)
from .exceptions import (
    SchemaIssue,
    SchemaValidationError,
    UnsupportedSchemaVersionError,
)
from .migration_codec import encode_legacy_report, legacy_report_digest

SUPPORTED_REPORT_SCHEMA_VERSIONS = supported_schema_versions(SchemaFamily.REPORT)
SUPPORTED_DIFF_SCHEMA_VERSIONS = supported_schema_versions(SchemaFamily.DIFF)
RFC3339_DATE_TIME_RE = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})[Tt]"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.[0-9]+)?(?:[Zz]|(?P<offset_sign>[+-])"
    r"(?P<offset_hour>[0-9]{2}):(?P<offset_minute>[0-9]{2}))$"
)
FORMAT_CHECKER = FormatChecker()


def _days_in_gregorian_month(year: int, month: int) -> int:
    if month == 2:
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        return 29 if leap else 28
    return 30 if month in {4, 6, 9, 11} else 31


def _shift_gregorian_date(
    year: int, month: int, day: int, delta: int
) -> tuple[int, int, int] | None:
    if delta == 0:
        return year, month, day
    if delta == 1:
        day += 1
        if day > _days_in_gregorian_month(year, month):
            day = 1
            month += 1
            if month > 12:
                month = 1
                year += 1
    elif delta == -1:
        day -= 1
        if day == 0:
            month -= 1
            if month == 0:
                month = 12
                year -= 1
            if year >= 0:
                day = _days_in_gregorian_month(year, month)
    else:
        return None
    if not 0 <= year <= 9999:
        return None
    return year, month, day


@FORMAT_CHECKER.checks("date-time")
def _is_rfc3339_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return True
    match = RFC3339_DATE_TIME_RE.fullmatch(value)
    if match is None:
        return False
    year, month, day = (int(part) for part in match.group("date").split("-"))
    if not 1 <= month <= 12:
        return False
    if not 1 <= day <= _days_in_gregorian_month(year, month):
        return False
    hour = int(match.group("hour"))
    minute = int(match.group("minute"))
    second = int(match.group("second"))
    offset_hour = match.group("offset_hour")
    offset_minute = match.group("offset_minute")
    ordinary_ranges_valid = (
        hour <= 23
        and minute <= 59
        and second <= 60
        and (offset_hour is None or int(offset_hour) <= 23)
        and (offset_minute is None or int(offset_minute) <= 59)
    )
    if not ordinary_ranges_valid:
        return False
    if second != 60:
        return True

    offset_total = 0
    if offset_hour is not None and offset_minute is not None:
        offset_total = int(offset_hour) * 60 + int(offset_minute)
        if match.group("offset_sign") == "-":
            offset_total = -offset_total
    utc_total_minutes = hour * 60 + minute - offset_total
    day_delta, utc_minute_of_day = divmod(utc_total_minutes, 24 * 60)
    utc_date = _shift_gregorian_date(year, month, day, day_delta)
    if utc_date is None:
        return False
    _, utc_month, utc_day = utc_date
    return utc_minute_of_day == 23 * 60 + 59 and (utc_month, utc_day) in {
        (6, 30),
        (12, 31),
    }


def load_schema(name: str) -> dict[str, Any]:
    """Load a canonical schema from the installed analyzer package."""

    resource = files("trustlab.schemas").joinpath(name)
    try:
        data = json.loads(resource.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SchemaValidationError(
            "required packaged schema resource is missing"
        ) from exc
    except json.JSONDecodeError as exc:
        raise SchemaValidationError("packaged schema resource is invalid JSON") from exc
    if not isinstance(data, dict):
        raise SchemaValidationError("packaged schema resource must be an object")
    return data


def schema_resource_names() -> tuple[str, ...]:
    return tuple(
        sorted(
            resource.name
            for resource in files("trustlab.schemas").iterdir()
            if resource.name.endswith(".schema.json")
        )
    )


def check_schema(schema: dict[str, Any], *, schema_name: str) -> None:
    try:
        Draft202012Validator.check_schema(schema)
    except JSONSchemaSchemaError as exc:
        raise SchemaValidationError(
            f"project schema is invalid: {schema_name}"
        ) from exc


def check_project_schemas() -> tuple[str, ...]:
    names = schema_resource_names()
    if not names:
        raise SchemaValidationError("no packaged project schemas found")
    for name in names:
        check_schema(load_schema(name), schema_name=name)
    return names


def _json_pointer(parts: Any) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped) if escaped else "/"


def _constraint_message(error: JSONSchemaValidationError) -> str:
    if error.validator == "required":
        match = re.fullmatch(r"'([^']+)' is a required property", error.message)
        return "missing required property: " + (
            match.group(1) if match else "<unknown>"
        )
    if error.validator == "enum":
        return "value is not permitted"
    if error.validator == "type":
        return f"expected type {error.validator_value}"
    if error.validator == "format":
        return f"expected format {error.validator_value}"
    if error.validator == "additionalProperties":
        return "undeclared property is not permitted"
    return f"{error.validator} constraint failed"


def _error_sort_key(
    error: JSONSchemaValidationError,
) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    return (
        tuple(str(part) for part in error.absolute_path),
        tuple(str(part) for part in error.absolute_schema_path),
        error.message,
    )


def validate_with_schema(
    data: object,
    schema_name: str,
    *,
    artifact_name: str,
    supported_versions: frozenset[str],
) -> None:
    if not isinstance(data, dict):
        raise SchemaValidationError(f"{artifact_name} must be a JSON object")
    version = data.get("schema_version")
    if isinstance(version, str) and version not in supported_versions:
        raise UnsupportedSchemaVersionError(
            f"unsupported {artifact_name} schema version"
        )

    schema = load_schema(schema_name)
    check_schema(schema, schema_name=schema_name)
    validator = Draft202012Validator(schema, format_checker=FORMAT_CHECKER)
    errors = sorted(validator.iter_errors(data), key=_error_sort_key)
    if errors:
        issues = tuple(
            SchemaIssue(
                instance_path=_json_pointer(error.absolute_path),
                schema_path=_json_pointer(error.absolute_schema_path),
                validator=str(error.validator),
                message=_constraint_message(error),
            )
            for error in errors
        )
        diagnostics = [f"{issue.instance_path}: {issue.message}" for issue in issues]
        plural = "error" if len(errors) == 1 else "errors"
        version_label = version if isinstance(version, str) else "<missing or invalid>"
        first_error = errors[0]
        safe_cause = JSONSchemaValidationError(
            _constraint_message(first_error),
            validator=str(first_error.validator),
            path=tuple(first_error.absolute_path),
            schema_path=tuple(first_error.absolute_schema_path),
        )
        raise SchemaValidationError(
            f"{artifact_name} schema validation failed for version {version_label} "
            f"({len(errors)} {plural}): " + "; ".join(diagnostics),
            issues=issues,
        ) from safe_cause


def validate_report(data: object) -> None:
    version = data.get("schema_version") if isinstance(data, dict) else None
    resource_version = (
        version
        if isinstance(version, str)
        else current_write_version(SchemaFamily.REPORT)
    )
    validate_with_schema(
        data,
        schema_resource_name(SchemaFamily.REPORT, resource_version),
        artifact_name="report",
        supported_versions=SUPPORTED_REPORT_SCHEMA_VERSIONS,
    )
    if resource_version == "2.0.0":
        _validate_v2_migration_provenance(data)


def _migration_provenance_error(detail: str) -> SchemaValidationError:
    return SchemaValidationError(
        f"report migration provenance validation failed: {detail}"
    )


def _validate_v2_migration_provenance(data: object) -> None:
    """Bind v2 migration claims to one exact, validated v1 source."""

    if not isinstance(data, dict):  # Schema validation has already rejected this.
        return
    provenance = data.get("provenance")
    extensions = data.get("extensions")
    if not isinstance(provenance, dict) or not isinstance(extensions, dict):
        return
    source_version = provenance.get("source_schema_version")
    history = provenance.get("migration_history")
    migration_extension = extensions.get("org.androidtrustlab.migration")

    if source_version == "raw":
        if history != [] or migration_extension is not None:
            raise _migration_provenance_error(
                "raw reports must not claim migration history or preserved sources"
            )
        return

    expected_history = [
        {
            "migration_id": "report-v1-to-v2",
            "source_schema_version": "1.0.0",
            "target_schema_version": "2.0.0",
        }
    ]
    if source_version != "1.0.0" or history != expected_history:
        raise _migration_provenance_error("the registered v1-to-v2 chain is required")
    if not isinstance(migration_extension, dict) or set(migration_extension) != {
        "encoding",
        "source_report_json",
        "source_sha256",
    }:
        raise _migration_provenance_error(
            "the exact preserved-source extension is required"
        )
    encoded_source = migration_extension.get("source_report_json")
    source_digest = migration_extension.get("source_sha256")
    if (
        migration_extension.get("encoding") != "canonical-json-text-v1"
        or not isinstance(encoded_source, str)
        or not isinstance(source_digest, str)
    ):
        raise _migration_provenance_error("the preserved-source encoding is invalid")
    if re.fullmatch(r"[a-f0-9]{64}", source_digest) is None:
        raise _migration_provenance_error("the preserved-source digest is invalid")
    if not secrets.compare_digest(legacy_report_digest(encoded_source), source_digest):
        raise _migration_provenance_error("the preserved-source digest does not match")
    try:
        source = json.loads(
            encoded_source,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid constant: {value}")
            ),
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise _migration_provenance_error(
            "the preserved source is not strict JSON"
        ) from exc
    if not isinstance(source, dict) or encode_legacy_report(source) != encoded_source:
        raise _migration_provenance_error(
            "the preserved source is not deterministically encoded"
        )
    validate_with_schema(
        source,
        schema_resource_name(SchemaFamily.REPORT, "1.0.0"),
        artifact_name="preserved source report",
        supported_versions=frozenset({"1.0.0"}),
    )


def validate_diff(data: object) -> None:
    version = data.get("schema_version") if isinstance(data, dict) else None
    resource_version = (
        version
        if isinstance(version, str)
        else current_write_version(SchemaFamily.DIFF)
    )
    validate_with_schema(
        data,
        schema_resource_name(SchemaFamily.DIFF, resource_version),
        artifact_name="diff",
        supported_versions=SUPPORTED_DIFF_SCHEMA_VERSIONS,
    )
