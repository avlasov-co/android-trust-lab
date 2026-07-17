"""JSON Schema validation helpers."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from fractions import Fraction
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError as JSONSchemaSchemaError
from jsonschema.exceptions import ValidationError as JSONSchemaValidationError

from .canonical_json import (
    CanonicalJSONError,
    canonical_json_bytes,
    framed_content_digest,
    parse_canonical_json,
)
from .comparison import classify_comparison_contexts
from .compatibility import (
    SchemaFamily,
    current_write_version,
    report_migration_path,
    schema_resource_name,
    supported_schema_versions,
)
from .exceptions import (
    CollectionError,
    ComparisonAcknowledgementError,
    SchemaIssue,
    SchemaValidationError,
    UnsupportedSchemaVersionError,
)
from .identity import (
    REPORT_EVIDENCE_FIELDS,
    collection_event_identity,
    validate_relative_artifact_path,
    validate_report_identities,
)
from .migration_codec import encode_legacy_report, legacy_report_digest
from .privacy import (
    validate_portable_collection_manifest,
    validate_portable_diff,
    validate_portable_report,
)
from .report_v3 import migrate_v2_source_reference
from .report_v4 import report_v4_from_v3_shape
from .report_v5 import report_v5_from_v4_shape
from .report_v6 import report_v6_from_v5_shape
from .security_evidence import SELECTED_PROCESS_NAMES, is_selected_process_capture

SUPPORTED_REPORT_SCHEMA_VERSIONS = supported_schema_versions(SchemaFamily.REPORT)
SUPPORTED_DIFF_SCHEMA_VERSIONS = supported_schema_versions(SchemaFamily.DIFF)
SUPPORTED_DATASET_MANIFEST_SCHEMA_VERSIONS = supported_schema_versions(
    SchemaFamily.DATASET_MANIFEST
)
SUPPORTED_COLLECTION_MANIFEST_SCHEMA_VERSIONS = supported_schema_versions(
    SchemaFamily.COLLECTION_MANIFEST
)
SUPPORTED_DATASET_SOURCE_SCHEMA_VERSIONS = frozenset({"1.0.0"})
RFC3339_DATE_TIME_RE = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})[Tt]"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]+))?(?:[Zz]|(?P<offset_sign>[+-])"
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
    try:
        errors = sorted(validator.iter_errors(data), key=_error_sort_key)
    except RecursionError as exc:
        raise SchemaValidationError(
            f"{artifact_name} schema validation exceeded the nesting limit"
        ) from exc
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
    if resource_version in {"2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0"}:
        _validate_canonical_document(data, artifact_name="report")
    validate_with_schema(
        data,
        schema_resource_name(SchemaFamily.REPORT, resource_version),
        artifact_name="report",
        supported_versions=SUPPORTED_REPORT_SCHEMA_VERSIONS,
    )
    if resource_version == "2.0.0":
        _validate_v2_migration_provenance(data)
    elif resource_version == "3.0.0":
        _validate_v3_report_semantics(data)
    elif resource_version == "4.0.0":
        _validate_v4_report_semantics(data)
    elif resource_version == "5.0.0":
        _validate_v5_report_semantics(data)
    elif resource_version == "6.0.0":
        _validate_v6_report_semantics(data)
        validate_portable_report(data)


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


def _validate_v3_raw_artifacts(data: dict[str, Any]) -> list[dict[str, Any]]:
    raw_artifacts = cast(list[dict[str, Any]], data["raw_artifacts"])
    logical_ids = [artifact["logical_id"] for artifact in raw_artifacts]
    relative_paths = [artifact["relative_path"] for artifact in raw_artifacts]
    if len(logical_ids) != len(set(logical_ids)):
        raise SchemaValidationError("report raw artifact logical IDs must be unique")
    if len(relative_paths) != len(set(relative_paths)):
        raise SchemaValidationError("report raw artifact paths must be unique")
    for path in relative_paths:
        pure = PurePosixPath(path)
        if (
            pure.is_absolute()
            or path != pure.as_posix()
            or "\\" in path
            or ":" in path
            or any(part in {"", ".", ".."} for part in pure.parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
        ):
            raise SchemaValidationError(
                "report raw artifact paths must be normalized and relative"
            )
    if len({artifact["collection_id"] for artifact in raw_artifacts}) != 1:
        raise SchemaValidationError(
            "report raw artifacts must belong to one collection event"
        )
    if (
        len(
            {
                (artifact["collector_name"], artifact["collector_version"])
                for artifact in raw_artifacts
            }
        )
        != 1
    ):
        raise SchemaValidationError(
            "report raw artifacts must identify one collector implementation"
        )
    ordering = [
        (artifact["logical_id"], artifact["relative_path"], artifact["sha256"])
        for artifact in raw_artifacts
    ]
    if ordering != sorted(ordering):
        raise SchemaValidationError(
            "report raw artifacts must use canonical logical ID and path order"
        )
    return raw_artifacts


def _validate_v3_migration_provenance(
    data: dict[str, Any], raw_artifacts: list[dict[str, Any]]
) -> None:
    provenance = data["provenance"]
    history = provenance["migration_history"]
    source_version = provenance["source_schema_version"]
    migration_extension = data["extensions"].get("org.androidtrustlab.migration-v3")
    if source_version == "raw":
        if (
            history
            or migration_extension is not None
            or "org.androidtrustlab.migration" in data["extensions"]
        ):
            raise _migration_provenance_error(
                "raw v3 reports must not claim migration history or a v2 source"
            )
        collection_manifest_digest = _validate_v3_collection_extension(
            data, raw_artifacts
        )
        expected_event_id = collection_event_identity(
            collection_id=raw_artifacts[0]["collection_id"],
            timestamp=data["collection_timestamp"],
            experiment_id=data["experiment_id"],
            target_type=data["target"]["target_type"],
            observer_type=data["observer"]["observer_type"],
            collection_method=data["observer"]["collection_method"],
            collection_manifest_sha256=collection_manifest_digest,
        )
        if not secrets.compare_digest(data["collection_event_id"], expected_event_id):
            raise _migration_provenance_error(
                "the raw collection event identity does not match its provenance"
            )
    else:
        expected_tail = {
            "migration_id": "report-v2-to-v3",
            "source_schema_version": "2.0.0",
            "target_schema_version": "3.0.0",
        }
        if (
            source_version != "2.0.0"
            or not history
            or any(
                history[-1].get(key) != value for key, value in expected_tail.items()
            )
        ):
            raise _migration_provenance_error(
                "the registered v2-to-v3 migration must terminate the chain"
            )
        if len(history) == 2 and {
            key: history[0].get(key)
            for key in (
                "migration_id",
                "source_schema_version",
                "target_schema_version",
            )
        } != {
            "migration_id": "report-v1-to-v2",
            "source_schema_version": "1.0.0",
            "target_schema_version": "2.0.0",
        }:
            raise _migration_provenance_error(
                "the historical v1-to-v2 migration record is invalid"
            )
        if len(history) not in {1, 2}:
            raise _migration_provenance_error(
                "the registered report migration chain is required"
            )
        if not isinstance(migration_extension, dict) or set(migration_extension) != {
            "encoding",
            "source_report_json",
            "source_sha256",
        }:
            raise _migration_provenance_error(
                "the exact canonical v2 source extension is required"
            )
        encoded_source = migration_extension.get("source_report_json")
        source_digest = migration_extension.get("source_sha256")
        if (
            migration_extension.get("encoding") != "atl-canonical-json-v1"
            or not isinstance(encoded_source, str)
            or not isinstance(source_digest, str)
        ):
            raise _migration_provenance_error("the canonical v2 source is invalid")
        try:
            source = parse_canonical_json(encoded_source.encode("utf-8"))
        except ValueError as exc:
            raise _migration_provenance_error(
                "the preserved v2 source is not canonical JSON"
            ) from exc
        if (
            not isinstance(source, dict)
            or canonical_json_bytes(source).decode("utf-8") != encoded_source
            or not secrets.compare_digest(
                hashlib.sha256(encoded_source.encode("utf-8")).hexdigest(),
                source_digest,
            )
        ):
            raise _migration_provenance_error(
                "the preserved v2 source binding does not match"
            )
        validate_with_schema(
            source,
            schema_resource_name(SchemaFamily.REPORT, "2.0.0"),
            artifact_name="preserved source report",
            supported_versions=frozenset({"2.0.0"}),
        )
        _validate_v2_migration_provenance(source)
        if len(raw_artifacts) != 1 or any(
            (
                raw_artifacts[0]["sha256"] != source_digest,
                raw_artifacts[0]["byte_size"] != len(encoded_source.encode("utf-8")),
                raw_artifacts[0]["media_type"] != "application/json",
                raw_artifacts[0]["status"] != "observed",
            )
        ):
            raise _migration_provenance_error(
                "the structured source reference must bind the canonical v2 report"
            )
        _validate_v3_migrated_payload(data, raw_artifacts, source)


def _validate_v3_migrated_payload(
    data: dict[str, Any],
    raw_artifacts: list[dict[str, Any]],
    source: dict[str, Any],
) -> None:
    """Prove that v3 evidence and provenance are the declared v2 migration."""

    expected_reference, expected_event_id, expected_extension = (
        migrate_v2_source_reference(source)
    )
    if raw_artifacts != [expected_reference.to_dict()]:
        raise _migration_provenance_error(
            "the structured source reference does not match the canonical v2 source"
        )
    if data["collection_event_id"] != expected_event_id:
        raise _migration_provenance_error(
            "the collection event does not bind the canonical v2 source"
        )
    copied_fields = (
        "collection_timestamp",
        "experiment_id",
        *REPORT_EVIDENCE_FIELDS,
    )
    if any(data[field] != source[field] for field in copied_fields):
        raise _migration_provenance_error(
            "the report evidence does not match the canonical v2 source"
        )
    provenance = data["provenance"]
    if (
        provenance["normalizer"] != source["provenance"]["normalizer"]
        or provenance["command_results"] != source["provenance"]["command_results"]
    ):
        raise _migration_provenance_error(
            "the report provenance does not preserve the canonical v2 source"
        )
    generator = provenance["generator"]
    if generator["name"] != "trustlab-migration":
        raise _migration_provenance_error(
            "the v2-to-v3 generator must identify the migration implementation"
        )
    historical_version = source["provenance"]["normalizer"]["version"]
    expected_history = [
        {
            **record,
            "implementation": {
                "name": "trustlab-migration",
                "version": historical_version,
            },
        }
        for record in source["provenance"]["migration_history"]
    ]
    expected_history.append(
        {
            "migration_id": "report-v2-to-v3",
            "source_schema_version": "2.0.0",
            "target_schema_version": "3.0.0",
            "implementation": generator,
        }
    )
    if provenance["migration_history"] != expected_history:
        raise _migration_provenance_error(
            "the report migration history does not match the canonical v2 source"
        )
    expected_extensions = {
        **source["extensions"],
        **expected_extension,
    }
    if data["extensions"] != expected_extensions:
        raise _migration_provenance_error(
            "the report extensions do not preserve the canonical v2 source"
        )


def _validate_v3_collection_extension(
    data: dict[str, Any], raw_artifacts: list[dict[str, Any]]
) -> str | None:
    extension = data["extensions"].get("org.androidtrustlab.collection")
    if extension is None:
        return None
    if not isinstance(extension, dict) or set(extension) != {
        "canonicalization",
        "canonical_manifest_sha256",
        "manifest",
    }:
        raise SchemaValidationError(
            "report collection provenance must use the exact manifest binding"
        )
    canonicalization = extension["canonicalization"]
    declared_digest = extension["canonical_manifest_sha256"]
    if (
        canonicalization != "atl-canonical-json-v1"
        or not isinstance(declared_digest, str)
        or re.fullmatch(r"[a-f0-9]{64}", declared_digest) is None
    ):
        raise SchemaValidationError(
            "report collection manifest digest metadata is invalid"
        )
    manifest = extension["manifest"]
    validate_collection_manifest(manifest)
    expected_digest = hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()
    if not secrets.compare_digest(declared_digest, expected_digest):
        raise SchemaValidationError(
            "report collection manifest digest does not match its provenance"
        )
    manifest_artifacts = {
        artifact["logical_name"]: artifact for artifact in manifest["artifacts"]
    }
    selected_sources = [
        artifact
        for artifact in manifest["artifacts"]
        if artifact["logical_name"] == "raw_report"
        and artifact["media_type"] == "text/plain"
        and artifact["status"] == "observed"
    ]
    if (
        len(raw_artifacts) != 1
        or len(selected_sources) != 1
        or raw_artifacts[0]["logical_id"] != selected_sources[0]["logical_name"]
    ):
        raise SchemaValidationError(
            "report collection provenance must bind its unique observed raw_report"
        )
    for raw_reference in raw_artifacts:
        manifest_artifact = manifest_artifacts.get(raw_reference["logical_id"])
        expected_artifact = {
            "relative_path": raw_reference["relative_path"],
            "sha256": raw_reference["sha256"],
            "byte_size": raw_reference["byte_size"],
            "media_type": raw_reference["media_type"],
            "status": raw_reference["status"],
            "redaction_state": raw_reference["redaction_state"],
        }
        if manifest_artifact is None or any(
            manifest_artifact[field] != value
            for field, value in expected_artifact.items()
        ):
            raise SchemaValidationError(
                "report raw artifact does not match its collection manifest"
            )
        if (
            raw_reference["collection_id"] != manifest["collection_id"]
            or raw_reference["collector_name"] != manifest["collector"]["name"]
            or raw_reference["collector_version"] != manifest["collector"]["version"]
        ):
            raise SchemaValidationError(
                "report raw artifact collector does not match its collection manifest"
            )
    raw_reference = raw_artifacts[0]
    expected_report_metadata = (
        (manifest["collection_id"], raw_reference["collection_id"]),
        (manifest["collector"]["name"], raw_reference["collector_name"]),
        (manifest["collector"]["version"], raw_reference["collector_version"]),
        (manifest["ended_at"], data["collection_timestamp"]),
        (manifest["experiment_id"], data["experiment_id"]),
        (manifest["target"]["target_type"], data["target"]["target_type"]),
        (manifest["observer"]["observer_type"], data["observer"]["observer_type"]),
        (
            manifest["observer"]["collection_method"],
            data["observer"]["collection_method"],
        ),
    )
    if any(observed != expected for observed, expected in expected_report_metadata):
        raise SchemaValidationError(
            "report metadata does not match its collection manifest"
        )
    expected_command_results = [
        {
            "command_id": artifact["probe_id"],
            "status": artifact["status"],
            "exit_code": artifact["exit_code"],
            "timed_out": artifact["timed_out"],
            "detail": artifact["detail"],
        }
        for artifact in manifest["artifacts"]
    ]
    if data["provenance"]["command_results"] != expected_command_results:
        raise SchemaValidationError(
            "report command results do not match its collection manifest"
        )
    expected_collection_errors: list[str] = []
    if manifest["completion_status"] != "complete":
        expected_collection_errors.append(
            f"collection manifest completion status: {manifest['completion_status']}"
        )
    expected_collection_errors.extend(
        f"collection warning: {warning}"[:1024] for warning in manifest["warnings"]
    )
    for artifact in manifest["artifacts"]:
        if artifact["status"] in {"observed", "observed_absent"}:
            continue
        detail = f": {artifact['detail']}" if artifact["detail"] else ""
        expected_collection_errors.append(
            f"probe {artifact['probe_id']}: {artifact['status']}{detail}"[:1024]
        )
    report_errors = data["limitations"]["collection_errors"]
    if any(
        error not in report_errors
        for error in dict.fromkeys(expected_collection_errors)
    ):
        raise SchemaValidationError(
            "report limitations do not retain its collection manifest outcomes"
        )
    return declared_digest


def _validate_v3_report_semantics(data: object) -> None:
    """Validate v3 source bindings, migration claims, and both identities."""

    if not isinstance(data, dict):
        return
    raw_artifacts = _validate_v3_raw_artifacts(data)
    _validate_v3_migration_provenance(data, raw_artifacts)
    validate_report_identities(data)


def _validate_v4_report_semantics(data: object) -> None:
    """Validate v4 source binding, deterministic migration, and identities."""

    if not isinstance(data, dict):
        return
    _validate_v4_mount_semantics(data["mounts"])
    raw_artifacts = _validate_v3_raw_artifacts(data)
    provenance = data["provenance"]
    source_version = provenance["source_schema_version"]
    migration_extension = data["extensions"].get("org.androidtrustlab.migration-v4")
    if source_version == "raw":
        if migration_extension is not None:
            raise _migration_provenance_error(
                "raw v4 reports must not preserve a v3 migration source"
            )
        _validate_v3_migration_provenance(data, raw_artifacts)
        validate_report_identities(data)
        return
    if source_version != "3.0.0":
        raise _migration_provenance_error("v4 migrations require one exact v3 source")
    if not isinstance(migration_extension, dict) or set(migration_extension) != {
        "encoding",
        "source_report_json",
        "source_sha256",
    }:
        raise _migration_provenance_error(
            "the exact canonical v3 source extension is required"
        )
    encoded_source = migration_extension.get("source_report_json")
    source_digest = migration_extension.get("source_sha256")
    if (
        migration_extension.get("encoding") != "atl-canonical-json-v1"
        or not isinstance(encoded_source, str)
        or not isinstance(source_digest, str)
    ):
        raise _migration_provenance_error("the canonical v3 source is invalid")
    try:
        source = parse_canonical_json(encoded_source.encode("utf-8"))
    except ValueError as exc:
        raise _migration_provenance_error(
            "the preserved v3 source is not canonical JSON"
        ) from exc
    if (
        not isinstance(source, dict)
        or source.get("schema_version") != "3.0.0"
        or canonical_json_bytes(source).decode("utf-8") != encoded_source
        or not secrets.compare_digest(
            hashlib.sha256(encoded_source.encode("utf-8")).hexdigest(),
            source_digest,
        )
    ):
        raise _migration_provenance_error(
            "the preserved v3 source binding does not match"
        )
    validate_report(source)
    migration_history = data["provenance"]["migration_history"]
    if not migration_history:
        raise _migration_provenance_error(
            "the report-v3-to-v4 migration record is required"
        )
    declared_implementation_version = migration_history[-1]["implementation"]["version"]
    expected = report_v4_from_v3_shape(
        source,
        add_v3_to_v4_migration=True,
        migration_implementation_version=declared_implementation_version,
    )
    if data != expected:
        raise _migration_provenance_error(
            "the v4 report is not the deterministic migration of its v3 source"
        )
    validate_report_identities(data)


def _validate_v5_evidence_refs(refs: list[str]) -> None:
    for reference in refs:
        try:
            validate_relative_artifact_path(reference)
        except CollectionError as exc:
            raise SchemaValidationError(
                "report security evidence reference must be portable"
            ) from exc


def _expected_v5_process_limitations(
    processes: dict[str, Any], selected: list[dict[str, Any]]
) -> list[str]:
    expected = ["observer_scoped_visibility"]
    optional = (
        (processes["scope"] == "selected", "selected_filter_not_exhaustive"),
        (processes["scope"] == "app_sandbox", "app_sandbox_visibility"),
        (processes["completeness"] == "partial", "partial_process_table"),
        (processes["completeness"] == "unsupported", "unsupported_ps_format"),
        (
            any(
                item["visibility"]["status"] == "observed"
                and item["context"]["status"] == "not_collected"
                for item in selected
            ),
            "process_contexts_not_collected",
        ),
    )
    expected.extend(code for required, code in optional if required)
    return expected


def _validate_v5_direct_process_scope(
    processes: dict[str, Any],
    selected: list[dict[str, Any]],
    *,
    observer_type: str,
) -> None:
    app_scope_required = (
        observer_type == "unprivileged_app"
        and processes["capture_status"] != "not_collected"
    )
    if (app_scope_required and processes["scope"] != "app_sandbox") or (
        observer_type != "unprivileged_app" and processes["scope"] == "app_sandbox"
    ):
        raise SchemaValidationError(
            "report process scope does not match the observer boundary"
        )
    if processes["limitations"] != _expected_v5_process_limitations(
        processes, selected
    ):
        raise SchemaValidationError(
            "report process limitations do not match its scope and parser outcome"
        )


def _validate_v5_process_capture_shape(processes: dict[str, Any]) -> None:
    if processes["capture_status"] == "observed":
        if not processes["evidence_refs"]:
            raise SchemaValidationError(
                "observed process capture requires a source evidence reference"
            )
        if processes["completeness"] == "unknown":
            raise SchemaValidationError(
                "observed process captures require an explicit parser outcome"
            )
        expected_formats = (
            {"unknown"}
            if processes["completeness"] in {"malformed", "unsupported"}
            else {
                "complete": {"toybox", "toolbox"},
                "selected": {"selected"},
                "app_sandbox": {"selected", "toybox", "toolbox"},
                "unknown": {"unknown"},
            }[processes["scope"]]
        )
        if processes["source_format"] not in expected_formats:
            raise SchemaValidationError(
                "report process format does not match its declared scope"
            )
    elif processes["evidence_refs"]:
        raise SchemaValidationError(
            "unobserved process capture cannot retain source evidence references"
        )


def _validate_v5_process_item(
    item: dict[str, Any], *, absence_capable: bool, all_refs: list[str]
) -> None:
    visibility = item["visibility"]
    context = item["context"]
    refs = item["evidence_refs"]
    all_refs.extend(refs)
    invalid = (
        (
            visibility["status"] == "observed_absent" and not absence_capable,
            "report cannot infer process absence from scoped or partial evidence",
        ),
        (
            context["status"] == "observed" and visibility["status"] != "observed",
            "report process context requires observed process visibility",
        ),
        (
            visibility["status"] == "observed" and not refs,
            "observed process visibility requires an evidence reference",
        ),
        (
            visibility["status"] == "observed_absent"
            and context["status"] != "observed_absent",
            "observed process absence requires an absent process context",
        ),
        (
            visibility["status"] != "observed" and bool(refs),
            "unobserved process visibility cannot retain row references",
        ),
        (
            visibility["status"] not in {"observed", "observed_absent"}
            and context["status"] != visibility["status"],
            "unavailable process visibility and context statuses must agree",
        ),
    )
    for failed, message in invalid:
        if failed:
            raise SchemaValidationError(message)


def _validate_v5_process_semantics(
    processes: dict[str, Any],
    all_refs: list[str],
    *,
    observer_type: str,
    migrated: bool,
) -> None:
    selected = processes["selected_processes"]
    all_refs.extend(processes["evidence_refs"])
    if [item["name"] for item in selected] != list(SELECTED_PROCESS_NAMES):
        raise SchemaValidationError(
            "report selected process observations must use canonical name order"
        )
    if not migrated:
        _validate_v5_direct_process_scope(
            processes, selected, observer_type=observer_type
        )
    _validate_v5_process_capture_shape(processes)
    absence_capable = (
        processes["capture_status"] == "observed"
        and processes["scope"] == "complete"
        and processes["completeness"] == "complete"
    )
    for item in selected:
        _validate_v5_process_item(
            item, absence_capable=absence_capable, all_refs=all_refs
        )
    if processes["capture_status"] != "observed" and (
        processes["completeness"] != "unknown"
        or any(
            item["visibility"]["status"] != processes["capture_status"]
            for item in selected
        )
    ):
        raise SchemaValidationError(
            "unavailable process captures cannot claim parsed visibility"
        )


def _validate_v5_selinux_semantics(selinux: dict[str, Any], *, migrated: bool) -> None:
    if not migrated:
        expected_limitations = ["complete_policy_not_inspected"]
        if selinux["denial_collection"]["status"] != "observed":
            expected_limitations.append("denials_not_collected")
        if selinux["current_context"]["status"] != "observed":
            expected_limitations.append("current_context_not_observed")
        if selinux["limitations"] != expected_limitations:
            raise SchemaValidationError(
                "report SELinux limitations do not match its evidence statuses"
            )
    for field_name in ("policy_mode", "current_context", "denial_collection"):
        evidence = selinux[field_name]
        if (
            not migrated
            and evidence["status"] == "observed"
            and not evidence["evidence_refs"]
        ):
            raise SchemaValidationError(
                f"direct observed SELinux {field_name} requires an evidence reference"
            )
        if evidence["status"] != "observed" and evidence["evidence_refs"]:
            raise SchemaValidationError(
                f"unobserved SELinux {field_name} cannot retain evidence references"
            )


def _v5_adapter_capture(
    data: dict[str, Any], names: frozenset[str]
) -> dict[str, Any] | None:
    adapter = data["extensions"].get("org.androidtrustlab.adapter", {})
    captures = adapter.get("captures", []) if isinstance(adapter, dict) else []
    matches = [
        capture
        for capture in captures
        if isinstance(capture, dict) and capture.get("name") in names
    ]
    if len(matches) > 1:
        raise SchemaValidationError(
            "report security evidence has duplicate semantic adapter captures"
        )
    if not matches:
        return None
    capture = matches[0]
    if not isinstance(capture.get("status"), str) or not isinstance(
        capture.get("source_ref"), str
    ):
        raise SchemaValidationError("report security adapter capture is invalid")
    return capture


def _v5_command_status(data: dict[str, Any], names: frozenset[str]) -> str:
    command_results = data["provenance"]["command_results"]
    matches = [result for result in command_results if result["command_id"] in names]
    if len(matches) > 1:
        raise SchemaValidationError(
            "report security evidence has duplicate semantic command results"
        )
    command_status = matches[0]["status"] if matches else None
    adapter_capture = _v5_adapter_capture(data, names)
    adapter_status = None
    if adapter_capture is not None:
        raw_status = adapter_capture["status"]
        adapter_status = {
            "observed": "observed",
            "empty": "observed_absent",
            "not_collected": "not_collected",
            "inaccessible": "inaccessible",
            "command_error": "command_error",
            "timeout": "command_error",
            "unsupported": "unsupported",
            "error": "command_error",
        }.get(raw_status)
        if adapter_status is None:
            raise SchemaValidationError(
                "report security adapter capture status is invalid"
            )
    if (
        command_status is not None
        and adapter_status is not None
        and (command_status != adapter_status)
    ):
        raise SchemaValidationError(
            "report command and adapter capture statuses do not agree"
        )
    return command_status or adapter_status or "not_collected"


def _require_v5_capture(
    capture: dict[str, Any] | None, *, evidence_name: str, status: str
) -> dict[str, Any] | None:
    if status != "not_collected" and capture is None:
        raise SchemaValidationError(
            f"report {evidence_name} requires its semantic adapter capture"
        )
    return capture


def _validate_v5_refs_bind_capture(
    refs: list[str],
    capture: dict[str, Any],
    *,
    evidence_name: str,
) -> None:
    source_ref = capture["source_ref"]
    if refs != [source_ref]:
        raise SchemaValidationError(
            f"report {evidence_name} source reference does not bind its "
            "semantic adapter capture"
        )


def _validate_v5_security_provenance(data: dict[str, Any]) -> None:
    adapter = data["extensions"].get("org.androidtrustlab.adapter")
    if not isinstance(adapter, dict) or not isinstance(adapter.get("captures"), list):
        raise SchemaValidationError(
            "direct report security evidence requires adapter capture provenance"
        )
    processes = data["process_state"]
    process_names = frozenset({"processes", "ps_selected"})
    process_capture = _v5_adapter_capture(data, process_names)
    process_result = _v5_command_status(data, process_names)
    expected_process_status = (
        "observed"
        if process_result in {"observed", "observed_absent"}
        else process_result
    )
    if processes["capture_status"] != expected_process_status:
        raise SchemaValidationError(
            "report process capture status does not match command provenance"
        )
    process_capture = _require_v5_capture(
        process_capture,
        evidence_name="process evidence",
        status=processes["capture_status"],
    )
    if processes["capture_status"] == "observed" and process_capture is not None:
        if processes["evidence_refs"] != [process_capture["source_ref"]]:
            raise SchemaValidationError(
                "report process capture source reference does not bind its "
                "semantic adapter capture"
            )
        for item in processes["selected_processes"]:
            if item["visibility"]["status"] == "observed":
                _validate_v5_refs_bind_capture(
                    item["evidence_refs"],
                    process_capture,
                    evidence_name=f"selected process {item['name']}",
                )
        selected_capture = is_selected_process_capture(
            process_capture["name"],
            process_capture["source_ref"],
        )
        if selected_capture and processes["scope"] not in {
            "selected",
            "app_sandbox",
        }:
            raise SchemaValidationError(
                "report filtered process capture cannot claim complete scope"
            )

    selinux = data["selinux"]
    mode_names = frozenset({"selinux_mode", "getenforce"})
    mode_capture = _v5_adapter_capture(data, mode_names)
    mode_result = _v5_command_status(data, mode_names)
    allowed_mode_statuses = (
        {"observed", "command_error"}
        if mode_result == "observed"
        else {"command_error"}
        if mode_result == "observed_absent"
        else {mode_result}
    )
    if selinux["policy_mode"]["status"] not in allowed_mode_statuses:
        raise SchemaValidationError(
            "report SELinux mode status does not match command provenance"
        )
    mode_capture = _require_v5_capture(
        mode_capture,
        evidence_name="SELinux policy-mode evidence",
        status=selinux["policy_mode"]["status"],
    )
    if selinux["policy_mode"]["status"] == "observed" and mode_capture is not None:
        _validate_v5_refs_bind_capture(
            selinux["policy_mode"]["evidence_refs"],
            mode_capture,
            evidence_name="SELinux policy-mode evidence",
        )

    context_names = frozenset(
        {
            "selinux_context",
            "collector_context",
            "app_context",
            "selinux_self_context",
        }
    )
    context_capture = _v5_adapter_capture(data, context_names)
    context_result = _v5_command_status(
        data,
        context_names,
    )
    allowed_context_statuses = (
        {"observed", "command_error"}
        if context_result == "observed"
        else {context_result}
    )
    if selinux["current_context"]["status"] not in allowed_context_statuses:
        raise SchemaValidationError(
            "report SELinux context status does not match command provenance"
        )
    context_capture = _require_v5_capture(
        context_capture,
        evidence_name="SELinux current-context evidence",
        status=selinux["current_context"]["status"],
    )
    if (
        selinux["current_context"]["status"] == "observed"
        and context_capture is not None
    ):
        _validate_v5_refs_bind_capture(
            selinux["current_context"]["evidence_refs"],
            context_capture,
            evidence_name="SELinux current-context evidence",
        )

    denial_names = frozenset({"selinux_denials"})
    denial_capture = _v5_adapter_capture(data, denial_names)
    denial_result = _v5_command_status(data, denial_names)
    expected_denial_status = (
        "observed"
        if denial_result in {"observed", "observed_absent"}
        else denial_result
    )
    if selinux["denial_collection"]["status"] != expected_denial_status:
        raise SchemaValidationError(
            "report SELinux denial status does not match command provenance"
        )
    denial_capture = _require_v5_capture(
        denial_capture,
        evidence_name="SELinux denial evidence",
        status=selinux["denial_collection"]["status"],
    )
    if (
        selinux["denial_collection"]["status"] == "observed"
        and denial_capture is not None
        and selinux["denial_collection"]["evidence_refs"]
        != [denial_capture["source_ref"]]
    ):
        raise SchemaValidationError(
            "report SELinux denial source reference does not bind its semantic "
            "adapter capture"
        )


def _validate_v5_security_semantics(data: dict[str, Any]) -> None:
    observer_type = data["observer"]["observer_type"]
    selinux = data["selinux"]
    processes = data["process_state"]
    if (
        selinux["source_observer"] != observer_type
        or processes["source_observer"] != observer_type
    ):
        raise SchemaValidationError(
            "report security evidence source observer does not match the report"
        )
    all_refs = [
        *selinux["policy_mode"]["evidence_refs"],
        *selinux["current_context"]["evidence_refs"],
        *selinux["denial_collection"]["evidence_refs"],
    ]
    migrated = data["provenance"]["source_schema_version"] == "4.0.0"
    _validate_v5_process_semantics(
        processes,
        all_refs,
        observer_type=observer_type,
        migrated=migrated,
    )
    _validate_v5_selinux_semantics(
        selinux,
        migrated=migrated,
    )
    if not migrated:
        _validate_v5_security_provenance(data)
    _validate_v5_evidence_refs(all_refs)


def _validate_v5_report_semantics(data: object) -> None:
    """Validate v5 structured evidence, exact v4 source, and identities."""

    if not isinstance(data, dict):
        return
    _validate_v5_security_semantics(data)
    _validate_v4_mount_semantics(data["mounts"])
    raw_artifacts = _validate_v3_raw_artifacts(data)
    source_version = data["provenance"]["source_schema_version"]
    migration_extension = data["extensions"].get("org.androidtrustlab.migration-v5")
    if source_version == "raw":
        if migration_extension is not None:
            raise _migration_provenance_error(
                "raw v5 reports must not preserve a v4 migration source"
            )
        _validate_v3_migration_provenance(data, raw_artifacts)
        validate_report_identities(data)
        return
    if source_version != "4.0.0":
        raise _migration_provenance_error("v5 migrations require one exact v4 source")
    if not isinstance(migration_extension, dict) or set(migration_extension) != {
        "encoding",
        "source_report_json",
        "source_sha256",
    }:
        raise _migration_provenance_error(
            "the exact canonical v4 source extension is required"
        )
    encoded_source = migration_extension.get("source_report_json")
    source_digest = migration_extension.get("source_sha256")
    if (
        migration_extension.get("encoding") != "atl-canonical-json-v1"
        or not isinstance(encoded_source, str)
        or not isinstance(source_digest, str)
    ):
        raise _migration_provenance_error("the canonical v4 source is invalid")
    try:
        source = parse_canonical_json(encoded_source.encode("utf-8"))
    except ValueError as exc:
        raise _migration_provenance_error(
            "the preserved v4 source is not canonical JSON"
        ) from exc
    if (
        not isinstance(source, dict)
        or source.get("schema_version") != "4.0.0"
        or canonical_json_bytes(source).decode("utf-8") != encoded_source
        or not secrets.compare_digest(
            hashlib.sha256(encoded_source.encode("utf-8")).hexdigest(),
            source_digest,
        )
    ):
        raise _migration_provenance_error(
            "the preserved v4 source binding does not match"
        )
    validate_report(source)
    migration_history = data["provenance"]["migration_history"]
    if not migration_history:
        raise _migration_provenance_error(
            "the report-v4-to-v5 migration record is required"
        )
    declared_version = migration_history[-1]["implementation"]["version"]
    expected = report_v5_from_v4_shape(
        source,
        add_v4_to_v5_migration=True,
        migration_implementation_version=declared_version,
    )
    if data != expected:
        raise _migration_provenance_error(
            "the v5 report is not the deterministic migration of its v4 source"
        )
    validate_report_identities(data)


def _validate_v6_direct_evidence(data: dict[str, Any]) -> None:
    adapter = data["extensions"].get("org.androidtrustlab.adapter")
    if not isinstance(adapter, dict) or not isinstance(adapter.get("captures"), list):
        raise SchemaValidationError(
            "direct report root and Magisk evidence requires adapter provenance"
        )
    captures = {
        capture["name"]: capture
        for capture in adapter["captures"]
        if isinstance(capture, dict)
        and isinstance(capture.get("name"), str)
        and isinstance(capture.get("source_ref"), str)
    }

    def validate_refs(
        evidence: dict[str, Any], allowed_names: frozenset[str], label: str
    ) -> None:
        refs = evidence["evidence_refs"]
        if evidence["status"] in {"observed", "observed_absent"}:
            allowed_refs = {
                captures[name]["source_ref"]
                for name in allowed_names
                if name in captures
                and captures[name].get("status") in {"observed", "empty"}
            }
            if len(refs) != 1 or refs[0] not in allowed_refs:
                raise SchemaValidationError(
                    f"report {label} does not bind its semantic adapter capture"
                )
        elif refs:
            raise SchemaValidationError(
                f"unavailable report {label} must not claim source references"
            )

    root = data["root_state"]
    magisk = data["magisk_state"]
    observer = data["observer"]["observer_type"]
    if root["source_observer"] != observer or magisk["source_observer"] != observer:
        raise SchemaValidationError(
            "report root and Magisk source observers must match the report observer"
        )
    validate_refs(
        root["observer_effective_uid_is_root"],
        frozenset({"root_probe", "identity", "id"}),
        "observer effective UID evidence",
    )
    for field, label in (
        ("root_shell_available", "root-shell evidence"),
        ("su_invocation_tested", "su invocation-test evidence"),
        ("su_invocation_result", "su invocation-result evidence"),
        ("root_management_artifact_observed", "root-management evidence"),
    ):
        validate_refs(root[field], frozenset({"root_probe"}), label)
    validate_refs(
        root["su_binary_observed"],
        frozenset({"root_probe", "su_paths"}),
        "su binary evidence",
    )
    su_tested = root["su_invocation_tested"]
    su_result = root["su_invocation_result"]
    invocation_was_tested = (
        su_tested["status"] == "observed" and su_tested["value"] is True
    )
    result_was_observed = su_result["status"] == "observed"
    if invocation_was_tested != result_was_observed:
        raise SchemaValidationError(
            "report su invocation tested/result evidence is contradictory"
        )
    for field in (
        "binary_visibility",
        "zygisk_visibility",
        "version_name",
        "version_code",
        "module_context",
    ):
        validate_refs(
            magisk[field],
            frozenset({"magisk"}),
            f"Magisk {field.replace('_', ' ')} evidence",
        )
    for field in ("daemon_visibility", "process_visibility"):
        validate_refs(
            magisk[field],
            frozenset({"processes", "ps_selected"}),
            f"Magisk {field.replace('_', ' ')} evidence",
        )
    validate_refs(
        magisk["command_status"],
        frozenset({"magisk"}),
        "command status",
    )
    relevant_names = {"properties", "getprop_selected", "boot_state"}
    relevant = [captures[name] for name in relevant_names if name in captures]
    observed = [
        capture
        for capture in relevant
        if capture.get("status") in {"observed", "empty"}
    ]
    failures = [
        capture
        for capture in relevant
        if capture.get("status")
        in {"inaccessible", "command_error", "timeout", "error"}
    ]
    inferred = adapter.get("input_kind") == "legacy_sectioned_text" or any(
        str(capture["source_ref"]).startswith("legacy-sections/")
        for capture in relevant
    )
    source_quality = (
        "structured_capture"
        if observed and not inferred
        else "legacy_inferred"
        if observed
        else "unavailable"
    )
    boot_fields = (
        "flash_locked",
        "verified_boot_state",
        "vbmeta_device_state",
        "verity_mode",
    )
    signal_count = sum(
        data["verified_boot"][field]["status"] == "observed" for field in boot_fields
    )
    command_success = (
        "complete"
        if observed and not failures and signal_count == len(boot_fields)
        else "partial"
        if observed and signal_count
        else "failed"
        if failures
        else "not_collected"
    )
    observer_capability = data["observer"]["privilege_level"]
    limitations = ["hardware_attestation_not_collected"]
    if data["target"]["target_type"] == "avd":
        limitations.append("virtual_target_not_hardware_backed")
    if inferred:
        limitations.append("legacy_capture_status_inferred")
    if observer_capability in {"app_sandbox", "unspecified"}:
        limitations.append("observer_capability_limited")
    level = (
        "unassessed"
        if signal_count == 0
        else "medium"
        if source_quality == "structured_capture"
        and command_success == "complete"
        and observer_capability in {"shell", "root"}
        else "low"
    )
    expected_confidence = {
        "level": level,
        "source_quality": source_quality,
        "command_success": command_success,
        "observer_capability": observer_capability,
        "corroborating_signal_count": signal_count,
        "target_limitations": sorted(limitations),
        "evidence_refs": sorted({str(capture["source_ref"]) for capture in observed}),
    }
    if data["verified_boot"]["confidence"] != expected_confidence:
        raise SchemaValidationError(
            "report confidence does not match its evidence and provenance factors"
        )


def _validate_v6_raw_provenance(
    data: dict[str, Any], raw_artifacts: list[dict[str, Any]]
) -> None:
    extension = data["extensions"].get("org.androidtrustlab.collection")
    manifest_digest: str | None = None
    if extension is not None:
        if len(raw_artifacts) != 1:
            raise SchemaValidationError(
                "report collection provenance must bind its unique observed raw_report"
            )
        if not isinstance(extension, dict) or set(extension) != {
            "canonicalization",
            "canonical_manifest_sha256",
            "portable_binding",
        }:
            raise SchemaValidationError(
                "report portable collection binding has an invalid shape"
            )
        manifest_digest = extension["canonical_manifest_sha256"]
        binding = extension["portable_binding"]
        if (
            extension["canonicalization"] != "atl-canonical-json-v1"
            or not isinstance(manifest_digest, str)
            or re.fullmatch(r"[a-f0-9]{64}", manifest_digest) is None
            or not isinstance(binding, dict)
            or set(binding)
            != {
                "artifact_results",
                "collection_id",
                "collection_errors",
                "completion_status",
                "raw_artifact_sha256",
                "raw_artifact_status",
                "redaction_state",
            }
            or binding["collection_id"] != raw_artifacts[0]["collection_id"]
            or binding["raw_artifact_sha256"] != raw_artifacts[0]["sha256"]
            or binding["raw_artifact_status"] != raw_artifacts[0]["status"]
            or binding["redaction_state"] != raw_artifacts[0]["redaction_state"]
            or binding["completion_status"] not in {"complete", "partial", "failed"}
        ):
            raise SchemaValidationError(
                "report portable collection binding does not match its raw artifact"
            )
        if binding["artifact_results"] != data["provenance"]["command_results"]:
            raise SchemaValidationError(
                "report command results do not match the portable collection binding"
            )
        if not set(binding["collection_errors"]) <= set(
            data["limitations"]["collection_errors"]
        ):
            raise SchemaValidationError(
                "report limitations do not retain portable collection limitations"
            )
    expected_event_id = collection_event_identity(
        collection_id=raw_artifacts[0]["collection_id"],
        timestamp=data["collection_timestamp"],
        experiment_id=data["experiment_id"],
        target_type=data["target"]["target_type"],
        observer_type=data["observer"]["observer_type"],
        collection_method=data["observer"]["collection_method"],
        collection_manifest_sha256=manifest_digest,
    )
    if not secrets.compare_digest(data["collection_event_id"], expected_event_id):
        raise _migration_provenance_error(
            "the raw v6 collection event identity does not match its provenance"
        )


def _validate_v6_report_semantics(data: object) -> None:
    """Validate v6 direct evidence or its exact deterministic v5 migration."""

    if not isinstance(data, dict):
        return
    _validate_v4_mount_semantics(data["mounts"])
    raw_artifacts = _validate_v3_raw_artifacts(data)
    source_version = data["provenance"]["source_schema_version"]
    migration_extension = data["extensions"].get("org.androidtrustlab.migration-v6")
    if source_version == "raw":
        if migration_extension is not None or any(
            key.startswith("org.androidtrustlab.migration")
            for key in data["extensions"]
        ):
            raise _migration_provenance_error(
                "raw v6 reports must not claim migration provenance"
            )
        _validate_v5_security_semantics(data)
        _validate_v6_direct_evidence(data)
        if data["provenance"]["migration_history"]:
            raise _migration_provenance_error(
                "raw v6 reports must not claim migration history"
            )
        _validate_v6_raw_provenance(data, raw_artifacts)
        validate_report_identities(data)
        return
    if source_version != "5.0.0":
        raise _migration_provenance_error("v6 migrations require one exact v5 source")
    if not isinstance(migration_extension, dict) or set(migration_extension) != {
        "encoding",
        "source_report_json",
        "source_sha256",
    }:
        raise _migration_provenance_error(
            "the exact canonical v5 source extension is required"
        )
    encoded_source = migration_extension.get("source_report_json")
    source_digest = migration_extension.get("source_sha256")
    if (
        migration_extension.get("encoding") != "atl-canonical-json-v1"
        or not isinstance(encoded_source, str)
        or not isinstance(source_digest, str)
    ):
        raise _migration_provenance_error("the canonical v5 source is invalid")
    try:
        source = parse_canonical_json(encoded_source.encode("utf-8"))
    except ValueError as exc:
        raise _migration_provenance_error(
            "the preserved v5 source is not canonical JSON"
        ) from exc
    if (
        not isinstance(source, dict)
        or source.get("schema_version") != "5.0.0"
        or canonical_json_bytes(source).decode("utf-8") != encoded_source
        or not secrets.compare_digest(
            hashlib.sha256(encoded_source.encode("utf-8")).hexdigest(),
            source_digest,
        )
    ):
        raise _migration_provenance_error(
            "the preserved v5 source binding does not match"
        )
    validate_report(source)
    history = data["provenance"]["migration_history"]
    if not history:
        raise _migration_provenance_error(
            "the report-v5-to-v6 migration record is required"
        )
    declared_version = history[-1]["implementation"]["version"]
    expected = report_v6_from_v5_shape(
        source,
        add_v5_to_v6_migration=True,
        migration_implementation_version=declared_version,
    )
    if data != expected:
        raise _migration_provenance_error(
            "the v6 report is not the deterministic migration of its v5 source"
        )
    validate_report_identities(data)


def _mount_semantic_error(detail: str) -> SchemaValidationError:
    return SchemaValidationError(f"report mount validation failed: {detail}")


def _mount_attempt_is_usable(attempt: dict[str, Any]) -> bool:
    return (
        attempt["capture_status"] == "observed"
        and attempt["record_count"] > 0
        and attempt["parse_status"] in {"complete", "partial"}
    )


def _validate_mount_attempt(attempt: dict[str, Any]) -> None:
    allowed_formats = {
        "mountinfo": {"mountinfo"},
        "proc_mounts": {"proc_mounts"},
        # Historical generic MOUNT sections accepted common mount output,
        # /proc-shaped output, and a source-ordered mixture of the two.
        "mounts": {"mountinfo", "proc_mounts", "mount", "mixed"},
    }
    if attempt["format"] not in allowed_formats[attempt["name"]]:
        raise _mount_semantic_error(
            "mount source attempt name does not match its format"
        )
    if attempt["capture_status"] == "observed":
        parse_status = attempt["parse_status"]
        if parse_status not in {
            "complete",
            "partial",
            "malformed",
            "empty",
        }:
            raise _mount_semantic_error(
                "observed mount attempts must carry a parser outcome"
            )
        if (attempt["record_count"] > 0) != (parse_status in {"complete", "partial"}):
            raise _mount_semantic_error(
                "mount attempt record count does not match parser usability"
            )
        if parse_status == "complete" and attempt["malformed_line_count"] != 0:
            raise _mount_semantic_error(
                "complete mount attempts cannot claim malformed lines"
            )
        return
    expected_status = "empty" if attempt["capture_status"] == "empty" else "not_parsed"
    if (
        attempt["record_count"] != 0
        or attempt["malformed_line_count"] != 0
        or attempt["warnings"]
        or attempt["parse_status"] != expected_status
    ):
        raise _mount_semantic_error(
            "unobserved mount attempts cannot claim parsed records"
        )


def _validate_v4_mount_observation(
    records: list[dict[str, Any]], observation: dict[str, Any]
) -> dict[str, Any] | None:
    attempts = observation["attempts"]
    priority = {"mountinfo": 0, "proc_mounts": 1, "mounts": 2}
    attempt_names = [attempt["name"] for attempt in attempts]
    if len(attempt_names) != len(set(attempt_names)) or attempt_names != sorted(
        attempt_names, key=priority.__getitem__
    ):
        raise _mount_semantic_error(
            "mount source attempts must be unique and fixed-priority ordered"
        )
    for attempt in attempts:
        _validate_mount_attempt(attempt)
    selected_source = observation["selected_source"]
    first_usable_source = next(
        (attempt["name"] for attempt in attempts if _mount_attempt_is_usable(attempt)),
        None,
    )
    if selected_source != first_usable_source:
        raise _mount_semantic_error(
            "selected source must be the first usable fixed-priority attempt"
        )
    selected_attempt = next(
        (attempt for attempt in attempts if attempt["name"] == selected_source),
        None,
    )
    if records:
        if (
            selected_attempt is None
            or selected_attempt["capture_status"] != "observed"
            or selected_attempt["record_count"] != len(records)
            or observation["selected_format"] != selected_attempt["format"]
            or observation["parse_status"] != selected_attempt["parse_status"]
            or observation["parse_status"] not in {"complete", "partial"}
        ):
            raise _mount_semantic_error(
                "selected source must bind the complete selected record set"
            )
        record_formats = {record["format"] for record in records}
        selected_format = observation["selected_format"]
        if selected_format == "mixed":
            formats_match = selected_source == "mounts" and len(record_formats) > 1
        else:
            formats_match = record_formats == {selected_format}
        if not formats_match:
            raise _mount_semantic_error(
                "selected mount records do not match their source format"
            )
        if observation["parse_status"] == "complete" and any(
            record["parse_status"] != "parsed" for record in records
        ):
            raise _mount_semantic_error(
                "complete mount attempts cannot contain partial records"
            )
    elif (
        any(
            value is not None
            for value in (selected_source, observation["selected_format"])
        )
        or observation["parse_status"] != "not_parsed"
    ):
        raise _mount_semantic_error("an empty mount set cannot claim a selected source")
    return selected_attempt


def _expected_system_resolution(
    records: list[dict[str, Any]], *, complete_mount_set: bool
) -> tuple[str, str | None, list[Any]]:
    system_indices = [
        record["record_index"]
        for record in records
        if record["mount_point"] == "/system"
    ]
    root_indices = [
        record["record_index"] for record in records if record["mount_point"] == "/"
    ]
    if len(system_indices) == 1:
        return "explicit_system", "/system", system_indices
    if len(system_indices) > 1:
        return "ambiguous", None, system_indices
    if complete_mount_set and len(root_indices) == 1:
        return "system_as_root", "/", root_indices
    if complete_mount_set and len(root_indices) > 1:
        return "ambiguous", None, root_indices
    return "unresolved", None, root_indices


def _validate_v4_system_resolution(
    records: list[dict[str, Any]],
    resolution: dict[str, Any],
    *,
    complete_mount_set: bool,
) -> None:
    expected_resolution = _expected_system_resolution(
        records,
        complete_mount_set=complete_mount_set,
    )
    observed_resolution = (
        resolution["state"],
        resolution["system_root"],
        resolution["record_indices"],
    )
    if observed_resolution != expected_resolution:
        raise _mount_semantic_error(
            "system resolution does not match exact /system and root records"
        )


def _validate_v4_dynamic_partitions(
    records: list[dict[str, Any]],
    dynamic: dict[str, Any],
    *,
    complete_mount_set: bool,
) -> None:
    expected_records = [
        record
        for record in records
        if str(record["source"]).startswith(("/dev/block/mapper/", "/dev/block/dm-"))
        or str(record["major_minor"]).startswith("253:")
    ]
    expected_state = (
        "detected"
        if expected_records
        else "not_detected"
        if complete_mount_set
        else "unknown"
    )
    if (
        dynamic["state"] != expected_state
        or dynamic["record_indices"]
        != [record["record_index"] for record in expected_records]
        or dynamic["sources"]
        != sorted({record["source"] for record in expected_records})
    ):
        raise _mount_semantic_error(
            "dynamic partition aggregate does not match mount records"
        )


def _validate_v4_apex_set(records: list[dict[str, Any]], apex: dict[str, Any]) -> None:
    apex_records = [
        record
        for record in records
        if record["mount_point"] == "/apex"
        or record["mount_point"].startswith("/apex/")
    ]
    packages = sorted(
        {
            record["mount_point"]
            .removeprefix("/apex/")
            .split("/", 1)[0]
            .split("@", 1)[0]
            for record in apex_records
            if record["mount_point"] != "/apex"
        }
    )
    accesses = [record["access"] for record in apex_records]
    expected = {
        "packages": packages,
        "record_indices": [record["record_index"] for record in apex_records],
        "mount_count": len(apex_records),
        "package_count": len(packages),
        "read_only_count": accesses.count("read_only"),
        "writable_count": accesses.count("writable"),
        "unknown_access_count": accesses.count("unknown"),
        "overlay_count": sum(
            record["overlay_state"] == "detected" for record in apex_records
        ),
        "bind_count": sum(
            record["bind_state"] == "detected" for record in apex_records
        ),
    }
    if apex != expected:
        raise _mount_semantic_error("APEX aggregate does not match mount records")


def _validate_v4_mount_semantics(mounts: dict[str, Any]) -> None:
    records = mounts["records"]
    observation = mounts["observation"]
    if [record["record_index"] for record in records] != list(range(len(records))):
        raise _mount_semantic_error("record indices must be contiguous source order")
    expected_paths = sorted({record["evidence_path"] for record in records})
    if observation["evidence_paths"] != expected_paths:
        raise _mount_semantic_error(
            "observation evidence paths must match selected records"
        )
    selected_attempt = _validate_v4_mount_observation(records, observation)
    complete_mount_set = bool(
        selected_attempt and selected_attempt["parse_status"] == "complete"
    )
    _validate_v4_system_resolution(
        records,
        mounts["system_resolution"],
        complete_mount_set=complete_mount_set,
    )
    _validate_v4_dynamic_partitions(
        records,
        mounts["dynamic_partitions"],
        complete_mount_set=complete_mount_set,
    )
    _validate_v4_apex_set(records, mounts["apex_set"])


def validate_diff(data: object) -> None:
    version = data.get("schema_version") if isinstance(data, dict) else None
    resource_version = (
        version
        if isinstance(version, str)
        else current_write_version(SchemaFamily.DIFF)
    )
    if resource_version in {
        "2.0.0",
        "2.1.0",
        "2.2.0",
        "2.3.0",
        "2.4.0",
        "2.5.0",
        "2.6.0",
        "2.7.0",
    }:
        _validate_canonical_document(data, artifact_name="diff")
    validate_with_schema(
        data,
        schema_resource_name(SchemaFamily.DIFF, resource_version),
        artifact_name="diff",
        supported_versions=SUPPORTED_DIFF_SCHEMA_VERSIONS,
    )
    if resource_version in {
        "2.0.0",
        "2.1.0",
        "2.2.0",
        "2.3.0",
        "2.4.0",
        "2.5.0",
        "2.6.0",
        "2.7.0",
    }:
        _validate_v2_diff_semantics(data, schema_version=resource_version)
    validate_portable_diff(data)


def _validate_canonical_document(data: object, *, artifact_name: str) -> None:
    try:
        canonical_json_bytes(data)
    except CanonicalJSONError as exc:
        raise SchemaValidationError(
            f"{artifact_name} is outside the bounded canonical JSON model"
        ) from exc


def _validate_v2_diff_semantics(data: object, *, schema_version: str) -> None:
    if not isinstance(data, dict):
        return
    projection = {
        key: value
        for key, value in data.items()
        if key not in {"diff_id", "content_digest"}
    }
    try:
        expected_digest = framed_content_digest(
            family="diff",
            schema_version=schema_version,
            value=projection,
        )
    except CanonicalJSONError as exc:
        raise SchemaValidationError(
            "diff payload is outside the canonical identity model"
        ) from exc
    if not secrets.compare_digest(data["content_digest"], expected_digest):
        raise SchemaValidationError("diff content digest does not match its payload")
    if data["diff_id"] != f"atldiff-{expected_digest[:32]}":
        raise SchemaValidationError("diff ID does not bind its canonical content")
    for side in ("base", "compare"):
        provenance = data["provenance"][side]
        if provenance["common_report"] != data[f"{side}_report"]:
            raise SchemaValidationError(
                "diff provenance does not bind the exact common report identities"
            )
        original_version = provenance["original_schema_version"]
        original_digest = provenance["original_content_digest"]
        migrations = provenance["applied_migrations"]
        content_addressed_versions = {
            "2.0.0": {"3.0.0"},
            "2.1.0": {"3.0.0", "4.0.0"},
            "2.2.0": {"3.0.0", "4.0.0", "5.0.0"},
            "2.3.0": {"3.0.0", "4.0.0", "5.0.0", "6.0.0"},
            "2.4.0": {"3.0.0", "4.0.0", "5.0.0", "6.0.0"},
            "2.5.0": {"3.0.0", "4.0.0", "5.0.0", "6.0.0"},
            "2.6.0": {"3.0.0", "4.0.0", "5.0.0", "6.0.0"},
            "2.7.0": {"3.0.0", "4.0.0", "5.0.0", "6.0.0"},
        }[schema_version]
        if (original_version in content_addressed_versions) != (
            original_digest is not None
        ):
            raise SchemaValidationError(
                "diff provenance must distinguish legacy and content identities"
            )
        expected_steps_by_version = {
            "2.0.0": {
                "1.0.0": [
                    ("report-v1-to-v2", "1.0.0", "2.0.0"),
                    ("report-v2-to-v3", "2.0.0", "3.0.0"),
                ],
                "2.0.0": [("report-v2-to-v3", "2.0.0", "3.0.0")],
                "3.0.0": [],
            },
            "2.1.0": {
                "1.0.0": [
                    ("report-v1-to-v2", "1.0.0", "2.0.0"),
                    ("report-v2-to-v3", "2.0.0", "3.0.0"),
                    ("report-v3-to-v4", "3.0.0", "4.0.0"),
                ],
                "2.0.0": [
                    ("report-v2-to-v3", "2.0.0", "3.0.0"),
                    ("report-v3-to-v4", "3.0.0", "4.0.0"),
                ],
                "3.0.0": [("report-v3-to-v4", "3.0.0", "4.0.0")],
                "4.0.0": [],
            },
            "2.2.0": {
                "1.0.0": [
                    ("report-v1-to-v2", "1.0.0", "2.0.0"),
                    ("report-v2-to-v3", "2.0.0", "3.0.0"),
                    ("report-v3-to-v4", "3.0.0", "4.0.0"),
                    ("report-v4-to-v5", "4.0.0", "5.0.0"),
                ],
                "2.0.0": [
                    ("report-v2-to-v3", "2.0.0", "3.0.0"),
                    ("report-v3-to-v4", "3.0.0", "4.0.0"),
                    ("report-v4-to-v5", "4.0.0", "5.0.0"),
                ],
                "3.0.0": [
                    ("report-v3-to-v4", "3.0.0", "4.0.0"),
                    ("report-v4-to-v5", "4.0.0", "5.0.0"),
                ],
                "4.0.0": [("report-v4-to-v5", "4.0.0", "5.0.0")],
                "5.0.0": [],
            },
            "2.3.0": {
                "1.0.0": [
                    ("report-v1-to-v2", "1.0.0", "2.0.0"),
                    ("report-v2-to-v3", "2.0.0", "3.0.0"),
                    ("report-v3-to-v4", "3.0.0", "4.0.0"),
                    ("report-v4-to-v5", "4.0.0", "5.0.0"),
                    ("report-v5-to-v6", "5.0.0", "6.0.0"),
                ],
                "2.0.0": [
                    ("report-v2-to-v3", "2.0.0", "3.0.0"),
                    ("report-v3-to-v4", "3.0.0", "4.0.0"),
                    ("report-v4-to-v5", "4.0.0", "5.0.0"),
                    ("report-v5-to-v6", "5.0.0", "6.0.0"),
                ],
                "3.0.0": [
                    ("report-v3-to-v4", "3.0.0", "4.0.0"),
                    ("report-v4-to-v5", "4.0.0", "5.0.0"),
                    ("report-v5-to-v6", "5.0.0", "6.0.0"),
                ],
                "4.0.0": [
                    ("report-v4-to-v5", "4.0.0", "5.0.0"),
                    ("report-v5-to-v6", "5.0.0", "6.0.0"),
                ],
                "5.0.0": [("report-v5-to-v6", "5.0.0", "6.0.0")],
                "6.0.0": [],
            },
            "2.4.0": {
                version: [
                    (
                        step.migration_id,
                        step.source_schema_version,
                        step.target_schema_version,
                    )
                    for step in report_migration_path(version)
                ]
                for version in SUPPORTED_REPORT_SCHEMA_VERSIONS
            },
            "2.5.0": {
                version: [
                    (
                        step.migration_id,
                        step.source_schema_version,
                        step.target_schema_version,
                    )
                    for step in report_migration_path(version)
                ]
                for version in SUPPORTED_REPORT_SCHEMA_VERSIONS
            },
            "2.6.0": {
                version: [
                    (
                        step.migration_id,
                        step.source_schema_version,
                        step.target_schema_version,
                    )
                    for step in report_migration_path(version)
                ]
                for version in SUPPORTED_REPORT_SCHEMA_VERSIONS
            },
            "2.7.0": {
                version: [
                    (
                        step.migration_id,
                        step.source_schema_version,
                        step.target_schema_version,
                    )
                    for step in report_migration_path(version)
                ]
                for version in SUPPORTED_REPORT_SCHEMA_VERSIONS
            },
        }
        expected_steps = expected_steps_by_version[schema_version].get(original_version)
        if expected_steps is None or len(migrations) != len(expected_steps):
            raise SchemaValidationError(
                "diff provenance migration chain does not match the source version"
            )
        observed_steps = [
            (
                migration["migration_id"],
                migration["source_schema_version"],
                migration["target_schema_version"],
            )
            for migration in migrations
        ]
        if observed_steps != expected_steps:
            raise SchemaValidationError(
                "diff provenance does not use the registered migration chain"
            )
        common_report = provenance["common_report"]
        current_report_version = {
            "2.0.0": "3.0.0",
            "2.1.0": "4.0.0",
            "2.2.0": "5.0.0",
            "2.3.0": "6.0.0",
            "2.4.0": "6.0.0",
            "2.5.0": "6.0.0",
            "2.6.0": "6.0.0",
            "2.7.0": "6.0.0",
        }[schema_version]
        if original_version == current_report_version and (
            provenance["original_report_id"] != common_report["report_id"]
            or not secrets.compare_digest(
                original_digest, common_report["content_digest"]
            )
        ):
            raise SchemaValidationError(
                "diff provenance does not bind the original current report identity"
            )
    if schema_version in {"2.4.0", "2.5.0", "2.6.0", "2.7.0"}:
        _validate_diff_compatibility(data)
    if schema_version in {"2.5.0", "2.6.0", "2.7.0"}:
        _validate_diff_comparison(data)


def _validate_diff_compatibility(data: dict[str, Any]) -> None:
    compatibility = data["compatibility"]
    input_versions = compatibility["input_schema_versions"]
    migrations = compatibility["migrations"]
    warnings = compatibility["warnings"]
    if (
        compatibility["canonical_comparison_schema_version"]
        != (data["provenance"]["common_report_schema_version"])
    ):
        raise SchemaValidationError(
            "diff compatibility does not bind the canonical comparison schema"
        )
    expected_warnings: list[str] = []
    for side in ("base", "compare"):
        provenance = data["provenance"][side]
        source_version = provenance["original_schema_version"]
        if input_versions[side] != source_version:
            raise SchemaValidationError(
                "diff compatibility input version does not bind provenance"
            )
        expected_migrations = [
            step.to_compatibility_dict()
            for step in report_migration_path(source_version)
        ]
        if migrations[side] != expected_migrations:
            raise SchemaValidationError(
                "diff compatibility does not use the registered migration path"
            )
        if expected_migrations:
            expected_warnings.append(f"{side}_input_migrated_temporarily_in_memory")
    if warnings != expected_warnings:
        raise SchemaValidationError("diff compatibility warnings are not canonical")


def _validate_diff_comparison(data: dict[str, Any]) -> None:
    comparison = data["comparison"]
    try:
        expected = classify_comparison_contexts(
            comparison["context"]["base"],
            comparison["context"]["compare"],
            allow_mixed=comparison["acknowledgement"] == "allow_mixed",
        )
    except ComparisonAcknowledgementError as exc:
        raise SchemaValidationError(
            "diff mixed comparison acknowledgement is invalid"
        ) from exc
    if comparison != expected:
        raise SchemaValidationError(
            "diff comparison axis and reasons are not canonical"
        )


def _collection_manifest_semantic_error(detail: str) -> SchemaValidationError:
    return SchemaValidationError(
        f"collection manifest semantic validation failed: {detail}"
    )


def _manifest_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _manifest_strings(item)]
    if isinstance(value, list):
        return [text for item in value for text in _manifest_strings(item)]
    return []


def _validate_manifest_portability(data: dict[str, Any]) -> None:
    strings = _manifest_strings(data)
    path_patterns = (
        re.compile(r"(?:^|[\s('\"\[=:])/(?:$|[A-Za-z0-9._~-])"),
        re.compile(r"(?:^|[\s('\"\[=])//[^/\s]+/"),
        re.compile(r"(?:^|[\s('\"\[=:])[A-Za-z]:[\\/]"),
        re.compile(r"(?:^|[\s('\"\[=:])\\\\(?:[^\\/\s]+[\\/]|[?.]\\)"),
        re.compile(r"(?:^|[\s('\"\[=:])\\[^\\/\s]+\\"),
        re.compile(r"(?i)(?:^|[\s('\"\[=:])file:(?://)?/"),
        re.compile(r"(?:^|[\s('\"\[=:])~(?:[A-Za-z0-9._-]+)?/"),
    )
    if any(pattern.search(value) for value in strings for pattern in path_patterns):
        raise _collection_manifest_semantic_error(
            "portable manifests must not contain absolute paths"
        )

    free_text = [
        *data["warnings"],
        *(
            artifact["detail"]
            for artifact in data["artifacts"]
            if artifact["detail"] is not None
        ),
    ]
    labeled_sensitive_patterns = (
        re.compile(
            r"(?i)\b(?:device\s+)?serial(?:\s+number)?\b"
            r"(?:\s*(?:[:=]|\bis\b)\s*|\s+)"
            r"(?!is\b|was\b|has\b|not\b|removed\b|redacted\b|withheld\b|"
            r"unknown\b|unavailable\b)\S+"
        ),
        re.compile(
            r"(?i)\badb(?:\.exe)?\s+-s\s+"
            r"(?!redacted\b|withheld\b|unknown\b|unavailable\b)\S+"
        ),
        re.compile(
            r"(?i)\badb\s+target\b(?:\s*[:=]\s*|\s+)"
            r"(?!unknown\b|redacted\b|unavailable\b)\S+"
        ),
        re.compile(
            r"(?i)\b(?:authorization\s*:\s*)?bearer\s+"
            r"(?!redacted\b|withheld\b|unknown\b|unavailable\b)\S+"
        ),
        re.compile(
            r"(?i)\b(?:password|passwd|token|secret|api[_ -]?key|"
            r"access[_ -]?token|refresh[_ -]?token)\b\s*(?:[:=]|\bis\b)\s*"
            r"(?!removed\b|redacted\b|withheld\b|unknown\b|unavailable\b)\S+"
        ),
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    )
    identifier_patterns = (
        re.compile(r"(?i)\bemulator-[0-9]{4,}\b"),
        re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{12,20}(?![0-9A-Fa-f])"),
        re.compile(r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b"),
        re.compile(
            r"\b(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
            r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}\b"
        ),
        re.compile(
            r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
        ),
        re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    )
    process_diagnostic_patterns = (
        re.compile(
            r"(?i)\b(?:pid|ppid|uid|cmdline|command[ _-]?line)\b"
            r"\s*(?:[:=]|\bis\b)?\s*"
            r"(?!redacted\b|withheld\b|unknown\b|unavailable\b)\S+"
        ),
        re.compile(
            r"(?i)\buser\s*[:=]\s*"
            r"(?!redacted\b|withheld\b|unknown\b|unavailable\b)\S+"
        ),
        re.compile(r"(?i)\bu[0-9]+_[ai][0-9]+\b"),
        re.compile(r"(?<![0-9])(?:[0-9]{4,})(?![0-9])"),
        re.compile(
            r"(?i)(?:^|\s)(?:init|adbd|zygote|zygote64|system_server|"
            r"magisk|magiskd)(?:\s|$)"
        ),
        re.compile(r"(?:^|\s)--[A-Za-z0-9][^\s]*"),
        re.compile(r"(?:^|\s)(?:\.{0,2}/|[A-Za-z0-9._-]+/)[^\s]+"),
    )
    if (
        any(
            pattern.search(value)
            for value in strings
            for pattern in labeled_sensitive_patterns
        )
        or any(
            pattern.search(value)
            for value in free_text
            for pattern in identifier_patterns
        )
        or any(
            pattern.search(value)
            for value in free_text
            for pattern in process_diagnostic_patterns
        )
    ):
        raise _collection_manifest_semantic_error(
            "portable manifests must not contain process identities, command lines, "
            "identifiers, or secrets"
        )
    if free_text:
        raise _collection_manifest_semantic_error(
            "portable diagnostics must use structured statuses; warnings must be "
            "empty and artifact details must be null"
        )


def _validate_manifest_artifacts(data: dict[str, Any]) -> None:
    artifacts = data["artifacts"]
    logical_names = [artifact["logical_name"] for artifact in artifacts]
    if len(logical_names) != len(set(logical_names)):
        raise _collection_manifest_semantic_error(
            "artifact logical names must be unique"
        )
    paths = [
        artifact["relative_path"]
        for artifact in artifacts
        if artifact["relative_path"] is not None
    ]
    if len(paths) != len(set(paths)):
        raise _collection_manifest_semantic_error("artifact paths must be unique")
    for path in paths:
        pure_path = PurePosixPath(path)
        if (
            pure_path.is_absolute()
            or path != pure_path.as_posix()
            or any(part in {"", ".", ".."} for part in pure_path.parts)
        ):
            raise _collection_manifest_semantic_error(
                "artifact paths must be normalized relative paths"
            )

    for artifact in artifacts:
        if artifact["status"] in {"observed", "observed_absent"} and artifact[
            "exit_code"
        ] not in {
            None,
            0,
        }:
            raise _collection_manifest_semantic_error(
                "successful artifact outcomes cannot record a failed exit code"
            )


def _validate_manifest_completion(data: dict[str, Any]) -> None:
    available = {"observed", "observed_absent"}
    statuses = {artifact["status"] for artifact in data["artifacts"]}
    completion = data["completion_status"]
    required_unsupported = (
        {"unsupported"}
        if data.get("collector", {}).get("name") in {"trustlab-adb", "trustlab-magisk"}
        else set()
    )
    failed_or_omitted = {
        "inaccessible",
        "not_collected",
        "command_error",
        *required_unsupported,
    }
    if completion == "complete" and statuses & failed_or_omitted:
        raise _collection_manifest_semantic_error(
            "complete collections cannot contain failed or omitted probes"
        )
    if completion == "partial" and not (
        statuses & available
        and statuses - available - ({"unsupported"} - required_unsupported)
    ):
        raise _collection_manifest_semantic_error(
            "partial collections require both usable and unavailable evidence"
        )
    if completion == "failed" and statuses & available:
        raise _collection_manifest_semantic_error(
            "failed collections cannot contain usable artifacts"
        )


def _validate_manifest_timestamps(data: dict[str, Any]) -> None:
    def order_key(value: str) -> tuple[int, int, Fraction]:
        match = RFC3339_DATE_TIME_RE.fullmatch(value)
        if match is None:  # Schema format validation runs before semantics.
            raise _collection_manifest_semantic_error("invalid collection timestamp")
        year, month, day = (int(part) for part in match.group("date").split("-"))
        days_before_year = (
            0
            if year == 0
            else (
                365 * year + (year + 3) // 4 - (year + 99) // 100 + (year + 399) // 400
            )
        )
        days_before_month = sum(
            _days_in_gregorian_month(year, prior_month)
            for prior_month in range(1, month)
        )
        day_index = days_before_year + days_before_month + day - 1
        offset_minutes = 0
        if match.group("offset_hour") is not None:
            offset_minutes = int(match.group("offset_hour")) * 60 + int(
                match.group("offset_minute")
            )
            if match.group("offset_sign") == "-":
                offset_minutes = -offset_minutes
        utc_minute = (
            day_index * 1_440
            + int(match.group("hour")) * 60
            + int(match.group("minute"))
            - offset_minutes
        )
        fraction_digits = match.group("fraction") or "0"
        return (
            utc_minute,
            int(match.group("second")),
            Fraction(int(fraction_digits), 10 ** len(fraction_digits)),
        )

    started = order_key(data["started_at"])
    ended = order_key(data["ended_at"])
    if ended < started:
        raise _collection_manifest_semantic_error(
            "collection end timestamp precedes its start"
        )


def _validate_collection_manifest_semantics(data: object) -> None:
    if not isinstance(data, dict):
        return
    _validate_manifest_portability(data)
    observer = data["observer"]
    expected_privileges = {
        "host": "host",
        "adb_shell": "shell",
        "unprivileged_app": "app_sandbox",
        "root_collector": "root",
    }
    if expected_privileges[observer["observer_type"]] != observer["privilege_level"]:
        raise _collection_manifest_semantic_error(
            "observer privilege does not match observer type"
        )
    collector_name = data["collector"]["name"]
    expected_observers = {
        "trustlab-host": "host",
        "trustlab-adb": "adb_shell",
        "trustlab-app": "unprivileged_app",
        "trustlab-magisk": "root_collector",
    }
    if (
        collector_name in expected_observers
        and observer["observer_type"] != expected_observers[collector_name]
    ):
        raise _collection_manifest_semantic_error(
            "collector identity does not match observer type"
        )
    expected_transports = {
        "trustlab-host": "local",
        "trustlab-adb": "adb",
        "trustlab-app": "app_api",
        "trustlab-magisk": "on_device",
        "trustlab-fixture": "fixture",
    }
    if data["environment"]["transport"] != expected_transports[collector_name]:
        raise _collection_manifest_semantic_error(
            "collector identity does not match environment transport"
        )
    expected_platforms = {
        "trustlab-host": {"linux", "macos", "windows", "unknown"},
        "trustlab-adb": {"android"},
        "trustlab-app": {"android"},
        "trustlab-magisk": {"android"},
    }
    if (
        collector_name in expected_platforms
        and data["environment"]["platform"] not in expected_platforms[collector_name]
    ):
        raise _collection_manifest_semantic_error(
            "collector identity does not match environment platform"
        )
    _validate_manifest_artifacts(data)
    _validate_manifest_completion(data)
    _validate_manifest_timestamps(data)
    validate_portable_collection_manifest(data)


def validate_collection_manifest(data: object) -> None:
    """Validate a portable collection manifest and its semantic invariants."""

    version = data.get("schema_version") if isinstance(data, dict) else None
    resource_version = (
        version
        if isinstance(version, str)
        else current_write_version(SchemaFamily.COLLECTION_MANIFEST)
    )
    validate_with_schema(
        data,
        schema_resource_name(SchemaFamily.COLLECTION_MANIFEST, resource_version),
        artifact_name="collection manifest",
        supported_versions=SUPPORTED_COLLECTION_MANIFEST_SCHEMA_VERSIONS,
    )
    _validate_collection_manifest_semantics(data)


def _dataset_semantic_error(detail: str) -> SchemaValidationError:
    return SchemaValidationError(f"dataset contract validation failed: {detail}")


def _validate_dataset_relative_path(path: str) -> None:
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise _dataset_semantic_error("artifact path contains control characters")
    if "\\" in path or ":" in path:
        raise _dataset_semantic_error("artifact paths must be portable relative paths")
    pure_path = PurePosixPath(path)
    if (
        pure_path.is_absolute()
        or path != pure_path.as_posix()
        or any(part in {"", ".", ".."} for part in pure_path.parts)
    ):
        raise _dataset_semantic_error(
            "artifact paths must be normalized relative paths"
        )


def _validate_unique_strings(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise _dataset_semantic_error(f"{label} must be unique")


def _validate_dataset_artifact_contract(
    data: dict[str, Any], *, require_current_profile: bool
) -> dict[str, Any]:
    artifacts = data["artifacts"]
    artifact_ids = [artifact["artifact_id"] for artifact in artifacts]
    artifact_paths = [artifact["relative_path"] for artifact in artifacts]
    _validate_unique_strings(artifact_ids, "artifact IDs")
    _validate_unique_strings(artifact_paths, "artifact paths")
    for path in artifact_paths:
        _validate_dataset_relative_path(path)

    artifacts_by_id = {artifact["artifact_id"]: artifact for artifact in artifacts}
    source_id = data["declarative_source_artifact_id"]
    source = artifacts_by_id.get(source_id)
    if source is None or source["role"] != "declarative_source":
        raise _dataset_semantic_error(
            "declarative source reference must resolve to its artifact"
        )
    if source["relative_path"] != "source.json":
        raise _dataset_semantic_error("declarative source path must be source.json")

    expected_contracts = {
        "declarative_source": (
            "dataset_source",
            "application/json",
            {"author"},
        ),
        "raw_artifact": (
            "trustlab_raw_text",
            "text/plain",
            {"author", "collector"},
        ),
        "collection_manifest": (
            "collection_manifest",
            "application/json",
            {"author", "collector"},
        ),
        "normalized_report": ("report", "application/json", {"generator"}),
        "derived_diff": ("diff", "application/json", {"generator"}),
    }
    current_versions = {
        "declarative_source": "1.0.0",
        "raw_artifact": "1.0.0",
        "collection_manifest": current_write_version(SchemaFamily.COLLECTION_MANIFEST),
        "normalized_report": current_write_version(SchemaFamily.REPORT),
        "derived_diff": current_write_version(SchemaFamily.DIFF),
    }
    schema_profile = data["artifact_schema_versions"]
    readable_versions = {
        "declarative_source": frozenset({"1.0.0"}),
        "raw_artifact": frozenset({"1.0.0"}),
        "collection_manifest": SUPPORTED_COLLECTION_MANIFEST_SCHEMA_VERSIONS,
        "normalized_report": SUPPORTED_REPORT_SCHEMA_VERSIONS,
        "derived_diff": SUPPORTED_DIFF_SCHEMA_VERSIONS,
    }
    if require_current_profile and schema_profile != current_versions:
        raise _dataset_semantic_error(
            "dataset source must use the current artifact schema profile"
        )
    if set(schema_profile) != set(readable_versions) or any(
        schema_profile[role] not in versions
        for role, versions in readable_versions.items()
    ):
        raise _dataset_semantic_error(
            "dataset artifact schema profile contains unsupported versions"
        )
    if (
        data["creation_tooling"]["name"] != "trustlab-dataset-generator"
        or data["creation_tooling"]["command"] != "python tools/generate_report.py"
    ):
        raise _dataset_semantic_error(
            "dataset creation tooling must identify the canonical generator"
        )
    for artifact in artifacts:
        family, media_type, producer_kinds = expected_contracts[artifact["role"]]
        if (
            artifact["schema_family"] != family
            or artifact["media_type"] != media_type
            or artifact["producer"]["kind"] not in producer_kinds
            or artifact["schema_version"] != schema_profile[artifact["role"]]
        ):
            raise _dataset_semantic_error(
                "artifact role, format, producer, and schema profile must agree"
            )
        if artifact["role"] in {"normalized_report", "derived_diff"} and (
            artifact["producer"]["name"] != "trustlab"
            or artifact["producer"]["version"] != data["creation_tooling"]["version"]
        ):
            raise _dataset_semantic_error(
                "generated artifact producers must match creation tooling"
            )

        role = artifact["role"]
        path = PurePosixPath(artifact["relative_path"])
        expected_prefix = "derived/diffs" if role == "derived_diff" else "samples"
        if role == "declarative_source":
            continue
        if (
            path.parent == PurePosixPath(".")
            or not path.is_relative_to(expected_prefix)
            or (role == "raw_artifact" and path.suffix != ".txt")
            or (role != "raw_artifact" and path.suffix != ".json")
            or path.name == "README.md"
        ):
            raise _dataset_semantic_error(
                "artifact roles require reserved dataset paths and extensions"
            )
    return artifacts_by_id


def _validate_sample_collection_reference(
    sample: dict[str, Any], artifacts_by_id: dict[str, Any]
) -> str | None:
    relationship = sample["collection_manifest"]
    collection_id = relationship["artifact_id"]
    reason = relationship["reason"]
    if relationship["status"] == "observed":
        if (
            not isinstance(collection_id, str)
            or reason is not None
            or collection_id not in artifacts_by_id
            or artifacts_by_id[collection_id]["role"] != "collection_manifest"
        ):
            raise _dataset_semantic_error(
                "observed collection references must resolve without a reason"
            )
        return collection_id
    if collection_id is not None or not isinstance(reason, str) or not reason:
        raise _dataset_semantic_error(
            "not-collected relationships require a reason and no artifact"
        )
    return None


def _validate_sample_origin(sample: dict[str, Any]) -> None:
    origin = sample["origin_classification"]
    target = sample["target_type"]
    collected = sample["collection_manifest"]["status"] == "observed"
    if origin == "synthetic":
        if target == "physical" or "captured" in sample["collection_method"]:
            raise _dataset_semantic_error(
                "synthetic samples cannot claim physical or captured evidence"
            )
    elif origin == "avd_captured":
        if target != "avd" or not collected:
            raise _dataset_semantic_error(
                "AVD captures require an AVD target and collection manifest"
            )
    elif target != "physical" or not collected:
        raise _dataset_semantic_error(
            "physical captures require a physical target and collection manifest"
        )


def _validate_dataset_authorization(data: dict[str, Any], origins: set[str]) -> None:
    authorization = data["authorization"]
    classification = authorization["classification"]
    if "physical_captured" in origins:
        allowed_physical_authorizations = (
            {"mixed_authorized"}
            if len(origins) > 1
            else {
                "authorized_physical_collection",
                "consented_physical_collection",
            }
        )
        if (
            not authorization["physical_data_disclosed"]
            or classification not in allowed_physical_authorizations
            or data["redaction"]["status"] not in {"applied", "verified"}
        ):
            raise _dataset_semantic_error(
                "physical data requires disclosure, authorization, and redaction"
            )
    elif authorization["physical_data_disclosed"]:
        raise _dataset_semantic_error(
            "physical-data disclosure cannot be set without physical samples"
        )
    if origins == {"synthetic"} and classification != "project_authored_synthetic":
        raise _dataset_semantic_error(
            "synthetic-only datasets require project-authored authorization"
        )
    if origins == {"avd_captured"} and classification != "authorized_avd_collection":
        raise _dataset_semantic_error(
            "AVD-only captures require AVD collection authorization"
        )
    if len(origins) > 1 and classification != "mixed_authorized":
        raise _dataset_semantic_error(
            "mixed-origin datasets require mixed authorization"
        )


def _validate_dataset_sample_contract(
    data: dict[str, Any], artifacts_by_id: dict[str, Any]
) -> set[str]:
    samples = data["samples"]
    _validate_unique_strings([sample["sample_id"] for sample in samples], "sample IDs")
    _validate_unique_strings(
        [sample["raw_artifact_id"] for sample in samples],
        "sample raw artifact references",
    )
    _validate_unique_strings(
        [sample["normalized_report_artifact_id"] for sample in samples],
        "sample report artifact references",
    )
    _validate_unique_strings(
        [
            sample["collection_manifest"]["artifact_id"]
            for sample in samples
            if sample["collection_manifest"]["status"] == "observed"
        ],
        "observed collection artifact references",
    )
    origins = {sample["origin_classification"] for sample in samples}
    if origins != set(data["origin_classifications"]):
        raise _dataset_semantic_error(
            "declared origin classifications must exactly match sample origins"
        )

    referenced = {data["declarative_source_artifact_id"]}
    for sample in samples:
        raw_id = sample["raw_artifact_id"]
        report_id = sample["normalized_report_artifact_id"]
        if (
            raw_id not in artifacts_by_id
            or artifacts_by_id[raw_id]["role"] != "raw_artifact"
            or report_id not in artifacts_by_id
            or artifacts_by_id[report_id]["role"] != "normalized_report"
        ):
            raise _dataset_semantic_error(
                "sample raw and report references must resolve to matching artifacts"
            )
        referenced.update({raw_id, report_id})
        collection_id = _validate_sample_collection_reference(sample, artifacts_by_id)
        if collection_id is not None:
            referenced.add(collection_id)
        _validate_sample_origin(sample)
        raw_producer = artifacts_by_id[raw_id]["producer"]
        if sample["origin_classification"] == "synthetic":
            if raw_producer["kind"] != "author":
                raise _dataset_semantic_error(
                    "synthetic raw artifacts must be author-produced"
                )
            if collection_id is not None and (
                artifacts_by_id[collection_id]["producer"]["kind"] != "author"
                or artifacts_by_id[collection_id]["producer"]["name"]
                != raw_producer["name"]
                or artifacts_by_id[collection_id]["producer"]["version"]
                != raw_producer["version"]
            ):
                raise _dataset_semantic_error(
                    "synthetic collection fixtures must match their raw author"
                )
        elif (
            collection_id is None
            or raw_producer["kind"] != "collector"
            or artifacts_by_id[collection_id]["producer"]["kind"] != "collector"
            or raw_producer["name"]
            != artifacts_by_id[collection_id]["producer"]["name"]
            or raw_producer["version"]
            != artifacts_by_id[collection_id]["producer"]["version"]
        ):
            raise _dataset_semantic_error(
                "captured raw artifacts must match their collection producer"
            )
        if sample["origin_classification"] == "physical_captured" and any(
            artifacts_by_id[artifact_id]["redaction_state"] == "not_required"
            for artifact_id in (raw_id, report_id, collection_id)
            if artifact_id is not None
        ):
            raise _dataset_semantic_error("physical sample artifacts require redaction")

    _validate_dataset_authorization(data, origins)
    return referenced


def _validate_dataset_contract_semantics(
    data: object, *, require_current_profile: bool
) -> None:
    if not isinstance(data, dict):
        return
    artifacts_by_id = _validate_dataset_artifact_contract(
        data, require_current_profile=require_current_profile
    )
    referenced = _validate_dataset_sample_contract(data, artifacts_by_id)

    derivations = data["derived_diffs"]
    derivation_ids = [item["derivation_id"] for item in derivations]
    _validate_unique_strings(derivation_ids, "derivation IDs")
    _validate_unique_strings(
        [item["artifact_id"] for item in derivations],
        "diff artifact references",
    )
    samples_by_id = {sample["sample_id"]: sample for sample in data["samples"]}
    sample_ids = set(samples_by_id)
    for derivation in derivations:
        artifact_id = derivation["artifact_id"]
        if (
            derivation["base_sample_id"] not in sample_ids
            or derivation["compare_sample_id"] not in sample_ids
            or derivation["base_sample_id"] == derivation["compare_sample_id"]
            or artifact_id not in artifacts_by_id
            or artifacts_by_id[artifact_id]["role"] != "derived_diff"
        ):
            raise _dataset_semantic_error(
                "diff derivations must resolve distinct samples and a diff artifact"
            )
        if (
            "physical_captured"
            in {
                samples_by_id[derivation["base_sample_id"]]["origin_classification"],
                samples_by_id[derivation["compare_sample_id"]]["origin_classification"],
            }
            and artifacts_by_id[artifact_id]["redaction_state"] == "not_required"
        ):
            raise _dataset_semantic_error(
                "diffs derived from physical samples require redaction"
            )
        referenced.add(artifact_id)
    if referenced != set(artifacts_by_id):
        raise _dataset_semantic_error(
            "artifact registry must be a closed, fully referenced graph"
        )


def validate_dataset_source(data: object) -> None:
    """Validate the author-maintained declarative dataset source."""

    validate_with_schema(
        data,
        "dataset_source_v1_0_0.schema.json",
        artifact_name="dataset source",
        supported_versions=SUPPORTED_DATASET_SOURCE_SCHEMA_VERSIONS,
    )
    _validate_dataset_contract_semantics(data, require_current_profile=True)


def validate_dataset_manifest(data: object) -> None:
    """Validate a historical v1 or strict verifiable v2 dataset manifest."""

    version = data.get("schema_version") if isinstance(data, dict) else None
    if (
        isinstance(version, str)
        and version not in SUPPORTED_DATASET_MANIFEST_SCHEMA_VERSIONS
    ):
        raise UnsupportedSchemaVersionError(
            "unsupported dataset manifest schema version"
        )
    resource_version = (
        version
        if isinstance(version, str)
        else current_write_version(SchemaFamily.DATASET_MANIFEST)
    )
    validate_with_schema(
        data,
        schema_resource_name(SchemaFamily.DATASET_MANIFEST, resource_version),
        artifact_name="dataset manifest",
        supported_versions=SUPPORTED_DATASET_MANIFEST_SCHEMA_VERSIONS,
    )
    if resource_version == "2.0.0":
        _validate_dataset_contract_semantics(data, require_current_profile=False)
