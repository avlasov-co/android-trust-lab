"""Command line interface for Android Trust Lab analyzer."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

from .diff import make_diff
from .exceptions import (
    CollectionError,
    InvalidJSONError,
    MissingFileError,
    NormalizationError,
    OutputWriteError,
    SchemaValidationError,
    TrustLabError,
    UnsupportedSchemaVersionError,
)
from .migrations import migrate_report_v1_to_v2
from .normalizer import normalize_raw_file
from .observers import OBSERVER_REGISTRY
from .report_writer import diff_to_markdown, load_json, report_to_markdown, write_json
from .validators import validate_diff, validate_report

EXIT_INTERNAL_ERROR = 1
EXIT_USAGE_ERROR = 2
EXIT_MISSING_FILE = 3
EXIT_INVALID_JSON = 4
EXIT_UNSUPPORTED_SCHEMA = 5
EXIT_SCHEMA_VALIDATION = 6
EXIT_COLLECTION_FAILURE = 7
EXIT_NORMALIZATION_FAILURE = 8
EXIT_OUTPUT_WRITE_FAILURE = 9

EXPECTED_ERROR_EXIT_CODES = (
    (MissingFileError, EXIT_MISSING_FILE),
    (InvalidJSONError, EXIT_INVALID_JSON),
    (UnsupportedSchemaVersionError, EXIT_UNSUPPORTED_SCHEMA),
    (SchemaValidationError, EXIT_SCHEMA_VALIDATION),
    (CollectionError, EXIT_COLLECTION_FAILURE),
    (NormalizationError, EXIT_NORMALIZATION_FAILURE),
    (OutputWriteError, EXIT_OUTPUT_WRITE_FAILURE),
)


def _concise_error_message(exc: Exception) -> str:
    without_controls = "".join(
        " " if ord(character) < 32 or ord(character) == 127 else character
        for character in str(exc)
    )
    message = " ".join(without_controls.split())
    message = message.encode("ascii", errors="backslashreplace").decode("ascii")
    return (message or "project operation failed")[:300]


def _print_status(message: str) -> None:
    """Emit best-effort ASCII status without changing a completed operation."""

    try:
        print(message)
    except Exception:
        # A closed pipe or incompatible output encoding must not turn an
        # already-published artifact into a failed command.
        pass


def _paths_alias(left: str, right: str) -> bool:
    left_path = Path(left)
    right_path = Path(right)
    try:
        return left_path.samefile(right_path)
    except OSError:
        return left_path.resolve(strict=False) == right_path.resolve(strict=False)


def _require_distinct_output(output: str, *inputs: str) -> None:
    if any(_paths_alias(output, input_path) for input_path in inputs):
        raise OutputWriteError("output must not replace an input artifact")


def cmd_normalize(args: argparse.Namespace) -> int:
    report = normalize_raw_file(
        args.input,
        experiment_id=args.experiment_id,
        target_type=args.target_type,
        observer_type=args.observer,
        collection_method=args.collection_method,
        collection_timestamp=args.collection_timestamp,
        raw_artifact_ref=args.raw_artifact_ref,
    )
    if args.validate:
        validate_report(report)
    _require_distinct_output(args.output, args.input)
    write_json(report, args.output)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    base = load_json(args.base)
    compare = load_json(args.compare)
    validate_report(base)
    validate_report(compare)
    _require_distinct_output(args.output, args.base, args.compare)
    diff = make_diff(base, compare)
    validate_diff(diff)
    write_json(diff, args.output)
    return 0


def cmd_migrate_report(args: argparse.Namespace) -> int:
    source = load_json(args.input)
    migrated = migrate_report_v1_to_v2(source)
    _require_distinct_output(args.output, args.input)
    write_json(migrated, args.output)
    return 0


def cmd_validate_report(args: argparse.Namespace) -> int:
    validate_report(load_json(args.report))
    _print_status("valid report")
    return 0


def cmd_validate_diff(args: argparse.Namespace) -> int:
    validate_diff(load_json(args.diff))
    _print_status("valid diff")
    return 0


def cmd_summarize(args: argparse.Namespace) -> int:
    data = load_json(args.path)
    if "diff_id" in data:
        validate_diff(data)
        print(diff_to_markdown(data))
    elif "report_id" in data:
        validate_report(data)
        print(report_to_markdown(data))
    else:
        raise SchemaValidationError("unrecognized JSON artifact")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustlab", description="Android Trust Lab analyzer"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show tracebacks for expected project errors",
    )
    sub = parser.add_subparsers(required=True)

    normalize = sub.add_parser(
        "normalize", help="Normalize raw artifact into trust report JSON"
    )
    normalize.add_argument("--input", required=True)
    normalize.add_argument("--output", required=True)
    normalize.add_argument("--experiment-id", default="unknown")
    normalize.add_argument(
        "--target-type", choices=["avd", "physical", "unknown"], default="unknown"
    )
    normalize.add_argument(
        "--observer", choices=tuple(OBSERVER_REGISTRY), default="adb_shell"
    )
    normalize.add_argument("--collection-method", default="raw_artifact")
    normalize.add_argument(
        "--collection-timestamp",
        default=None,
        help="Optional ISO-8601 timestamp for reproducible sample reports",
    )
    normalize.add_argument(
        "--raw-artifact-ref",
        default=None,
        help="Optional stable artifact reference; defaults to the input basename",
    )
    normalize.add_argument(
        "--no-validate",
        action="store_false",
        dest="validate",
        default=True,
        help="DANGEROUS: write a report without schema validation",
    )
    normalize.set_defaults(func=cmd_normalize)

    diff = sub.add_parser("diff", help="Diff two trust reports")
    diff.add_argument("--base", required=True)
    diff.add_argument("--compare", required=True)
    diff.add_argument("--output", required=True)
    diff.set_defaults(func=cmd_diff)

    migrate = sub.add_parser(
        "migrate-report", help="Migrate a trust report from schema v1 to v2"
    )
    migrate.add_argument("--input", required=True)
    migrate.add_argument("--output", required=True)
    migrate.set_defaults(func=cmd_migrate_report)

    vr = sub.add_parser("validate-report", help="Validate a trust report")
    vr.add_argument("report")
    vr.set_defaults(func=cmd_validate_report)

    vd = sub.add_parser("validate-diff", help="Validate a trust diff")
    vd.add_argument("diff")
    vd.set_defaults(func=cmd_validate_diff)

    sm = sub.add_parser("summarize", help="Print markdown summary")
    sm.add_argument("path")
    sm.set_defaults(func=cmd_summarize)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        handler = cast(Callable[[argparse.Namespace], int], args.func)
        return handler(args)
    except TrustLabError as exc:
        if args.debug:
            raise
        for error_type, exit_code in EXPECTED_ERROR_EXIT_CODES:
            if isinstance(exc, error_type):
                print(f"error: {_concise_error_message(exc)}", file=sys.stderr)
                return exit_code
        print(f"error: {_concise_error_message(exc)}", file=sys.stderr)
        return EXIT_INTERNAL_ERROR
    except Exception:
        if args.debug:
            raise
        print("error: internal project failure", file=sys.stderr)
        return EXIT_INTERNAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
