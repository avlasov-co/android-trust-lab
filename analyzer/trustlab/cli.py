"""Command line interface for Android Trust Lab analyzer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .normalizer import normalize_raw_file
from .diff import make_diff
from .report_writer import write_json, load_json, diff_to_markdown, report_to_markdown
from .validators import validate_report, validate_diff


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
    write_json(report, args.output)
    if args.validate:
        validate_report(report)
    print(args.output)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    base = load_json(args.base)
    compare = load_json(args.compare)
    diff = make_diff(base, compare)
    write_json(diff, args.output)
    if args.validate:
        validate_diff(diff)
    print(args.output)
    return 0


def cmd_validate_report(args: argparse.Namespace) -> int:
    validate_report(load_json(args.report))
    print(f"valid report: {args.report}")
    return 0


def cmd_validate_diff(args: argparse.Namespace) -> int:
    validate_diff(load_json(args.diff))
    print(f"valid diff: {args.diff}")
    return 0


def cmd_summarize(args: argparse.Namespace) -> int:
    data = load_json(args.path)
    if "changed_dimensions" in data:
        print(diff_to_markdown(data))
    else:
        print(report_to_markdown(data))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trustlab", description="Android Trust Lab analyzer")
    sub = parser.add_subparsers(required=True)

    normalize = sub.add_parser("normalize", help="Normalize raw artifact into trust report JSON")
    normalize.add_argument("--input", required=True)
    normalize.add_argument("--output", required=True)
    normalize.add_argument("--experiment-id", default="unknown")
    normalize.add_argument("--target-type", choices=["avd", "physical", "unknown"], default="unknown")
    normalize.add_argument("--observer", choices=["host", "adb_shell", "unprivileged_app", "root_collector"], default="adb_shell")
    normalize.add_argument("--collection-method", default="raw_artifact")
    normalize.add_argument("--collection-timestamp", default=None, help="Optional ISO-8601 timestamp for reproducible sample reports")
    normalize.add_argument("--raw-artifact-ref", default=None, help="Optional stable artifact reference stored in raw_artifacts")
    normalize.add_argument("--no-validate", action="store_false", dest="validate", default=True, help="Skip schema validation")
    normalize.set_defaults(func=cmd_normalize)

    diff = sub.add_parser("diff", help="Diff two trust reports")
    diff.add_argument("--base", required=True)
    diff.add_argument("--compare", required=True)
    diff.add_argument("--output", required=True)
    diff.add_argument("--no-validate", action="store_false", dest="validate", default=True, help="Skip schema validation")
    diff.set_defaults(func=cmd_diff)

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
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
