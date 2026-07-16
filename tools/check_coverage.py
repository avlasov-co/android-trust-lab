#!/usr/bin/env python3
"""Enforce independent statement and branch coverage floors by source group."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NamedTuple, cast


class CoveragePolicy(NamedTuple):
    label: str
    path_prefix: str
    minimum_statements: float
    minimum_branches: float


class CoverageMetrics(NamedTuple):
    covered_statements: int
    statements: int
    covered_branches: int
    branches: int

    @property
    def statement_percent(self) -> float:
        return 100.0 * self.covered_statements / self.statements

    @property
    def branch_percent(self) -> float:
        return 100.0 * self.covered_branches / self.branches


POLICIES = (
    CoveragePolicy("analyzer/trustlab", "analyzer/trustlab/", 85.0, 80.0),
    CoveragePolicy("tools", "tools/", 70.0, 60.0),
)


def load_coverage(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        raise ValueError("coverage JSON must contain a files object")
    return data


def group_metrics(payload: Mapping[str, Any], path_prefix: str) -> CoverageMetrics:
    raw_files = payload.get("files")
    if not isinstance(raw_files, dict):
        raise ValueError("coverage JSON must contain a files object")

    totals = [0, 0, 0, 0]
    for raw_path, raw_file in raw_files.items():
        normalized_path = str(raw_path).replace("\\", "/").removeprefix("./")
        if not normalized_path.startswith(path_prefix):
            continue
        if not isinstance(raw_file, dict) or not isinstance(
            raw_file.get("summary"), dict
        ):
            raise ValueError(f"coverage entry has no summary: {normalized_path}")
        summary = cast(dict[str, Any], raw_file["summary"])
        fields = (
            "covered_lines",
            "num_statements",
            "covered_branches",
            "num_branches",
        )
        values = [summary.get(field) for field in fields]
        if any(not isinstance(value, int) for value in values):
            raise ValueError(f"coverage summary is malformed: {normalized_path}")
        for index, value in enumerate(values):
            totals[index] += cast(int, value)

    metrics = CoverageMetrics(*totals)
    if metrics.statements == 0 or metrics.branches == 0:
        raise ValueError(f"coverage group has no measurable code: {path_prefix}")
    return metrics


def coverage_errors(
    payload: Mapping[str, Any], policies: Sequence[CoveragePolicy] = POLICIES
) -> list[str]:
    errors: list[str] = []
    for policy in policies:
        metrics = group_metrics(payload, policy.path_prefix)
        if metrics.statement_percent < policy.minimum_statements:
            errors.append(
                f"{policy.label} statement coverage {metrics.statement_percent:.2f}% "
                f"is below {policy.minimum_statements:.2f}%"
            )
        if metrics.branch_percent < policy.minimum_branches:
            errors.append(
                f"{policy.label} branch coverage {metrics.branch_percent:.2f}% "
                f"is below {policy.minimum_branches:.2f}%"
            )
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("coverage_json", type=Path)
    args = parser.parse_args(argv)
    payload = load_coverage(args.coverage_json)
    errors = coverage_errors(payload)
    if errors:
        raise ValueError("coverage policy errors:\n- " + "\n- ".join(errors))
    for policy in POLICIES:
        metrics = group_metrics(payload, policy.path_prefix)
        print(
            f"{policy.label}: statements {metrics.statement_percent:.2f}%, "
            f"branches {metrics.branch_percent:.2f}%"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
