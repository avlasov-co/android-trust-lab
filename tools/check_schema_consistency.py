#!/usr/bin/env python3
"""Ensure compatibility schema copies match packaged canonical resources."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_DIR = ROOT / "analyzer" / "trustlab" / "schemas"
COMPATIBILITY_DIR = ROOT / "collector" / "schema"


def schema_names(directory: Path) -> set[str]:
    return {path.name for path in directory.glob("*.schema.json")}


def check_schema_directories(canonical: Path, compatibility: Path) -> None:
    canonical_names = schema_names(canonical)
    compatibility_names = schema_names(compatibility)
    if not canonical_names:
        raise ValueError("no canonical packaged schemas found")
    if canonical_names != compatibility_names:
        missing = sorted(canonical_names - compatibility_names)
        unexpected = sorted(compatibility_names - canonical_names)
        detail = []
        if missing:
            detail.append("missing compatibility copies: " + ", ".join(missing))
        if unexpected:
            detail.append("unexpected compatibility schemas: " + ", ".join(unexpected))
        raise ValueError("; ".join(detail))
    drifted = [
        name
        for name in sorted(canonical_names)
        if (canonical / name).read_bytes() != (compatibility / name).read_bytes()
    ]
    if drifted:
        raise ValueError("schema copies drifted: " + ", ".join(drifted))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    check_schema_directories(CANONICAL_DIR, COMPATIBILITY_DIR)
    print(f"schema resources are consistent: {len(schema_names(CANONICAL_DIR))} schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
