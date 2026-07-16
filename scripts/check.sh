#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

if [[ -n "${PYTHON_BIN:-}" ]]; then
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1 && [[ ! -x "$PYTHON_BIN" ]]; then
    echo "PYTHON_BIN is not executable: $PYTHON_BIN" >&2
    exit 1
  fi
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN=python
else
  echo "Python 3 is required (set PYTHON_BIN to an interpreter path)" >&2
  exit 1
fi
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer is required" >&2
  exit 1
fi

require_path() {
  if [[ ! -e "$1" ]]; then
    echo "missing required path: $1" >&2
    exit 1
  fi
}

require_path analyzer
require_path tools
require_path tests
require_path collector/schema/trust_report_v1_0_0.schema.json
require_path collector/schema/trust_report_v2_0_0.schema.json
require_path collector/schema/trust_report_v3_0_0.schema.json
require_path collector/schema/collection_manifest_v1_0_0.schema.json
require_path collector/schema/dataset_manifest_v1_0_0.schema.json
require_path collector/schema/dataset_manifest_v2_0_0.schema.json
require_path collector/schema/dataset_source_v1_0_0.schema.json
require_path collector/schema/trust_diff.schema.json
require_path collector/schema/trust_diff_v2_0_0.schema.json
require_path datasets/manifest.json
require_path datasets/source.json
require_path results/artifact_manifest.json
require_path module/trustlab-magisk

export PYTHONPATH="$ROOT_DIR/analyzer${PYTHONPATH:+:$PYTHONPATH}"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

echo "[1/15] Python source compile check"
"$PYTHON_BIN" -m compileall -q analyzer tools tests

echo "[2/15] Ruff formatting check"
"$PYTHON_BIN" -m ruff format --check analyzer tools tests

echo "[3/15] Ruff lint check"
"$PYTHON_BIN" -m ruff check analyzer tools tests

echo "[4/15] Static type check"
"$PYTHON_BIN" -m mypy

echo "[5/15] Unit tests with branch coverage"
"$PYTHON_BIN" -m coverage erase
"$PYTHON_BIN" -m coverage run -m pytest
"$PYTHON_BIN" -m coverage report -m
COVERAGE_JSON=$(mktemp "${TMPDIR:-/tmp}/android-trust-lab-coverage.XXXXXX")
trap 'rm -f "$COVERAGE_JSON"' EXIT
"$PYTHON_BIN" -m coverage json -o "$COVERAGE_JSON"
"$PYTHON_BIN" tools/check_coverage.py "$COVERAGE_JSON"

echo "[6/15] Canonical project metadata validation"
"$PYTHON_BIN" tools/check_metadata.py

echo "[7/15] Project version consistency check"
"$PYTHON_BIN" tools/check_version_consistency.py

echo "[8/15] Python support policy consistency check"
"$PYTHON_BIN" tools/check_python_support.py

echo "[9/15] Packaged schema consistency check"
"$PYTHON_BIN" tools/check_schema_consistency.py

echo "[10/15] JSON Schema and checked-in artifact validation"
"$PYTHON_BIN" tools/check_schemas.py

echo "[11/15] Generated artifact freshness check"
"$PYTHON_BIN" tools/generate_report.py --check

echo "[12/15] Magisk package safety check"
"$PYTHON_BIN" tools/package_magisk_module.py --check-only

echo "[13/15] Shell syntax check"
while IFS= read -r script; do
  echo "$script"
  sh -n "$script"
done < <(find module/trustlab-magisk -name "*.sh" -print | sort)
bash -n scripts/check.sh scripts/verify_release.sh

echo "[14/15] ShellCheck"
find module/trustlab-magisk -name "*.sh" -print0 \
  | sort -z \
  | xargs -0 shellcheck --shell=sh --external-sources
shellcheck --shell=bash scripts/check.sh scripts/verify_release.sh

echo "[15/15] Baseline-aware secret detection"
git ls-files --cached --others --exclude-standard -z \
  | xargs -0 "$PYTHON_BIN" -m detect_secrets.pre_commit_hook \
    --baseline .secrets.baseline \
    --exclude-files '^\.secrets\.baseline$' \
    --exclude-lines '^\s+"sha256": "[a-f0-9]{64}",?\s*$' \
    --no-verify \
    --

echo "repository checks passed"
