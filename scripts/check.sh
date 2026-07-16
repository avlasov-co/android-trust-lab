#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
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

require_path() {
  if [[ ! -e "$1" ]]; then
    echo "missing required path: $1" >&2
    exit 1
  fi
}

require_path analyzer
require_path tools
require_path tests
require_path collector/schema/trust_report.schema.json
require_path collector/schema/trust_diff.schema.json
require_path datasets/manifest.json
require_path results/artifact_manifest.json
require_path module/trustlab-magisk

export PYTHONPATH="$ROOT_DIR/analyzer${PYTHONPATH:+:$PYTHONPATH}"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

echo "[1/9] Python source compile check"
"$PYTHON_BIN" -m compileall -q analyzer tools tests

echo "[2/9] Unit tests with branch coverage"
"$PYTHON_BIN" -m coverage erase
"$PYTHON_BIN" -m coverage run --branch --source=analyzer/trustlab -m pytest -q
"$PYTHON_BIN" -m coverage report -m

echo "[3/9] Canonical project metadata validation"
"$PYTHON_BIN" tools/check_metadata.py

echo "[4/9] Project version consistency check"
"$PYTHON_BIN" tools/check_version_consistency.py

echo "[5/9] Packaged schema consistency check"
"$PYTHON_BIN" tools/check_schema_consistency.py

echo "[6/9] JSON Schema and checked-in artifact validation"
"$PYTHON_BIN" tools/check_schemas.py

echo "[7/9] Generated artifact freshness check"
"$PYTHON_BIN" tools/generate_report.py --check

echo "[8/9] Magisk package safety check"
"$PYTHON_BIN" tools/package_magisk_module.py --check-only

echo "[9/9] Shell syntax check"
while IFS= read -r script; do
  echo "$script"
  sh -n "$script"
done < <(find module/trustlab-magisk -name "*.sh" -print | sort)
bash -n scripts/check.sh scripts/verify_release.sh

echo "repository checks passed"
