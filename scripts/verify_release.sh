#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python}"

require_path() {
  if [ ! -e "$1" ]; then
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
require_path results/trust_state_diffs.md
require_path results/summary_table.md
require_path results/artifact_manifest.json
require_path module/trustlab-magisk
require_path tools/generate_report.py
require_path tools/package_magisk_module.py

export PYTHONPATH="$ROOT_DIR/analyzer${PYTHONPATH:+:$PYTHONPATH}"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

echo "[1/5] Python source compile check"
$PYTHON_BIN -m compileall -q analyzer tools tests

echo "[2/5] Unit tests"
$PYTHON_BIN -m pytest -q

echo "[3/5] Generated report freshness check"
$PYTHON_BIN tools/generate_report.py --check

echo "[4/5] Magisk package safety check"
$PYTHON_BIN tools/package_magisk_module.py --check-only

echo "[5/5] Magisk shell syntax check"
while IFS= read -r script; do
  echo "$script"
  sh -n "$script"
done < <(find module/trustlab-magisk -name "*.sh" -print | sort)

echo "release verification passed"
