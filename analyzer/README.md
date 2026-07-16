# Analyzer

The analyzer parses raw Android Trust Lab artifacts, normalizes reports, validates JSON schemas, computes diffs, and writes summaries.

## Install

```bash
cd analyzer
python -m pip install -e ".[dev]"
```

JSON Schemas ship inside wheel and sdist artifacts. Validation therefore works
from any current directory and does not depend on a source checkout. The
packaged resources under `trustlab/schemas/` are canonical; repository-level
copies under `collector/schema/` are compatibility paths checked byte-for-byte
by the complete repository gate.

## Commands

```bash
trustlab normalize --input ../tests/fixtures/sample_raw_report.txt --output /tmp/report.json
trustlab validate-report /tmp/report.json
trustlab diff --base ../datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json --compare ../datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json --output /tmp/diff.json
trustlab diff --base ../datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json --compare ../datasets/samples/rooted_avd/E02_rooted_avd__observer-root__sample.json --output /tmp/observer_diff.json
trustlab summarize /tmp/diff.json
```

## Failure behavior

Reports and diffs are validate-first and atomically replaced. Expected failures
use stable nonzero exit codes and concise stderr without a traceback. See
`docs/cli_contract.md` from the repository root for the complete contract.
