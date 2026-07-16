# Analyzer

The analyzer parses raw Android Trust Lab artifacts, writes strict report v2,
validates versioned JSON schemas, explicitly migrates v1 reports, computes diffs,
and writes summaries.

## Install

Supported runtimes are Python 3.11, 3.12, 3.13, and 3.14. Use Python 3.11 or
newer to install the analyzer.

```bash
cd analyzer
python -m pip install -e ".[dev]"
```

JSON Schemas ship inside wheel and sdist artifacts. Validation therefore works
from any current directory and does not depend on a source checkout. The
packaged resources under `trustlab/schemas/` are canonical; repository-level
copies under `collector/schema/` are compatibility paths checked byte-for-byte
by the complete repository gate.

Collection manifest `1.0.0` uses the same packaged, exact-version validation
path. Manifest normalization accepts only bounded regular files, parses the exact
verified byte snapshot, and retains the canonical manifest digest plus all probe
outcomes in report provenance. Legacy direct raw-file normalization remains
supported.

## Commands

```bash
trustlab normalize --input ../tests/fixtures/sample_raw_report.txt --output /tmp/report.json
trustlab normalize --manifest ../datasets/samples/magisk_collector/collector_manifest_sample.json --output /tmp/manifest-report.json
trustlab validate-collection-manifest ../datasets/samples/magisk_collector/collector_manifest_sample.json
trustlab migrate-report --input ../tests/fixtures/report_v1_historical.json --output /tmp/migrated-v2.json
trustlab validate-report /tmp/report.json
trustlab diff --base ../datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json --compare ../datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json --output /tmp/diff.json
trustlab diff --base ../datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json --compare ../datasets/samples/rooted_avd/E02_rooted_avd__observer-root__sample.json --output /tmp/observer_diff.json
trustlab summarize /tmp/diff.json
```

## Failure behavior

Reports and diffs are validate-first and atomically replaced. Expected failures
use stable nonzero exit codes and concise stderr without a traceback. See
`docs/cli_contract.md` from the repository root for the complete contract.
