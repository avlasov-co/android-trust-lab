# Analyzer

The analyzer parses raw Android Trust Lab artifacts, normalizes reports, validates JSON schemas, computes diffs, and writes summaries.

## Install

```bash
cd analyzer
python -m pip install -e ".[dev]"
```

## Commands

```bash
trustlab normalize --input ../tests/fixtures/sample_raw_report.txt --output /tmp/report.json
trustlab validate-report /tmp/report.json
trustlab diff --base ../datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json --compare ../datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json --output /tmp/diff.json
trustlab diff --base ../datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json --compare ../datasets/samples/rooted_avd/E02_rooted_avd__observer-root__sample.json --output /tmp/observer_diff.json
trustlab summarize /tmp/diff.json
```
