# Analyzer

The analyzer parses raw Android Trust Lab artifacts, writes content-addressed
report v5, validates versioned JSON schemas, explicitly migrates v1/v2/v3/v4
reports, computes exact-input diff v2.2 documents, and writes summaries.

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
supported. Portable manifest metadata selects the ADB, host, app, or Magisk
adapter; direct versioned JSON can also declare its input kind. Typed metadata
cannot be contradicted by CLI or library overrides.

All raw parser entry points share the bounded decoding and malformed-input
contract in `docs/parser_limits.md` from the repository root. Oversized input
fails closed; legacy duplicate recovery is deterministic and explicitly
diagnosed rather than silently truncated.

Dataset manifest `2.0.0` is the sole writable dataset contract; frozen v1 remains
readable only. `trustlab dataset verify` validates the complete portable graph,
all byte bindings, collection relationships, and deterministic report/diff
freshness from any current directory.

Report `5.0.0` is the sole writer; report v1/v2/v3/v4 remain readable through the
validated `1.0.0` → `2.0.0` → `3.0.0` → `4.0.0` → `5.0.0` chain. Source bytes are hashed before
normalization, reports distinguish collection-event and evidence-content
identity, and diff v2.2 binds both exact report/content identities. See
`docs/content_identity.md` from the repository root.

## Commands

```bash
trustlab normalize --input ../tests/fixtures/sample_raw_report.txt --output /tmp/report.json
trustlab normalize --input ../tests/fixtures/adapters/adb_manifest.json --artifact-kind adb_collection_manifest --output /tmp/adb-report.json
trustlab normalize --manifest ../datasets/samples/magisk_collector/collector_manifest_sample.json --output /tmp/manifest-report.json
trustlab validate-collection-manifest ../datasets/samples/magisk_collector/collector_manifest_sample.json
trustlab dataset verify ../datasets/manifest.json
trustlab migrate-report --input ../tests/fixtures/report_v1_historical.json --output /tmp/migrated-v5.json
trustlab validate-report /tmp/report.json
trustlab diff --base ../datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json --compare ../datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json --output /tmp/diff.json
trustlab diff --base ../datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json --compare ../datasets/samples/rooted_avd/E02_rooted_avd__observer-root__sample.json --output /tmp/observer_diff.json
trustlab summarize /tmp/diff.json
```

## Failure behavior

Reports and diffs are validate-first and atomically replaced. Expected failures
use stable nonzero exit codes and concise stderr without a traceback. See
`docs/cli_contract.md` from the repository root for the complete contract.
