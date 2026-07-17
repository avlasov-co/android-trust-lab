# CLI Output and Failure Contract

The `trustlab` CLI validates authoritative JSON artifacts before publishing them.
Normalize validates its in-memory report before writing. Diff always validates
both input reports and the generated diff before writing.
`migrate-report` accepts any readable report version, validates every registered
migration step to current report v5, and publishes a separate output without
replacing the historical source. Current v3 input is validated and copied.
`validate-collection-manifest` validates the strict portable manifest contract.
Normalize with `--manifest` verifies every observed artifact binding before it
parses the declared `raw_report`. The validated manifest observer and schema
select the observer-specific adapter. Direct JSON inputs select from their
declared `artifact_kind`, `schema_version`, and `collector_version`; direct
non-JSON input uses the warned legacy fallback. `--artifact-kind` can make
direct-input selection explicit and is rejected with `--manifest`.
For `trustlab-app`, an `application/json` manifest entry selects the typed v2
app-probe adapter and enforces exact artifact/manifest metadata and outcome
binding; legacy `text/plain` app manifests retain the historical read path.
`dataset verify` is read-only: it validates dataset source and manifest
contracts, safe relative paths, exact size/hash bindings, the closed reference
graph, collection relationships, and deterministic report/diff freshness.
`collect host --output DIR` runs only the reviewed host-version command
allowlist, captures bounded and redacted provenance, and atomically publishes a
private unique collection directory. Missing SDK tools and command failures are
represented inside the completed collection rather than treated as CLI
failures.
`collect adb --serial SERIAL --output DIR` first requires one exact authorized
target through `adb devices` and `adb -s SERIAL get-state`, then runs only the
documented read-only argument-array allowlist. It publishes a private,
normalizable collection atomically and is silent on success. Preflight failures
exit with code 7 before any target shell command; diagnostics never echo the
serial.
`import magisk --input PATH --output DIR` accepts only an unpacked complete
Magisk collection directory or its exact `collector_manifest.json`. It verifies
the strict schema, collector and module versions, completion and redaction
declarations, closed relative-path set, aggregate limits, regular-file type,
byte sizes, and SHA-256 hashes. It opens declared files through a no-follow
directory walk, normalizes and validates the retained verified bytes through the
Magisk adapter, then atomically publishes a private `sha256-<manifest-digest>`
tree. It does not extract archives, run ADB, invoke root, or replace an existing
content address. Successful import is silent.

Validation uses Draft 2020-12 with explicit format checking. All detected
schema errors are reported in deterministic JSON-pointer order; diagnostics
name violated constraints without echoing sensitive input values.

Successful JSON writes use a temporary file in the destination directory. The
writer serializes before creating the directory, creates the temporary file with
mode `0600`, flushes and `fsync`s it, closes it, and uses `os.replace` on the same
filesystem. Failed validation creates no output. A failed write preserves an
existing destination and removes its ordinary temporary file.

New and replaced reports are intentionally private (`0600`) because reports can
contain device metadata. Portable structured raw-artifact references default to
the input basename and bind the exact pre-parse bytes by size and SHA-256.
Collection-event, content, and report identities exclude absolute host paths.
Use `--raw-artifact-ref` for a stable non-sensitive relative reference.

## Exit codes

Project-domain failures print one `error: ...` line to stderr, print no
traceback or stdout, and return:

| Code | Meaning |
|---:|---|
| 1 | Unexpected/internal project error |
| 2 | Command usage error reported by argparse |
| 3 | Missing input file |
| 4 | Invalid or non-UTF-8 JSON |
| 5 | Unsupported report, diff, collection, or dataset schema version |
| 6 | Schema validation failure |
| 7 | Collection or input-read failure |
| 8 | Normalization failure |
| 9 | Atomic output-write failure |

Usage failures retain argparse's standard usage diagnostic and exit code 2.
Unexpected exceptions are reduced to a generic code-1 message unless `--debug`
is active, so host details from exception text are not disclosed by default.

All raw text artifacts and JSON documents use strict UTF-8. Invalid raw bytes
are a collection failure (exit 7); invalid UTF-8 in JSON is an invalid-document
failure (exit 4). Decoding never substitutes replacement characters.

Successful write commands are silent, so a closed or encoding-incompatible
stdout cannot turn a completed publication into a failed command. Validation
commands emit short ASCII status text without echoing user paths. Normalize
refuses an output that aliases its raw input, diff refuses an output that aliases
either input report, and migration refuses an output that aliases its source.
Manifest normalization refuses to replace either the manifest or any bound
source artifact.
Host and ADB collection also remain silent after successful publication; the created
directory uses an opaque `atlcol-*` name beneath the caller-selected output
root.
Magisk import is also silent and places `collector_manifest.json`, its declared
evidence, and `trust_report.json` beneath the deterministic content address.
Successful dataset verification prints exactly `dataset verified` and never
modifies the bundle.

Place `--debug` before the subcommand to retain exception chaining and show a
traceback for an expected project error. Schema-validation causes retain native
validator/path metadata but replace rejected instance values with value-safe
constraint messages:

```bash
trustlab --debug validate-report report.json
```

Normalize retains `--no-validate` only for explicit low-level diagnosis. Its
help labels it **DANGEROUS**. It is never the default and is not used by project
generators or verification. Diff has no validation bypass.
