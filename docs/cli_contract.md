# CLI Output and Failure Contract

The `trustlab` CLI validates authoritative JSON artifacts before publishing them.
Normalize validates its in-memory report before writing. Diff always validates
both input reports and the generated diff before writing.
`migrate-report` accepts only validated report v1 input, validates its v2 result,
and publishes a separate output without replacing the historical source.
`validate-collection-manifest` validates the strict portable manifest contract.
Normalize with `--manifest` verifies every observed artifact binding before it
parses the declared `raw_report`.
`dataset verify` is read-only: it validates dataset source and manifest
contracts, safe relative paths, exact size/hash bindings, the closed reference
graph, collection relationships, and deterministic report/diff freshness.

Validation uses Draft 2020-12 with explicit format checking. All detected
schema errors are reported in deterministic JSON-pointer order; diagnostics
name violated constraints without echoing sensitive input values.

Successful JSON writes use a temporary file in the destination directory. The
writer serializes before creating the directory, creates the temporary file with
mode `0600`, flushes and `fsync`s it, closes it, and uses `os.replace` on the same
filesystem. Failed validation creates no output. A failed write preserves an
existing destination and removes its ordinary temporary file.

New and replaced reports are intentionally private (`0600`) because reports can
contain device metadata. Portable raw-artifact references default to the input
basename; a non-published digest of parsed evidence prevents same-name report-ID
collisions. Use `--raw-artifact-ref` for a stable non-sensitive logical
reference.

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
