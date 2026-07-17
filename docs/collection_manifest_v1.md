# Collection Manifest v1

Collection manifest `1.0.0` is the shared portable provenance contract for host,
ADB-shell, unprivileged-app, and root/Magisk observers. The Draft 2020-12 schema
is packaged as `collection_manifest_v1_0_0.schema.json` and resolved only through
the exact compatibility registry.

Every manifest identifies one collection event, collector and version, observer,
pseudonymous target, bounded environment metadata, start and end timestamps,
completion status, tool versions, a reserved warning list, redaction policy, and
artifact entries. The portable semantic profile requires `warnings=[]` and every
artifact `detail` to be null; structured statuses, exit codes, and timeout flags
carry outcomes without a free-text leakage channel. Direct identifiers, device
serials, credentials, and absolute host paths are forbidden.
Tool-version values are compact version tokens (letters, digits, `.`, `_`, `+`,
and `-`) rather than diagnostic sentences or command lines.

## Artifact outcomes

Each artifact has a stable logical name, expected media type, probe identity,
sensitivity, redaction state, exit code, and timeout flag. The canonical evidence
statuses keep these cases separate:

- `observed` binds a relative path, byte size, and SHA-256 digest;
- `observed_absent` means a successful probe affirmatively produced no artifact;
- `inaccessible` records an access boundary;
- `not_collected` records a probe that was not run or retained;
- `command_error` records command, transport, parser, or timeout failure;
- `unsupported` records a capability that does not apply.

Only `observed` entries may carry a path, size, or digest. A timeout is always a
`command_error`. A `complete` collection cannot conceal failed or omitted probes;
required ADB and Magisk probes also cannot be `unsupported` in a complete run;
a `partial` collection contains both usable and unavailable evidence; a `failed`
collection contains no usable artifact. An individual observed artifact is
limited to 64 MiB so verification remains bounded.

## Analyzer workflow

Validate a manifest without touching its artifacts:

```bash
trustlab validate-collection-manifest collector_manifest.json
```

Verify the bound raw artifact and normalize it:

```bash
trustlab normalize --manifest collector_manifest.json --output report.json
```

Verify, copy, normalize, and atomically publish a complete Magisk collection:

```bash
trustlab import magisk --input COLLECTION_DIR --output PRIVATE_IMPORT_ROOT
```

The dedicated importer is complete-only and applies the additional closed-bundle,
module-version, aggregate-size, content-addressed publication, and private-mode
contract documented in `docs/magisk_import_contract.md`. The generic normalize
command remains the compatibility path for partial historical collections.

The analyzer resolves artifact paths relative to the manifest; rejects traversal,
all symlink components, and non-regular files; checks the declared size before
streaming; and parses the exact byte snapshot whose SHA-256 it verified. It also
refuses to replace either the manifest or bound source evidence. The legacy
`trustlab normalize --input raw.txt ...` flow remains supported.

Manifest-backed reports retain every artifact outcome in
`provenance.command_results`. Partial status and unavailable probes are also
surfaced under `limitations.collection_errors`. The complete validated
manifest and a SHA-256 digest of its canonical JSON form are retained under the
strict `org.androidtrustlab.collection` extension, so the report remains bound to
its collection provenance. Report v4 also carries the raw entry as a structured
reference with its logical ID, relative path, size, digest, media type, collector
version, collection ID, status, and redaction state.

The manually authored Magisk sample demonstrates an honest `partial` legacy
capture: its consolidated `raw_report` is integrity-bound, while missing
per-command results remain `not_collected` instead of masquerading as an empty
successful artifact.

An unprivileged app collection binds exactly one `app_probe.json` raw report as
`application/json`. The v2 artifact repeats the manifest's collector, observer,
collection, target, timing, completion, environment, and redaction metadata;
normalization rejects any mismatch. Every inaccessible, unsupported, or failed
app probe also has an exact null-path manifest outcome. Historical
`trustlab-app` manifests with a `text/plain` legacy sectioned report remain
readable but cannot activate typed app-visible evidence.

The hardened Magisk runtime adds exact per-probe artifacts, structured command
results, a sanitized collection log, and an explicit boot-completion entry.
Every observed runtime file is integrity-bound, and the completion manifest is
the final non-replacing publication marker.
