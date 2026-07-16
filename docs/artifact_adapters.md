# Typed artifact adapters

Android Trust Lab parses imported capture facts through an explicit typed
adapter boundary before deriving trust dimensions. Adapters do not decide
whether a device is trustworthy. They identify what a source says was
captured, retain capture status and diagnostics, and expose constrained
syntactic evidence fragments to the normalizer.

## Supported input families

| Input kind | Schema version | Supported collector versions | Expected observer |
|---|---|---|---|
| `legacy_sectioned_text` | `legacy-sectioned-text-1` | `legacy` compatibility path | caller-supplied or `adb_shell` fallback |
| `adb_collection_manifest` | `1.0.0` | `0.3.0`, `0.3.0-dev0`, `1.0.0` | `adb_shell` |
| `magisk_collection_manifest` | `1.0.0` | `0.3.0`, `0.3.0-dev0`, `1.0.0` | `root_collector` |
| `host_collection_manifest` | `1.0.0` | `0.3.0`, `0.3.0-dev0`, `1.0.0` | `host` |
| `app_probe_json` | `1.0.0` | `0.3.0`, `0.3.0-dev0`, `1.0.0` | `unprivileged_app` |

The two JSON contracts are packaged as
`artifact_collection_manifest_v1_0_0.schema.json` and
`app_probe_v1_0_0.schema.json`. The collection-adapter contract covers the ADB,
Magisk, and host kinds; the declared kind and observer must agree.

## Selection and compatibility

JSON inputs must declare `artifact_kind`, `schema_version`, and
`collector_version`. Automatic selection reads those fields and never uses the
filename. An unsupported kind or version fails closed. A non-JSON input takes
the deliberate legacy sectioned-text path and records a warning that command
status was inferred because the historical format did not retain it.

Use `--artifact-kind` to make direct-input selection explicit when desired:

```bash
trustlab normalize \
  --input capture.json \
  --artifact-kind adb_collection_manifest \
  --output report.json
```

`--manifest` means the portable collection manifest v1 workflow documented in
[Collection manifest v1](collection_manifest_v1.md). It verifies the bound raw
report and selects the ADB, host, app, or Magisk adapter from validated observer
metadata. A current `text/plain` bound report uses the historical section syntax
inside that observer-specific boundary. `--artifact-kind` applies only to
direct `--input` normalization.

For JSON adapters, declared experiment, target, observer, method, timestamp,
and collector version are authoritative. Contradictory caller or CLI context
fails closed; contextual overrides remain available only for legacy direct
text. Metadata establishes provenance and visibility context but cannot create
an observation. For example, a
`root_collector` declaration without an observed identity capture leaves UID and
root-shell evidence `not_collected`.

## Typed boundary

Every adapter implements the `ArtifactAdapter` protocol and returns an immutable
`ArtifactParseResult` containing:

- `ArtifactMetadata` with input schema, collector version, and optional event
  context;
- ordered `CommandCapture` records with name, capture status, exit code,
  timeout, stdout, stderr, and a portable relative source reference;
- separate warning and error tuples;
- `EvidenceFragments` containing only constrained syntactic properties, boot
  key/value facts, selected mount records plus every mount-source attempt,
  identity fields, SELinux text, command line, `su` paths, Magisk text, and
  process facts.

Only coherent, syntactically parsed `observed` captures and deliberately empty
captures contribute parser fragments. Successful statuses require a zero or
absent exit code and no timeout; aliases and duplicate semantic captures are
rejected except for the deliberate mountinfo, `/proc/mounts`, and `mount`
fallback set. Mount selection uses fixed source priority rather than manifest
order, and malformed preferred-source attempts remain recorded when a usable
fallback exists. Observer-specific capture vocabularies prevent host evidence from
populating Android target dimensions.
Failed, inaccessible, timed-out, unsupported, and uncollected captures remain
visible in report command-result provenance and never have their stdout
interpreted as evidence. Adapter kind/version, warnings, errors, and capture
source references are retained in the namespaced
`org.androidtrustlab.adapter` report extension.

The direct file path uses the same bounded, regular-file, no-follow snapshot
reader as legacy normalization. Exact source bytes are hashed and any expected
size/digest is checked before UTF-8 decoding or adapter parsing. JSON parsing
rejects duplicate object members and non-standard constants.
[Parser limits and malformed-input policy](parser_limits.md) defines the shared
byte, line, section, JSON nesting, duplicate, warning, and recovery contract.

## Interpretation boundary

The parser layer reports syntax and capture outcomes. The normalizer alone
derives report dimensions such as verified-boot state, mount integrity, root
state, Magisk state, emulator signals, and limitations. Evidence absence is
recorded only when the relevant capture completed and observed the absence;
inaccessible or omitted captures are not converted into negative findings.

Shared contract, fixture, malformed-input, version-selection, determinism, and
metadata-confusion tests live in `tests/test_artifact_adapters.py`.
