# Collectors

## Typed artifact adapters

The analyzer accepts five explicit artifact families: legacy sectioned text,
ADB collection manifests, Magisk collection manifests, host collection
manifests, and app-probe JSON. JSON inputs declare `artifact_kind`,
`schema_version`, and `collector_version`; adapter selection never depends on a
filename. The legacy text path remains supported for existing samples and
always emits a warning because command exit status was not recorded by that
format.

The portable collection-manifest v1 workflow remains authoritative for bound
collector output. Its validated observer metadata selects the ADB, Magisk,
host, or app adapter for the exact verified sectioned-text payload. The direct
versioned JSON envelopes are strict import contracts for capture producers that
already retain per-capture results inline.

Adapters preserve capture status, exit code, timeout state, stdout, stderr,
warnings, and errors as typed parser results. Only successful/empty capture
payloads become syntactic evidence fragments. Trust dimensions are derived by
the normalizer, and observer metadata supplies visibility context only.

Android Trust Lab separates observers because Android trust evidence changes across privilege boundaries.

## Collector types

| Collector | Observer type | Can see | Cannot see |
|---|---|---|---|
| host collector | host | host OS, adb version, emulator metadata | internal Android state by itself |
| adb collector | adb_shell | shell-visible props, mounts, uid/gid, SELinux mode | normal app-only view, full root-only state |
| app probe | unprivileged_app | Android API-visible Build values, limited environment | privileged mount/process state |
| Magisk collector | root_collector | privileged read-only snapshot | hardware-backed trust proof by itself |

## Report naming

```text
E01_stock_avd__observer-adb__timestamp.json
collector_manifest_timestamp.json
```

## Artifact storage

Recommended layout:

```text
datasets/samples/<experiment_class>/raw/
datasets/samples/<experiment_class>/normalized/
results/
```

Current reports map to `collector/schema/trust_report_v3_0_0.schema.json`;
the versioned v1 and v2 schemas are retained for read compatibility.

All observer classes share
`collector/schema/collection_manifest_v1_0_0.schema.json`. Portable manifests
use pseudonymous targets and relative paths, bind observed artifacts by size and
SHA-256, and preserve missing, inaccessible, failed, timed-out, unsupported, and
successfully empty outcomes as distinct states.
