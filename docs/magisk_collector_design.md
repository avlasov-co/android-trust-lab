# Magisk Collector Design

The Magisk module is a read-only privileged collector for Android Trust Lab. It does not change system behavior.

## Why a root-side snapshot is useful

An adb shell or app observer cannot always see privileged state. A root-side collector can capture mount details, process visibility, SELinux contexts, Magisk paths, and boot properties from a different privilege boundary.

## What the collector can see

Depending on target and permissions, it may see:

- boot properties
- mount state
- SELinux mode
- process state
- filesystem contexts
- Magisk binary/version/path indicators

## What it collects

- boot state
- Android properties
- mounts
- SELinux state
- Magisk state
- process state
- collection errors

## What it must never modify

The module must not modify properties, patch SELinux, remount partitions, mount overlays, hide root, spoof identity, or help evade security checks.

## Lifecycle

- `post-fs-data.sh`: intentionally minimal in the MVP
- `service.sh`: waits for boot completion, writes one report, exits
- `action.sh`: manual collection entrypoint
- `uninstall.sh`: preserves private report directories and the stable private
  target pseudonym; no temporary state exists outside per-run directories

## Output paths

Private per-run path:

```text
/data/adb/android-trust-lab/reports/run_<timestamp>.<random>/
```

The module writes two artifact types:

```text
raw.txt
collector_manifest.json
```

The strict collection-manifest v1 document is not a normalized trust report. It
uses only portable relative paths, binds `raw.txt` by byte size and SHA-256,
records a pseudonymous target, and marks missing per-command results as
`not_collected`. The host analyzer verifies the binding and converts `raw.txt`
into the current `trust_report_v2_0_0.schema.json` format.

The pseudonymous target is a randomly generated 64-bit token stored once as
`/data/adb/android-trust-lab/target_pseudonym` with mode `0600`. Reusing that
private random token keeps target identity stable across collections without
hashing or retaining a device serial or observation content. The module validates
every dynamic value interpolated into the manifest, including its schema-safe
collector version, before publishing JSON.

## Permissions

The module runs with Magisk module script privileges. Output is created beneath
the root-controlled `/data/adb` tree with `umask 077`, exclusive randomized run
directories, mode `0700` directories, and mode `0600` artifacts. Symlinked
output directories are rejected. The collector uses a property allowlist and
does not capture the kernel command line.

## Limitations

A root-side collector improves visibility but does not prove hardware-backed boot trust by itself. It also changes the observer class and must be labeled clearly.
