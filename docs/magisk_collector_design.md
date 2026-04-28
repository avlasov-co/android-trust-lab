# Magisk Collector Design

The Magisk module is a read-only privileged collector for Android Trust Lab. It does not change system behavior.

## Why a root-side snapshot is useful

An adb shell or app observer cannot always see privileged state. A root-side collector can capture mount details, process visibility, SELinux contexts, Magisk paths, and boot properties from a different privilege boundary.

## What the collector can see

Depending on target and permissions, it may see:

- boot properties
- kernel command line
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
- `uninstall.sh`: removes internal temporary files, preserves exported reports

## Output paths

Primary path:

```text
/data/local/tmp/android-trust-lab/reports/
```

The module writes two artifact types:

```text
raw_<timestamp>.txt
collector_manifest_<timestamp>.json
```

The manifest is not a normalized trust report. It records provenance for the raw root-side snapshot. The host analyzer converts `raw_<timestamp>.txt` into `trust_report.schema.json` format.

Optional exported path:

```text
/sdcard/Android/data/dev.androidtrustlab/files/reports/
```

## Permissions

The module runs with Magisk module script privileges. It should still collect defensively and record errors instead of assuming every command exists.

## Limitations

A root-side collector improves visibility but does not prove hardware-backed boot trust by itself. It also changes the observer class and must be labeled clearly.
