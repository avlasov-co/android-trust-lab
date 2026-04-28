# Collectors

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

Reports must map to `collector/schema/trust_report.schema.json`.
