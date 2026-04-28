# Host Snapshot Collection

Collect host-side provenance before target collection.

## Collects

- host OS
- adb version
- emulator version
- AVD name
- target serial
- experiment id
- collection timestamp

## Example commands

```bash
uname -a
adb version
emulator -version || true
adb devices -l
```

## Purpose

Preserve provenance of experiment artifacts. Reports without provenance are not suitable for reproducible comparison.
