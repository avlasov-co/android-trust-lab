# Host Snapshot Collection

Collect host-side provenance before target collection.

## Collects

- host OS
- adb version
- emulator version
- AVD name
- pseudonymous target ID (a transport serial may be used transiently but must
  never be written to the portable manifest)
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

Preserve provenance with
`collector/schema/collection_manifest_v1_0_0.schema.json`. Host, ADB, app, and
root observers use this same contract; observed artifacts are bound by relative
path, byte size, and SHA-256. Reports without portable provenance are not
suitable for reproducible comparison.
