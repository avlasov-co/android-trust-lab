# Android Trust Lab

Android Trust Lab is a reproducible research harness for measuring Android trust-state transitions across controlled system configurations.

It is not a root detector, bypass tool, root-hiding framework, Magisk hiding project, Play Integrity bypass project, SafetyNet bypass project, banking-app bypass project, or DuckDetector clone.

The project studies a narrower and cleaner question:

> How do Android trust-state signals change when an Android target moves between controlled states?

Example states include stock AVD, rooted AVD, writable-system AVD, safe modified-property experiments, an optional read-only Magisk privileged collector, and later physical-device validation.

## Why this exists

Android trust state is not a single boolean. It is distributed across bootloader state, Android Verified Boot, vbmeta, dm-verity, SELinux, mount layout, system properties, root visibility, Magisk visibility, process visibility, app-visible APIs, root-visible signals, and emulator-vs-physical-device differences.

Most casual tooling collapses this into a verdict. Android Trust Lab does not. It records observations, normalizes them into a schema, compares reports, and documents limitations.

## What the framework collects

Android Trust Lab supports several observer classes:

| Observer | Purpose | Example visibility |
|---|---|---|
| host | provenance | host OS, adb version, emulator/AVD metadata |
| adb_shell | shell-level target view | getprop, mounts, id, getenforce, selected process data |
| unprivileged_app | normal app view | Build values, limited filesystem/API state |
| root_collector | privileged read-only snapshot | boot props, mounts, SELinux, Magisk/process state |

The optional Magisk module is only a privileged collector. It does not change system behavior.

## Architecture

```text
host / adb / app / root collector
        ↓
raw artifacts
        ↓
parser
        ↓
normalized trust_report.schema.json
        ↓
diff engine
        ↓
trust_diff.schema.json + markdown summary
```

## Basic virtual-target workflow

```bash
cd analyzer
python -m pip install -e ".[dev]"
cd ..

trustlab normalize   --input tests/fixtures/sample_raw_report.txt   --output /tmp/stock_report.json   --experiment-id E01_stock_avd   --observer adb_shell   --target-type avd

trustlab validate-report /tmp/stock_report.json

trustlab diff   --base datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json   --compare datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json   --output /tmp/root_diff.json

trustlab summarize /tmp/root_diff.json
```

## Example trust-state diff

```json
{
  "dimension": "root_presence",
  "before": false,
  "after": true,
  "severity": "medium",
  "interpretation": "Root-related evidence changed between reports. This is an observation, not an app verdict or bypass claim.",
  "evidence_paths": [
    "root_state.su_present"
  ]
}
```

## Current limitations

This version validates the collection and analysis pipeline on virtual targets. Hardware-backed trust behavior requires physical-device validation.

Emulator data is useful for collector development, schema design, analyzer testing, normalization, diff generation, and CI-friendly samples. It cannot prove OEM bootloader behavior, Qualcomm/Xiaomi boot-chain behavior, TEE behavior, hardware attestation correctness, Widevine/DRM conclusions, vendor/HAL mismatch behavior, Goodix/FOD behavior, or Mi 9-specific conclusions.

## Safety scope

Use this project only on owned devices, test images, AVDs, lab systems, and explicitly authorized targets.

Do not use this repository to bypass security checks, hide root, evade app detection, weaken SELinux, spoof device identity, persist malware, bypass DRM, or attack remote systems.

## References

- Android Verified Boot: https://source.android.com/docs/security/features/verifiedboot/avb
- dm-verity: https://source.android.com/docs/security/features/verifiedboot/dm-verity
- Android SELinux: https://source.android.com/docs/security/features/selinux
- Magisk developer guide: https://topjohnwu.github.io/Magisk/guides.html
