# E03 Writable System AVD

## Purpose

Measure signals that change when system or sensitive mounts become writable or overlay-backed.

## Target

AVD configured for writable system experiments.

## Preconditions

- Baseline report exists.
- Writable-system configuration is documented.

## Controlled change

System or sensitive mount layout becomes writable or overlay-backed.

## Expected signals

- mount flags change
- overlay behavior may appear
- writable sensitive partitions may be detected
- property consistency may change

## Collection procedure

1. Configure writable-system target.
2. Boot target.
3. Collect adb snapshot.
4. Normalize report.
5. Diff against E01 baseline.

## Artifacts produced

- raw report
- normalized report
- trust diff

## Actual result

A synthetic / AVD-limited sample artifact is included in:

- `datasets/samples/writable_system_avd/raw_sample.txt`
- `datasets/samples/writable_system_avd/E03_writable_system_avd__observer-adb__sample.json`

The generated diff is included in:

- `results/diffs/stock_vs_writable_system.json`

The sample demonstrates analyzer handling of overlay-backed and writable sensitive mount signals.

## Diff summary

Mount integrity dimensions change when compared to the stock AVD sample. The generated diff is limited to virtual-target evidence.

## Limitations

AVD writable-system behavior is not the same as OEM physical-device AVB behavior.

## Status

Sample artifact included. Physical-device validation is not claimed.
