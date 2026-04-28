# E02 Rooted AVD

## Purpose

Measure trust-state changes when root becomes available on a virtual target.

## Target

Rooted AVD or equivalent rooted virtual target.

## Preconditions

- Root access is intentionally available.
- Collection is authorized.
- Baseline stock report exists.

## Controlled change

Root access becomes available.

## Expected signals

- `su` availability may change.
- uid/gid may change under root collection.
- SELinux mode may differ.
- mounts may differ.
- properties may differ.
- process visibility may differ.

## Collection procedure

1. Start rooted target.
2. Wait for boot completion.
3. Collect adb snapshot.
4. Collect root snapshot if available.
5. Normalize reports.
6. Diff against E01 baseline.
7. Diff adb observer and root observer reports separately to isolate observer privilege changes.

## Artifacts produced

- raw adb report
- root report
- normalized adb report
- normalized root report
- diff against stock baseline
- observer-boundary diff

## Actual result

Synthetic / AVD-limited sample artifacts are included in:

- `datasets/samples/rooted_avd/raw_adb_sample.txt`
- `datasets/samples/rooted_avd/raw_root_sample.txt`
- `datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json`
- `datasets/samples/rooted_avd/E02_rooted_avd__observer-root__sample.json`

The generated result set separates target mutation from observer privilege:

- `results/diffs/stock_adb_vs_rooted_adb.json`
- `results/diffs/rooted_adb_vs_rooted_root.json`

## Diff summary

The stock-to-rooted adb comparison isolates target-state changes. The rooted adb-to-root comparison isolates observer privilege and root-side visibility changes.

## Limitations

Virtual root behavior is not physical-device boot-chain evidence. Hardware-backed boot conclusions remain out of scope.

## Status

Sample artifacts included. Physical-device validation is not claimed.
