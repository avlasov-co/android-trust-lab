# E01 Stock AVD

## Purpose

Collect a trust snapshot from a clean stock Android Virtual Device.

## Target

Stock AVD.

## Preconditions

- AVD boots cleanly.
- adb is available.
- No root collector is installed.

## Controlled change

None. This is the virtual baseline.

## Expected signals

- baseline getprop values
- baseline mount layout
- SELinux state available
- adb shell uid/gid visible
- emulator indicators present
- boot properties visible in virtual target

## Collection procedure

1. Start AVD.
2. Wait for boot completion.
3. Collect host snapshot.
4. Collect adb snapshot.
5. Normalize report.
6. Validate report.

## Artifacts produced

- raw adb report
- normalized report
- validation result

## Actual result

A synthetic / AVD-limited sample artifact is included in:

- `datasets/samples/stock_avd/raw_sample.txt`
- `datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json`

The sample establishes a virtual baseline with `adb_shell` observer visibility, shell privilege, SELinux enforcing state, no root shell availability, and emulator indicators present.

## Diff summary

Baseline experiment. No diff is required by itself. Generated comparison artifacts use this report as the base for rooted and writable-system virtual target comparisons.

## Limitations

Emulator target. No hardware-backed boot conclusion is claimed. The sample validates analyzer behavior and report structure only.

## Status

Sample artifact included. Physical-device validation is not claimed.
