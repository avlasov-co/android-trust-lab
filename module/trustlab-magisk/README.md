# Android Trust Lab Magisk Collector

This module is a read-only privileged collector for Android Trust Lab. It does not change system behavior.

It does not:

- modify properties
- patch SELinux
- remount partitions
- mount overlays
- hide root
- spoof identity
- evade security checks
- run a persistent daemon

## Installation

Package the folder as a Magisk module zip using `tools/package_magisk_module.md` instructions or any normal zip process preserving the module root.

## Boot-time collection

`service.sh` waits for `sys.boot_completed=1`, writes one report, and exits.

## Manual collection

Run the module action from Magisk or execute:

```bash
su -c /data/adb/modules/androidtrustlab/action.sh
```

## Output path

```text
/data/local/tmp/android-trust-lab/reports/
```

## Uninstall behavior

`uninstall.sh` removes internal temporary files and preserves exported reports.

## Limitations

Root-side visibility is not hardware-backed trust proof. Label reports as `root_collector` and compare them against adb/app observers instead of assuming all observers have equivalent visibility.

## Packaging note

This module is intended for installation through the Magisk app. The MVP intentionally does not include `META-INF/` recovery-installer files. If recovery flashing is ever supported later, it must use the official Magisk module installer flow and keep the same read-only safety boundaries.

The on-device JSON written by the module is a collection manifest, not a normalized trust report. The raw text artifact must be normalized with the host analyzer before it is compared against `trust_report.schema.json`.
