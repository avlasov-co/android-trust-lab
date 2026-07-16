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
/data/adb/android-trust-lab/reports/run_<timestamp>.<random>/
```

Each exclusive run directory is mode `0700`; `raw.txt` and
`collector_manifest.json` are mode `0600`. The collector deliberately excludes
the kernel command line and non-allowlisted Android properties.

A private, randomly generated `target_pseudonym` file is created once beneath
`/data/adb/android-trust-lab` and reused across runs. It provides stable
pseudonymous target identity without deriving an identifier from a serial or from
changing evidence bytes.

## Uninstall behavior

`uninstall.sh` preserves the private report directories and stable private
`target_pseudonym`. The collector keeps no temporary state outside per-run
directories.

## Limitations

Root-side visibility is not hardware-backed trust proof. Label reports as `root_collector` and compare them against adb/app observers instead of assuming all observers have equivalent visibility.

## Packaging note

This module is intended for installation through the Magisk app. The MVP intentionally does not include `META-INF/` recovery-installer files. If recovery flashing is ever supported later, it must use the official Magisk module installer flow and keep the same read-only safety boundaries.

The on-device JSON written by the module is a strict portable collection
manifest, not a normalized trust report. It binds `raw.txt` by relative path,
size, and SHA-256 and records missing per-command results honestly. Normalize it
on the host with `trustlab normalize --manifest collector_manifest.json --output
report.json`. The analyzer parses the exact verified bytes and retains the
manifest digest, full manifest record, and probe outcomes in the normalized
report.
