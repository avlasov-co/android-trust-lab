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

Package the folder only with the repository helper documented in
`tools/package_magisk_module.md`. It normalizes entry modes and ZIP metadata,
validates the closed payload, builds twice, compares exact bytes, and prints the
published archive SHA-256. A generic ZIP command is not an equivalent build.

## Boot-time collection

`service.sh` waits up to 120 seconds for `sys.boot_completed=1`, writes one
report, and exits. A timeout is retained as structured `timed_out` provenance
and produces an honest partial collection instead of being treated as boot
completion. An interruption during the boot wait is likewise handed to the
writer as an explicit partial outcome.

## Manual collection

Run the module action from the Magisk app. Android Trust Lab does not invoke or
recommend an interactive `su` workflow.

## Output path

```text
/data/adb/android-trust-lab/reports/run_<UTC>_<16-hex-nonce>/
```

The base, report, capture, event, and lock directories are mode `0700`; every
retained file is mode `0600`, under `umask 077`. A portable atomic-directory
lock serializes collection. Work is retained in a hidden same-filesystem staging
directory, and a fresh final directory becomes a collection only when its
non-replacing `collector_manifest.json` completion marker is linked last.
The ephemeral private lock owner binds a PID and process-start tick, allowing a
definitively dead owner to be recovered without stealing a live lock. Empty
ownerless lock and recovery directories are reclaimed only after a conservative
five-minute quarantine; fresh locks and unknown contents are never removed.

Each collection contains the projected `raw.txt`, per-probe `captures/`,
`command_results.json`, a sanitized `collector.log`, and the strict manifest.
All observed files have a manifest-bound byte size and SHA-256 digest. The
collector deliberately excludes the kernel command line and uses the exact
reviewed host/ADB property allowlist.

A private, randomly generated `target_pseudonym` file is created once beneath
`/data/adb/android-trust-lab` and reused across runs. It provides stable
pseudonymous target identity without deriving an identifier from a serial or from
changing evidence bytes.

## Uninstall behavior

`uninstall.sh` preserves private reports, fixed runtime-event records, and the
stable private `target_pseudonym`. A normally completed or interrupted run
removes its own lock and staging directory; an uncatchable kill may leave a
hidden, manifest-less staging directory or quarantined lock, never a published
collection.

## Limitations

Root-side visibility is not hardware-backed trust proof. Label reports as `root_collector` and compare them against adb/app observers instead of assuming all observers have equivalent visibility.

## Packaging note

This module is intended for installation through the Magisk app. The MVP intentionally does not include `META-INF/` recovery-installer files. If recovery flashing is ever supported later, it must use the official Magisk module installer flow and keep the same read-only safety boundaries.

The on-device JSON written by the module is a strict portable collection
manifest, not a normalized trust report. It binds every observed artifact by
relative path, size, and SHA-256 and records every required probe outcome.
Normalize it
on the host with `trustlab normalize --manifest collector_manifest.json --output
report.json`. The analyzer parses the exact verified bytes and retains the
manifest digest, full manifest record, and probe outcomes in the normalized
report.

For a complete hardened collection, the default host workflow is `trustlab
import magisk --input COLLECTION_DIR --output PRIVATE_IMPORT_ROOT`. It verifies
and privately copies the closed bundle before normalizing it. The importer never
invokes ADB, `su`, or Magisk. Complete hardened runtime output is accepted;
boot-timeout, interrupted, and other partial output remains available through
explicit generic manifest normalization.

The raw snapshot keeps `getenforce` separate from the collector's own `id -Z`
context. Its `PS_SELECTED` section contains only exact project-selected names
and sanitized process contexts when available. It never publishes PIDs, users,
or command arguments, and an unlisted name in this filtered section is not proof
that the process does not exist.
Command failures use fixed non-sensitive markers so inaccessible, unsupported,
and failed collection remain distinct from a genuinely empty successful section.
