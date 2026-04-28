# Trust Model

## Definition

In this project, trust state means the set of observable signals that describe whether an Android target appears to preserve expected platform integrity boundaries from the perspective of a specific observer.

Trust state is not a verdict. It is a structured measurement.

## Trust dimensions

Canonical dimensions:

- `bootloader_lock_state`
- `verified_boot_state`
- `vbmeta_state`
- `verity_mode`
- `selinux_mode`
- `mount_integrity`
- `root_presence`
- `magisk_presence`
- `property_consistency`
- `emulator_state`
- `physical_device_state`
- `app_visible_state`
- `root_visible_state`
- `observer_privilege`

`app_visible_state` and `root_visible_state` are contextual dimensions. They should only be diffed when reports contain real app-probe or root-probe payloads. They must not be inferred only from `observer.observer_type`, because that creates fake signal when the observer changes.

## Signal sources

Signals may come from:

- Android properties
- kernel command line
- mount table
- SELinux tools and contexts
- process table
- filesystem paths
- adb shell
- app-visible Android APIs
- root collector output
- host provenance data

## Observer types

| Observer | Description |
|---|---|
| host | Host-side experiment observer |
| adb_shell | Android shell observer through adb |
| unprivileged_app | Normal app sandbox observer |
| root_collector | Privileged read-only collector |
| boot_kernel | Boot/kernel-level evidence, when available |

## Privilege boundaries

The same target can expose different signals to different observers. A normal app may see Build values but not privileged mount or process context details. A root collector may see richer state, but it also changes the experiment class because a privileged observer exists.

## State classes

- Class A: stock virtual baseline
- Class B: rooted virtual system
- Class C: writable system modified
- Class D: Magisk collector present
- Class E: physical device baseline
- Class F: physical rooted device

## Known ambiguity

Some signals are missing, virtualized, vendor-specific, or observer-dependent. Missing evidence must not be treated as proof of absence unless the collector had permission and a known reliable signal path.

## Normalization rules

- Unknown values stay `unknown`.
- Missing values are recorded in `limitations.collection_errors` or as `unknown`.
- Raw evidence paths are preserved where practical.
- Emulator evidence must carry lower confidence for hardware-backed trust dimensions.
- A changed signal is not automatically a security failure. It is an observed transition.
