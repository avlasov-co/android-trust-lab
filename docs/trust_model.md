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
- `selinux_current_context`
- `selinux_denial_collection`
- `selected_process_visibility`
- `mount_integrity`
- `system_mount_resolution`
- `dynamic_partition_state`
- `apex_mount_set`
- `observer_uid_root`
- `root_shell_availability`
- `su_binary_visibility`
- `su_invocation_tested`
- `su_invocation_result`
- `root_management_artifact`
- `magisk_binary_visibility`
- `magisk_daemon_visibility`
- `magisk_process_visibility`
- `zygisk_visibility`
- `magisk_version_name`
- `magisk_version_code`
- `magisk_module_context`
- `magisk_command_status`
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
- allowlisted boot properties (not raw kernel command-line contents)
- mount table
- SELinux tools and contexts
- process table
- filesystem paths
- adb shell
- app-visible Android APIs
- root collector output
- host provenance data

## Supported observer types

| Observer | Description |
|---|---|
| host | Host-side experiment observer |
| adb_shell | Android shell observer through adb |
| unprivileged_app | Normal app sandbox observer |
| root_collector | Privileged read-only collector |

Boot/kernel-level evidence is a signal source when available; it is not a
standalone observer ID in the current report schema or analyzer registry.

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
- Process nonexistence is claimed only from a complete, supported full table;
  filtered, partial, inaccessible, and app-sandbox views remain inconclusive.
- Portable process evidence excludes PIDs, users, and command arguments; SELinux
  contexts exclude per-app MLS/MCS categories.
- Portable evidence uses semantic references, fixed property grammars, withheld
  mount text, non-source-derived category labels, and deterministic APEX
  ordinals before report identity is calculated.
- Confidence is derived from source quality, command success, observer
  capability, corroboration, and target limitations. Target type alone never
  assigns a confidence level.
- A changed signal is not automatically a security failure. It is an observed transition.
- Writable, overlay, and bind mount facts are contextual observations; no one
  mount fact is a platform-integrity verdict without target, namespace, and
  observer context.
