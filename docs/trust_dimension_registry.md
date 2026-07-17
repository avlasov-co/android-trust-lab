# Trust Dimension Registry

This file is generated from the validated, versioned trust-dimension registry. Do not edit it by hand.

All measured dimensions currently support report schema `6.0.0`, use the `nested_path_v1` extractor and `canonical_equality_v1` comparator, expect statuses `observed`, `observed_absent`, `inaccessible`, `not_collected`, `command_error`, `unsupported`, and use the `factorized_evidence_v1` confidence policy.

Contextual dimensions support report schema `6.0.0`, remain disabled by default, have no fabricated evidence path, and return only the canonical `not_collected` sentinel.

## Dimensions

| Stable ID | Title | Category | Evidence path | Materiality | Direction rule | Renderer | Matrix order |
|---|---|---|---|---|---|---|---|
| `bootloader_lock_state` | Bootloader lock state | `boot_integrity` | `verified_boot.flash_locked` | `high` | `ordered_bootloader_lock_v1` | `evidence_v1` | 1 |
| `verified_boot_state` | Verified Boot state | `boot_integrity` | `verified_boot.verified_boot_state` | `high` | `ordered_verified_boot_v1` | `evidence_v1` | 2 |
| `vbmeta_state` | vbmeta device state | `boot_integrity` | `verified_boot.vbmeta_device_state` | `high` | `ordered_vbmeta_state_v1` | `evidence_v1` | 3 |
| `verity_mode` | dm-verity mode | `boot_integrity` | `verified_boot.verity_mode` | `high` | `ordered_verity_mode_v1` | `evidence_v1` | 4 |
| `selinux_mode` | SELinux policy mode | `mandatory_access_control` | `selinux.policy_mode` | `high` | `ordered_selinux_mode_v1` | `evidence_v1` | 5 |
| `selinux_current_context` | SELinux current context | `mandatory_access_control` | `selinux.current_context` | `moderate` | `indeterminate_v1` | `evidence_v1` | — |
| `selinux_denial_collection` | SELinux denial collection | `mandatory_access_control` | `selinux.denial_collection` | `low` | `indeterminate_v1` | `evidence_v1` | — |
| `selected_process_visibility` | Selected process visibility | `process_visibility` | `process_state.selected_processes` | `moderate` | `indeterminate_v1` | `evidence_v1` | — |
| `mount_integrity` | Sensitive mount integrity | `mount_integrity` | `mounts.integrity_summary` | `high` | `ordered_mount_integrity_v1` | `mount_integrity_v1` | 6 |
| `system_mount_resolution` | System mount resolution | `mount_integrity` | `mounts.system_resolution` | `moderate` | `indeterminate_v1` | `evidence_v1` | — |
| `dynamic_partition_state` | Dynamic partition state | `mount_integrity` | `mounts.dynamic_partitions` | `low` | `indeterminate_v1` | `evidence_v1` | — |
| `apex_mount_set` | APEX mount set | `mount_integrity` | `mounts.apex_set` | `moderate` | `indeterminate_v1` | `evidence_v1` | — |
| `root_shell_availability` | Root shell availability | `root_visibility` | `root_state.root_shell_available` | `moderate` | `indeterminate_v1` | `presence_v1` | 7 |
| `su_binary_visibility` | su binary visibility | `root_visibility` | `root_state.su_binary_observed` | `moderate` | `indeterminate_v1` | `presence_v1` | — |
| `su_invocation_tested` | su invocation tested | `root_visibility` | `root_state.su_invocation_tested` | `low` | `indeterminate_v1` | `evidence_v1` | — |
| `su_invocation_result` | su invocation result | `root_visibility` | `root_state.su_invocation_result` | `moderate` | `indeterminate_v1` | `evidence_v1` | — |
| `root_management_artifact` | Root-management artifact | `root_visibility` | `root_state.root_management_artifact_observed` | `moderate` | `indeterminate_v1` | `presence_v1` | — |
| `magisk_binary_visibility` | Magisk binary visibility | `magisk_visibility` | `magisk_state.binary_visibility` | `moderate` | `indeterminate_v1` | `presence_v1` | 8 |
| `magisk_daemon_visibility` | Magisk daemon visibility | `magisk_visibility` | `magisk_state.daemon_visibility` | `moderate` | `indeterminate_v1` | `presence_v1` | — |
| `magisk_process_visibility` | Magisk process visibility | `magisk_visibility` | `magisk_state.process_visibility` | `moderate` | `indeterminate_v1` | `presence_v1` | — |
| `zygisk_visibility` | Zygisk visibility | `magisk_visibility` | `magisk_state.zygisk_visibility` | `moderate` | `indeterminate_v1` | `presence_v1` | — |
| `magisk_version_name` | Magisk version name | `magisk_visibility` | `magisk_state.version_name` | `informational` | `indeterminate_v1` | `evidence_v1` | — |
| `magisk_version_code` | Magisk version code | `magisk_visibility` | `magisk_state.version_code` | `informational` | `indeterminate_v1` | `evidence_v1` | — |
| `magisk_module_context` | Magisk module context | `magisk_visibility` | `magisk_state.module_context` | `informational` | `indeterminate_v1` | `evidence_v1` | — |
| `magisk_command_status` | Magisk command status | `magisk_visibility` | `magisk_state.command_status` | `low` | `indeterminate_v1` | `evidence_v1` | — |
| `property_consistency` | Security property consistency | `properties` | `properties.security` | `moderate` | `indeterminate_v1` | `property_map_v1` | 9 |
| `emulator_state` | Emulator state | `environment` | `emulator_state.is_emulator` | `informational` | `indeterminate_v1` | `evidence_v1` | — |
| `app_visible_state` | App-visible state | `app_visibility` | `extensions.org.androidtrustlab.app-probe` | `informational` | `indeterminate_v1` | `evidence_v1` | — |
| `physical_device_state` | Physical-device state | `contextual` | `—` | `informational` | `context_only_v1` | `not_applicable_v1` | — |
| `root_visible_state` | Root-visible state | `contextual` | `—` | `informational` | `context_only_v1` | `not_applicable_v1` | — |

## Descriptions and interpretation

| Stable ID | Description | Interpretation |
|---|---|---|
| `bootloader_lock_state` | Property-backed evidence describing whether the bootloader reports a locked state. | Bootloader lock evidence changed. On virtual targets this is property evidence only, not hardware-backed proof. |
| `verified_boot_state` | Observed Android Verified Boot state property evidence. | Verified boot property evidence changed. Emulator evidence remains limited for hardware-backed conclusions. |
| `vbmeta_state` | Observed vbmeta device-state property evidence. | vbmeta device-state evidence changed. Interpret according to target class and observer. |
| `verity_mode` | Observed dm-verity-related operating mode evidence. | dm-verity-related property evidence changed. |
| `selinux_mode` | Observed SELinux enforcement mode. | SELinux mode changed. This affects runtime MAC boundary interpretation. |
| `selinux_current_context` | Observer-scoped SELinux execution context evidence. | Observer SELinux context visibility changed. This is scoped evidence, not complete policy inspection. |
| `selinux_denial_collection` | Collection outcome for SELinux denial evidence. | SELinux denial collection status changed; compare collection scope before interpreting absence. |
| `selected_process_visibility` | Status-aware visibility and sanitized contexts for the selected process set. | Selected process visibility or sanitized contexts changed. Inconclusive scoped evidence is distinct from observed absence. |
| `mount_integrity` | Derived writable-sensitive-mount and overlay evidence. | Sensitive mount state changed. Review raw mount evidence before making any platform-integrity conclusion. |
| `system_mount_resolution` | Resolved Android system-root mount classification. | The resolved Android system root changed. Review the referenced mount records and source quality. |
| `dynamic_partition_state` | Derived dynamic-partition layout evidence. | Dynamic-partition evidence changed. This records layout evidence, not an integrity verdict. |
| `apex_mount_set` | Sanitized set of observed APEX package mounts. | The observed APEX package mount set changed. Review capture completeness and package mount records. |
| `root_shell_availability` | Direct evidence that a root shell was available to the observer. | Trust-state dimension changed between reports. |
| `su_binary_visibility` | Direct observer-scoped visibility of an su binary. | Trust-state dimension changed between reports. |
| `su_invocation_tested` | Evidence that an su invocation was attempted. | Trust-state dimension changed between reports. |
| `su_invocation_result` | Direct result of an attempted su invocation. | Trust-state dimension changed between reports. |
| `root_management_artifact` | Direct visibility of a root-management artifact. | Trust-state dimension changed between reports. |
| `magisk_binary_visibility` | Direct observer-scoped visibility of the Magisk binary. | Trust-state dimension changed between reports. |
| `magisk_daemon_visibility` | Direct observer-scoped visibility of the Magisk daemon. | Trust-state dimension changed between reports. |
| `magisk_process_visibility` | Direct observer-scoped visibility of a Magisk process. | Trust-state dimension changed between reports. |
| `zygisk_visibility` | Observer-scoped visibility of a Zygisk indicator. | Trust-state dimension changed between reports. |
| `magisk_version_name` | Sanitized Magisk version-name evidence. | Trust-state dimension changed between reports. |
| `magisk_version_code` | Sanitized Magisk numeric version-code evidence. | Trust-state dimension changed between reports. |
| `magisk_module_context` | Sanitized Magisk module-context evidence. | Trust-state dimension changed between reports. |
| `magisk_command_status` | Collection outcome for the Magisk command probe. | Trust-state dimension changed between reports. |
| `property_consistency` | Allowlisted security-relevant property group evidence. | Security-relevant property group changed. This does not imply bypass by itself. |
| `emulator_state` | Evidence that the target is an emulator or virtual device. | Trust-state dimension changed between reports. |
| `app_visible_state` | Typed evidence measured directly by the public-API unprivileged app probe. | App-visible evidence changed; interpret the transition in its observer and capability context. |
| `physical_device_state` | Reserved context dimension for direct physical-device evidence. | Physical-device state is unavailable until direct supporting payloads are present. |
| `root_visible_state` | Reserved context dimension for a future direct root-probe payload. | Root-visible state is unavailable until a direct root-probe payload is present. |
