# Cross-observer evidence matrix

Generated from one project-authored synthetic target state. This is not an AVD capture and does not represent physical OEM behavior.

Shared experimental protocol: `atl_cross_observer_v1`; experiment: `E35_cross_observer`; state: `state-e35-cross-observer-rooted-avd`.
Observer visibility protocols remain distinct (`app`, `adb`, and `root`) by design.

| Dimension | App sandbox | ADB shell | Root collector |
|---|---|---|---|
| Verified Boot state (`verified_boot_state`) | not_collected | green | green |
| SELinux policy mode (`selinux_mode`) | not_collected | enforcing | permissive |
| SELinux current context (`selinux_current_context`) | inaccessible | u:r:shell:s0 | u:r:magisk:s0 |
| Sensitive mount integrity (`mount_integrity`) | writable=not_collected; overlay=not_collected | writable=none; overlay=false | writable=none; overlay=false |
| su binary visibility (`su_binary_visibility`) | not_collected | present | present |
| Root shell availability (`root_shell_availability`) | not_collected | not_collected | present |
| Magisk binary visibility (`magisk_binary_visibility`) | not_collected | not_collected | present |
| Emulator state (`emulator_state`) | True | True | True |

All three pairwise diffs classify as `same_state_observer_change`. App-inaccessible SELinux context becomes `context_change`, not regression. The ADB/root SELinux-mode disagreement remains a provenance-bound, moderate-confidence contradiction.
