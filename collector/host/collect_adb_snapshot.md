# ADB Snapshot Collection

ADB collection records shell-visible trust-state signals.

## Commands

```bash
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.flash.locked
adb shell getprop ro.boot.vbmeta.device_state
adb shell getprop ro.boot.veritymode
adb shell getprop ro.build.fingerprint
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.device
adb shell getprop ro.product.manufacturer
adb shell getprop ro.product.model
adb shell getprop ro.debuggable
adb shell getprop ro.secure
adb shell getprop ro.adb.secure
adb shell getprop sys.boot_completed
adb shell cat /proc/self/mountinfo
adb shell cat /proc/mounts
adb shell mount
adb shell id
adb shell getenforce
adb shell id -Z
adb shell ps -A -o LABEL,NAME
```

## Rule

Every collected command must map to a trust dimension. Do not collect unrelated
command output. In particular, do not collect the kernel command line, broad
property dumps, or full process command lines. Treat the raw artifact as private
and redact unique identifiers before it leaves the authorized lab target.
Project process evidence to the exact selected names `init`, `adbd`, `zygote`,
`zygote64`, `system_server`, `magisk`, and `magiskd` before publication. Retain
only the selected name, a sanitized SELinux domain when available, capture
status, scope, and a relative evidence reference; never publish PIDs, users, or
command arguments. A filtered process list cannot prove that an unlisted process
does not exist.

Publish collection provenance with
`collector/schema/collection_manifest_v1_0_0.schema.json`. Record each command
or probe as a distinct artifact outcome; a command that did not run is
`not_collected`, not an empty observed file. Only relative artifact paths may be
published.

During normalization, validated `adb_shell` manifest metadata selects the ADB
typed adapter for the exact integrity-bound raw report. Inline capture imports
may instead use `artifact_collection_manifest_v1_0_0.schema.json` with
`artifact_kind` set to `adb_collection_manifest`.

## Suggested raw artifact format

Use section markers:

```text
=== GETPROP ===
[key]: [value]
=== MOUNTINFO ===
...complete /proc/self/mountinfo output...
=== PROC_MOUNTS ===
...complete /proc/mounts output...
=== MOUNT ===
...
=== ID ===
uid=2000(shell) gid=2000(shell)
=== GETENFORCE ===
Enforcing
=== SELINUX_CONTEXT ===
u:r:shell:s0
=== PS_SELECTED ===
u:r:init:s0 init
u:r:zygote:s0 zygote64
```

Keep each mount source separate and retain its command outcome. The analyzer
prefers mountinfo, then `/proc/mounts`, then common `mount` output regardless of
manifest array order. Do not filter to only familiar paths: system-as-root,
dynamic partitions, APEX package sets, bind/overlay context, propagation, and
mount-namespace topology depend on complete records.
