# ADB Snapshot Collection

ADB collection records shell-visible trust-state signals.

## Commands

```bash
adb shell getprop
adb shell mount
adb shell id
adb shell getenforce
adb shell cat /proc/cmdline
adb shell ps
adb shell ps -AZ || true
adb shell ls -Z / /system /vendor /data 2>/dev/null || true
```

## Rule

Every collected command must map to a trust dimension. Do not collect unrelated command output.

## Suggested raw artifact format

Use section markers:

```text
=== GETPROP ===
[key]: [value]
=== MOUNT ===
...
=== ID ===
uid=2000(shell) gid=2000(shell)
=== GETENFORCE ===
Enforcing
```
