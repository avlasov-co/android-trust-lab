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
adb shell mount
adb shell id
adb shell getenforce
adb shell pidof init adbd zygote zygote64 system_server magisk magiskd
adb shell ls -Z / /system /vendor /data 2>/dev/null || true
```

## Rule

Every collected command must map to a trust dimension. Do not collect unrelated
command output. In particular, do not collect the kernel command line, broad
property dumps, or full process command lines. Treat the raw artifact as private
and redact unique identifiers before it leaves the authorized lab target.

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
