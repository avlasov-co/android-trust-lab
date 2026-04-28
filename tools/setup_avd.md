# Setup AVD

## Requirements

- Android SDK platform-tools
- Android emulator
- a system image suitable for testing

## Procedure

1. Create or select a stock AVD.
2. Boot it.
3. Confirm adb connectivity.
4. Record AVD name, Android version, SDK, image, and emulator version.

```bash
adb devices -l
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
```
