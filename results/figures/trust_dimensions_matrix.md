# Trust Dimensions Matrix

This matrix is generated from sample reports for classes A-D. Classes E-F are intentionally unclaimed until physical-device artifacts exist.

| Dimension | Class A stock virtual | Class B rooted virtual | Class C writable modified | Class D Magisk collector | Class E physical baseline | Class F physical rooted |
|---|---|---|---|---|---|---|
| bootloader_lock_state | 1 | 1 | 1 | 1 | not collected | not collected |
| verified_boot_state | green | green | green | green | not collected | not collected |
| vbmeta_state | locked | locked | locked | locked | not collected | not collected |
| verity_mode | enforcing | enforcing | enforcing | enforcing | not collected | not collected |
| selinux_mode | enforcing | enforcing | enforcing | enforcing | not collected | not collected |
| mount_integrity | writable=none; overlay=false | writable=none; overlay=false | writable=/system; overlay=true | writable=none; overlay=false | not collected | not collected |
| root_presence | absent | present | absent | present | not collected | not collected |
| magisk_presence | absent | absent | absent | present | not collected | not collected |
| property_consistency | {"ro.adb.secure": "1", "ro.debuggable": "0", "ro.secure": "1", "sys.boot_completed": "1"} | {"ro.adb.secure": "1", "ro.debuggable": "0", "ro.secure": "1", "sys.boot_completed": "1"} | {"ro.adb.secure": "1", "ro.debuggable": "0", "ro.secure": "1", "sys.boot_completed": "1"} | {"ro.adb.secure": "1", "ro.debuggable": "0", "ro.secure": "1", "sys.boot_completed": "1"} | not collected | not collected |
| observer_privilege | shell | shell | shell | root | not collected | not collected |
