# Trust Dimensions Matrix

This matrix is generated from sample reports for classes A-D. Classes E-F are intentionally unclaimed until physical-device artifacts exist.

| Dimension | Class A stock virtual | Class B rooted virtual | Class C writable modified | Class D Magisk collector | Class E physical baseline | Class F physical rooted |
|---|---|---|---|---|---|---|
| Bootloader lock state (`bootloader_lock_state`) | 1 | 1 | 1 | 1 | not_collected | not_collected |
| Verified Boot state (`verified_boot_state`) | green | green | green | green | not_collected | not_collected |
| vbmeta device state (`vbmeta_state`) | locked | locked | locked | locked | not_collected | not_collected |
| dm-verity mode (`verity_mode`) | enforcing | enforcing | enforcing | enforcing | not_collected | not_collected |
| SELinux policy mode (`selinux_mode`) | enforcing | enforcing | enforcing | enforcing | not_collected | not_collected |
| Sensitive mount integrity (`mount_integrity`) | writable=none; overlay=false | writable=none; overlay=false | writable=/system; overlay=true | writable=none; overlay=false | not_collected | not_collected |
| Root shell availability (`root_shell_availability`) | not_collected | not_collected | not_collected | present | not_collected | not_collected |
| Magisk binary visibility (`magisk_binary_visibility`) | not present | not present | not present | present | not_collected | not_collected |
| Security property consistency (`property_consistency`) | {"ro.adb.secure": "1", "ro.debuggable": "0", "ro.secure": "1", "sys.boot_completed": "1"} | {"ro.adb.secure": "1", "ro.debuggable": "0", "ro.secure": "1", "sys.boot_completed": "1"} | {"ro.adb.secure": "1", "ro.debuggable": "0", "ro.secure": "1", "sys.boot_completed": "1"} | {"ro.adb.secure": "1", "ro.debuggable": "0", "ro.secure": "1", "sys.boot_completed": "1"} | not_collected | not_collected |
