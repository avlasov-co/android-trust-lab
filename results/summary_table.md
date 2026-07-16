# Summary Table

This table is generated from checked-in sample reports. Current samples are synthetic / AVD-limited and do not support physical-device boot-chain claims.

| experiment | target | observer | method | Root shell availability | Magisk binary visibility | SELinux policy mode | Sensitive mount integrity: writable sensitive mounts | Sensitive mount integrity: overlay | Verified Boot state | Bootloader lock state | confidence | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| E01_stock_avd | avd | adb_shell | adb_shell_snapshot | not_collected | not present | enforcing | none | false | green | 1 | low | sample |
| E02_rooted_avd | avd | adb_shell | synthetic_rooted_adb_snapshot | not_collected | not present | enforcing | none | false | green | 1 | low | sample |
| E02_rooted_avd | avd | root_collector | synthetic_root_collector_snapshot | not_collected | not present | enforcing | none | false | green | 1 | low | sample |
| E03_writable_system_avd | avd | adb_shell | synthetic_writable_system_snapshot | not_collected | not present | enforcing | /system | true | green | 1 | low | sample |
| E05_magisk_collector | avd | root_collector | magisk_module_manual | present | present | enforcing | none | false | green | 1 | low | sample |
