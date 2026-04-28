# Summary Table

This table is generated from checked-in sample reports. Current samples are synthetic / AVD-limited and do not support physical-device boot-chain claims.

| experiment | target | observer | method | root | magisk | selinux | writable sensitive mounts | overlay | verified boot | bootloader locked | confidence | status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| E01_stock_avd | avd | adb_shell | adb_shell_snapshot | absent | absent | enforcing | none | false | green | 1 | low | sample |
| E02_rooted_avd | avd | adb_shell | synthetic_rooted_adb_snapshot | present | absent | enforcing | none | false | green | 1 | low | sample |
| E02_rooted_avd | avd | root_collector | synthetic_root_collector_snapshot | present | absent | enforcing | none | false | green | 1 | low | sample |
| E03_writable_system_avd | avd | adb_shell | synthetic_writable_system_snapshot | absent | absent | enforcing | /system | true | green | 1 | low | sample |
| E05_magisk_collector | avd | root_collector | magisk_module_manual | present | present | enforcing | none | false | green | 1 | low | sample |
