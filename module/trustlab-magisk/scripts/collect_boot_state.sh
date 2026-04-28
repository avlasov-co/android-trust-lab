#!/system/bin/sh
cat <<EOF
=== BOOT_STATE ===
sys.boot_completed=$(getprop sys.boot_completed 2>/dev/null)
ro.boot.bootreason=$(getprop ro.boot.bootreason 2>/dev/null)
ro.boot.slot_suffix=$(getprop ro.boot.slot_suffix 2>/dev/null)
ro.boot.verifiedbootstate=$(getprop ro.boot.verifiedbootstate 2>/dev/null)
ro.boot.flash.locked=$(getprop ro.boot.flash.locked 2>/dev/null)
ro.boot.vbmeta.device_state=$(getprop ro.boot.vbmeta.device_state 2>/dev/null)
ro.boot.veritymode=$(getprop ro.boot.veritymode 2>/dev/null)
EOF
printf 'kernel_cmdline='
cat /proc/cmdline 2>/dev/null || true
printf '\n'
exit 0
