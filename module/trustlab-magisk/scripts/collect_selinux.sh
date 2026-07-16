#!/system/bin/sh
printf '=== GETENFORCE ===\n'
getenforce 2>/dev/null || printf 'unknown\n'
printf '=== SELINUX_CONTEXTS ===\n'
id -Z 2>/dev/null || true
ls -Zd / /system /vendor /data 2>/dev/null || true
exit 0
