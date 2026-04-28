#!/system/bin/sh
printf '=== GETENFORCE ===\n'
getenforce 2>/dev/null || printf 'unknown\n'
printf '=== SELINUX_CONTEXTS ===\n'
id -Z 2>/dev/null || true
PATTERN='(^|[[:space:]])(init|adbd|zygote|zygote64|system_server|magisk|magiskd)($|[[:space:]])'
ps -AZ 2>/dev/null | grep -E "$PATTERN" || true
ls -Zd / /system /vendor /data 2>/dev/null || true
exit 0
