#!/system/bin/sh
printf '=== PS ===\n'
PATTERN='(^|[[:space:]])(init|adbd|zygote|zygote64|system_server|magisk|magiskd)($|[[:space:]])'
ps -AZ 2>/dev/null | grep -E "$PATTERN" || ps 2>/dev/null | grep -E "$PATTERN" || true
exit 0
