#!/system/bin/sh
printf '=== GETPROP ===\n'
getprop 2>/dev/null | grep -E '^\[(ro\.boot\.|ro\.build\.|ro\.product\.|ro\.crypto\.|ro\.debuggable|ro\.secure|ro\.adb\.secure|sys\.boot_completed)' || true
exit 0
