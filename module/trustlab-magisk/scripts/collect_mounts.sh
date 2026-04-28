#!/system/bin/sh
printf '=== MOUNT ===\n'
mount 2>/dev/null | grep -E ' on /(system|vendor|product|system_ext|odm|data|apex)( |/)' || true
exit 0
