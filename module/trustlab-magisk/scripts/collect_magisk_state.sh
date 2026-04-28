#!/system/bin/sh
printf '=== MAGISK ===\n'
if command -v magisk >/dev/null 2>&1; then
  printf 'magisk_path='
  command -v magisk
  printf 'magisk_version='
  magisk -V 2>/dev/null || magisk -v 2>/dev/null || printf 'unknown\n'
else
  printf 'magisk: not found in PATH\n'
fi
[ -d /data/adb/magisk ] && printf 'magisk_data_path=/data/adb/magisk\n'
[ -d /data/adb/modules/androidtrustlab ] && printf 'module_context=androidtrustlab\n'
[ -d /data/adb/zygisk ] && printf 'zygisk_indicator=/data/adb/zygisk\n'
exit 0
