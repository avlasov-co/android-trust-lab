#!/system/bin/sh
printf '=== MAGISK ===\n'
if command -v magisk >/dev/null 2>&1; then
  printf 'magisk_binary_visibility=observed\n'
  VERSION_NAME="$(magisk -v 2>/dev/null)"
  VERSION_NAME_STATUS=$?
  VERSION_CODE="$(magisk -V 2>/dev/null)"
  VERSION_CODE_STATUS=$?
  if [ -n "$VERSION_NAME" ]; then
    printf 'magisk_version_name=redacted-magisk-version-name\n'
  fi
  if printf '%s\n' "$VERSION_CODE" | grep -Eq '^[0-9]{1,12}$'; then
    printf 'magisk_version_code=%s\n' "$VERSION_CODE"
  fi
  if [ "$VERSION_NAME_STATUS" -ne 0 ] || [ "$VERSION_CODE_STATUS" -ne 0 ]; then
    exit 12
  fi
else
  printf 'magisk_binary_visibility=observed_absent\n'
fi
[ -d /data/adb/modules/androidtrustlab ] && printf 'module_context=androidtrustlab\n'
if [ -d /data/adb/zygisk ]; then
  printf 'zygisk_visibility=observed\n'
else
  printf 'zygisk_visibility=observed_absent\n'
fi
exit 0
