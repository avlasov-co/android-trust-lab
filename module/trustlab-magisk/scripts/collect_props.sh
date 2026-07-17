#!/system/bin/sh
# Exact match for the reviewed host/ADB property allowlist.  Invalid values are
# projected to a fixed token before they enter retained evidence.
printf '=== GETPROP ===\n'
COLLECTION_STATUS=0
for KEY in \
  ro.boot.verifiedbootstate \
  ro.boot.flash.locked \
  ro.boot.vbmeta.device_state \
  ro.boot.veritymode \
  ro.build.version.release \
  ro.build.version.sdk \
  ro.debuggable \
  ro.secure \
  ro.adb.secure \
  sys.boot_completed \
  ro.kernel.qemu
do
  VALUE=$(getprop "$KEY" 2>/dev/null)
  GETPROP_STATUS=$?
  [ "$GETPROP_STATUS" -eq 0 ] || COLLECTION_STATUS=12
  VALID=0
  case "$KEY" in
    ro.boot.verifiedbootstate)
      case "$VALUE" in green|yellow|orange|red) VALID=1 ;; esac ;;
    ro.boot.flash.locked|ro.debuggable|ro.secure|ro.adb.secure|sys.boot_completed|ro.kernel.qemu)
      case "$VALUE" in 0|1) VALID=1 ;; esac ;;
    ro.boot.vbmeta.device_state)
      case "$VALUE" in locked|unlocked) VALID=1 ;; esac ;;
    ro.boot.veritymode)
      case "$VALUE" in enforcing|eio|logging|disabled) VALID=1 ;; esac ;;
    ro.build.version.release)
      printf '%s\n' "$VALUE" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){0,3}$' && VALID=1 ;;
    ro.build.version.sdk)
      printf '%s\n' "$VALUE" | grep -Eq '^[0-9]{1,3}$' && VALID=1 ;;
  esac
  [ "$VALID" -eq 1 ] || VALUE=unknown
  printf '[%s]: [%s]\n' "$KEY" "$VALUE"
done
exit "$COLLECTION_STATUS"
