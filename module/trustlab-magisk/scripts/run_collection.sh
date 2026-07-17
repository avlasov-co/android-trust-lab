#!/system/bin/sh
# Single constrained entry point for boot, Action, and KernelSU WebUI runs.
umask 077

MODDIR=${0%/*}/..
WRITER="$MODDIR/scripts/write_report.sh"
SOURCE=${1:-}

case "$SOURCE" in
  boot) METHOD=magisk_module_boot; BOOT_RESULT=${2:-auto} ;;
  action) METHOD=magisk_module_manual; BOOT_RESULT=auto ;;
  webui) METHOD=magisk_module_webui; BOOT_RESULT=auto ;;
  *)
    printf 'Android Trust Lab: invalid collection source\n' >&2
    exit 64
    ;;
esac

if [ ! -x "$WRITER" ]; then
  printf 'Android Trust Lab: write_report.sh is missing or not executable\n' >&2
  exit 1
fi

exec sh "$WRITER" "$METHOD" "$BOOT_RESULT"
