#!/system/bin/sh
MODDIR=${0%/*}
REPORT_SCRIPT="$MODDIR/scripts/write_report.sh"

if [ ! -x "$REPORT_SCRIPT" ]; then
  echo "Android Trust Lab: write_report.sh is missing or not executable"
  exit 1
fi

"$REPORT_SCRIPT" "magisk_module_manual"
exit $?
