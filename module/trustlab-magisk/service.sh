#!/system/bin/sh
MODDIR=${0%/*}
REPORT_SCRIPT="$MODDIR/scripts/write_report.sh"

# Late boot collector. One report, then exit. No daemon, no mutation.
count=0
while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ] && [ "$count" -lt 120 ]; do
  sleep 1
  count=$((count + 1))
done

if [ -x "$REPORT_SCRIPT" ]; then
  "$REPORT_SCRIPT" "magisk_module_boot" >/dev/null 2>&1
fi

exit 0
