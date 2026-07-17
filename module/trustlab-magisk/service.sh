#!/system/bin/sh
MODDIR=${0%/*}
REPORT_SCRIPT="$MODDIR/scripts/write_report.sh"

# Late boot collector. One report, then exit. No daemon, no mutation.
BOOT_VALUE=unknown
BOOT_QUERY_FAILED=0
BOOT_WAIT_FAILED=0

# Invoked through trap(1), which ShellCheck cannot resolve statically.
# shellcheck disable=SC2329
boot_wait_interrupted() {
  # Reset inherited dispositions before launching the recovery writer. A
  # second signal must remain deliverable to write_report.sh so it can publish
  # an explicit partial collection instead of becoming uninterruptible.
  trap - HUP INT TERM
  printf 'Android Trust Lab: boot_wait_interrupted\n' >&2
  if [ -x "$REPORT_SCRIPT" ]; then
    sh "$REPORT_SCRIPT" "magisk_module_boot" "interrupted"
  fi
  exit 130
}
trap 'boot_wait_interrupted' HUP INT TERM

read_boot_completion() {
  BOOT_QUERY_OUTPUT=$(getprop sys.boot_completed 2>&1)
  BOOT_QUERY_STATUS=$?
  if [ "$BOOT_QUERY_STATUS" -ne 0 ]; then
    BOOT_VALUE=unknown
    BOOT_QUERY_FAILED=1
    return
  fi
  case "$BOOT_QUERY_OUTPUT" in
    0|1) BOOT_VALUE=$BOOT_QUERY_OUTPUT ;;
    *) BOOT_VALUE=unknown; BOOT_QUERY_FAILED=1 ;;
  esac
}

count=0
read_boot_completion
while [ "$BOOT_VALUE" != "1" ] && [ "$count" -lt 120 ]; do
  if ! sleep 1; then
    BOOT_WAIT_FAILED=1
    break
  fi
  count=$((count + 1))
  read_boot_completion
done

if [ ! -x "$REPORT_SCRIPT" ]; then
  printf 'Android Trust Lab: write_report.sh is missing or not executable\n' >&2
  exit 1
fi

BOOT_RESULT=complete
if [ "$BOOT_VALUE" != "1" ]; then
  BOOT_RESULT=timeout
  if [ "$BOOT_WAIT_FAILED" -eq 1 ]; then
    printf 'Android Trust Lab: boot_wait_error\n' >&2
  fi
  if [ "$BOOT_QUERY_FAILED" -eq 1 ]; then
    printf 'Android Trust Lab: boot_query_error\n' >&2
  fi
  printf 'Android Trust Lab: boot_timeout\n' >&2
fi

# Do not discard collector output or errors.  write_report.sh itself exposes
# only the final manifest path plus fixed, sanitized diagnostics.
trap - HUP INT TERM
sh "$REPORT_SCRIPT" "magisk_module_boot" "$BOOT_RESULT"
exit $?
