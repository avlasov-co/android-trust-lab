#!/system/bin/sh
VALUE=$(getprop sys.boot_completed 2>/dev/null)
STATUS=$?
case "$VALUE" in 0|1) ;; *) VALUE=unknown ;; esac
cat <<EOF
=== BOOT_STATE ===
sys.boot_completed=$VALUE
EOF
[ "$STATUS" -eq 0 ] || exit 12
exit 0
