#!/system/bin/sh
printf '=== MOUNTINFO ===\n'
if ! cat /proc/self/mountinfo 2>/dev/null; then
  printf 'Permission denied\n'
fi
printf '=== PROC_MOUNTS ===\n'
if ! cat /proc/mounts 2>/dev/null; then
  printf 'Permission denied\n'
fi
printf '=== MOUNT ===\n'
if ! mount 2>/dev/null; then
  printf 'Command failed\n'
fi
exit 0
