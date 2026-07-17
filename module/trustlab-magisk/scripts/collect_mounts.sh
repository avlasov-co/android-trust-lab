#!/system/bin/sh
# Retain only reviewed mount points and field-wise projected values.  The
# runtime never invokes the mount utility and never publishes raw sources,
# device identifiers, optional propagation IDs, or arbitrary paths.
printf '=== MOUNTINFO ===\n'
COLLECTION_STATUS=0
if [ -r /proc/self/mountinfo ]; then
  if ! awk '
    function safe_path(path) {
      if (path == "/" || path == "/system" || path == "/vendor" ||
          path == "/product" || path == "/system_ext" || path == "/odm" ||
          path == "/data" || path == "/apex") return path
      if (path ~ /^\/apex\/[A-Za-z0-9._+-]+$/) return "/apex/redacted-apex"
      return ""
    }
    function safe_fs(value) {
      if (value ~ /^(apex|erofs|ext4|f2fs|overlay|squashfs|tmpfs|vfat|virtiofs)$/)
        return value
      return "unknown"
    }
    {
      separator = 0
      for (field_idx = 7; field_idx <= NF; field_idx++) if ($field_idx == "-") { separator = field_idx; break }
      mount_point = safe_path($5)
      if (separator == 0 || mount_point == "") next
      access = ($6 ~ /(^|,)rw(,|$)/) ? "rw" : "ro"
      root = safe_path($4)
      if (root == "") root = "/redacted/path"
      printf "0 0 0:0 %s %s %s - %s redacted-mount-source %s\n", \
        root, mount_point, access, safe_fs($(separator + 1)), access
    }
  ' /proc/self/mountinfo 2>/dev/null; then
    printf 'trustlab: command error\n'
    COLLECTION_STATUS=12
  fi
else
  printf 'trustlab: inaccessible\n'
  COLLECTION_STATUS=10
fi

printf '=== PROC_MOUNTS ===\n'
if [ -r /proc/mounts ]; then
  if ! awk '
    function safe_path(path) {
      if (path == "/" || path == "/system" || path == "/vendor" ||
          path == "/product" || path == "/system_ext" || path == "/odm" ||
          path == "/data" || path == "/apex") return path
      if (path ~ /^\/apex\/[A-Za-z0-9._+-]+$/) return "/apex/redacted-apex"
      return ""
    }
    function safe_fs(value) {
      if (value ~ /^(apex|erofs|ext4|f2fs|overlay|squashfs|tmpfs|vfat|virtiofs)$/)
        return value
      return "unknown"
    }
    {
      mount_point = safe_path($2)
      if (mount_point == "") next
      access = ($4 ~ /(^|,)rw(,|$)/) ? "rw" : "ro"
      printf "redacted-mount-source %s %s %s 0 0\n", \
        mount_point, safe_fs($3), access
    }
  ' /proc/mounts 2>/dev/null; then
    printf 'trustlab: command error\n'
    COLLECTION_STATUS=12
  fi
else
  printf 'trustlab: inaccessible\n'
  [ "$COLLECTION_STATUS" -ne 12 ] && COLLECTION_STATUS=10
fi
exit "$COLLECTION_STATUS"
