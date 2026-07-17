#!/system/bin/sh
printf '=== GETENFORCE ===\n'
COLLECTION_STATUS=0
MODE_OUTPUT=$(getenforce 2>&1)
MODE_STATUS=$?
if [ "$MODE_STATUS" -eq 0 ]; then
  case "$MODE_OUTPUT" in
    Enforcing | Permissive | Disabled) printf '%s\n' "$MODE_OUTPUT" ;;
    *) printf 'trustlab: command error\n'; COLLECTION_STATUS=12 ;;
  esac
else
  case "$MODE_OUTPUT" in
    *[Pp]ermission\ [Dd]enied* | *[Oo]peration\ [Nn]ot\ [Pp]ermitted*)
      printf 'trustlab: inaccessible\n'
      COLLECTION_STATUS=10
      ;;
    *[Nn]ot\ [Ff]ound* | *[Uu]nknown\ [Oo]ption* | *[Ii]nvalid\ [Oo]ption*)
      printf 'trustlab: unsupported\n'
      COLLECTION_STATUS=11
      ;;
    *) printf 'trustlab: command error\n'; COLLECTION_STATUS=12 ;;
  esac
fi
printf '=== SELINUX_CONTEXT ===\n'
CONTEXT_OUTPUT=$(id -Z 2>&1)
CONTEXT_STATUS=$?
if [ "$CONTEXT_STATUS" -eq 0 ] && [ -n "$CONTEXT_OUTPUT" ]; then
  if printf '%s\n' "$CONTEXT_OUTPUT" \
    | grep -Eq '^u:r:(adbd|init|magisk|magiskd|system_server|zygote):s[0-9]+(-s[0-9]+)?$'; then
    printf '%s\n' "$CONTEXT_OUTPUT"
  elif printf '%s\n' "$CONTEXT_OUTPUT" \
    | grep -Eq '^u:r:[a-z0-9_]+:s[0-9]+(-s[0-9]+)?$'; then
    printf 'redacted-selinux-context\n'
  else
    printf 'trustlab: command error\n'
    COLLECTION_STATUS=12
  fi
else
  case "$CONTEXT_OUTPUT" in
    *[Pp]ermission\ [Dd]enied* | *[Oo]peration\ [Nn]ot\ [Pp]ermitted*)
      printf 'trustlab: inaccessible\n'
      [ "$COLLECTION_STATUS" -ne 12 ] && COLLECTION_STATUS=10
      ;;
    *[Nn]ot\ [Ff]ound* | *[Uu]nknown\ [Oo]ption* | *[Ii]nvalid\ [Oo]ption*)
      printf 'trustlab: unsupported\n'
      [ "$COLLECTION_STATUS" -eq 0 ] && COLLECTION_STATUS=11
      ;;
    *) printf 'trustlab: command error\n'; COLLECTION_STATUS=12 ;;
  esac
fi
exit "$COLLECTION_STATUS"
