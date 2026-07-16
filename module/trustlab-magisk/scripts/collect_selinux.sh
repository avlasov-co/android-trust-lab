#!/system/bin/sh
printf '=== GETENFORCE ===\n'
MODE_OUTPUT=$(getenforce 2>&1)
MODE_STATUS=$?
if [ "$MODE_STATUS" -eq 0 ]; then
  case "$MODE_OUTPUT" in
    Enforcing | Permissive | Disabled) printf '%s\n' "$MODE_OUTPUT" ;;
    *) printf 'trustlab: command error\n' ;;
  esac
else
  case "$MODE_OUTPUT" in
    *[Pp]ermission\ [Dd]enied* | *[Oo]peration\ [Nn]ot\ [Pp]ermitted*)
      printf 'trustlab: inaccessible\n'
      ;;
    *[Nn]ot\ [Ff]ound* | *[Uu]nknown\ [Oo]ption* | *[Ii]nvalid\ [Oo]ption*)
      printf 'trustlab: unsupported\n'
      ;;
    *) printf 'trustlab: command error\n' ;;
  esac
fi
printf '=== SELINUX_CONTEXT ===\n'
CONTEXT_OUTPUT=$(id -Z 2>&1)
CONTEXT_STATUS=$?
if [ "$CONTEXT_STATUS" -eq 0 ] && [ -n "$CONTEXT_OUTPUT" ]; then
  printf '%s\n' "$CONTEXT_OUTPUT"
else
  case "$CONTEXT_OUTPUT" in
    *[Pp]ermission\ [Dd]enied* | *[Oo]peration\ [Nn]ot\ [Pp]ermitted*)
      printf 'trustlab: inaccessible\n'
      ;;
    *[Nn]ot\ [Ff]ound* | *[Uu]nknown\ [Oo]ption* | *[Ii]nvalid\ [Oo]ption*)
      printf 'trustlab: unsupported\n'
      ;;
    *) printf 'trustlab: command error\n' ;;
  esac
fi
exit 0
