#!/system/bin/sh
printf '=== PS_SELECTED ===\n'
CONTEXT_OUTPUT=$(ps -AZ 2>&1)
CONTEXT_STATUS=$?
BASIC_OUTPUT=$(ps 2>&1)
BASIC_STATUS=$?
if [ "$CONTEXT_STATUS" -ne 0 ] && [ "$BASIC_STATUS" -ne 0 ]; then
  case "$CONTEXT_OUTPUT $BASIC_OUTPUT" in
    *[Pp]ermission\ [Dd]enied* | *[Oo]peration\ [Nn]ot\ [Pp]ermitted*)
      printf 'trustlab: inaccessible\n'
      exit 10
      ;;
    *[Nn]ot\ [Ff]ound* | *[Uu]nknown\ [Oo]ption* | *[Ii]nvalid\ [Oo]ption*)
      printf 'trustlab: unsupported\n'
      exit 11
      ;;
    *) printf 'trustlab: command error\n'; exit 12 ;;
  esac
fi
for PROCESS in init adbd zygote zygote64 system_server magisk magiskd
do
  LINE=''
  if [ "$CONTEXT_STATUS" -eq 0 ]; then
    LINE=$(printf '%s\n' "$CONTEXT_OUTPUT" | awk -v target="$PROCESS" '$NF == target { print; exit }')
  fi
  if [ -n "$LINE" ]; then
    CONTEXT=$(printf '%s\n' "$LINE" | awk '{print $1}')
    if printf '%s\n' "$CONTEXT" \
      | grep -Eq '^u:r:(adbd|init|magisk|magiskd|system_server|zygote):s[0-9]+(-s[0-9]+)?$'; then
      printf '%s %s\n' "$CONTEXT" "$PROCESS"
    else
      printf '%s\n' "$PROCESS"
    fi
  elif [ "$BASIC_STATUS" -eq 0 ] && printf '%s\n' "$BASIC_OUTPUT" | awk -v target="$PROCESS" '$NF == target { found=1; exit } END { exit !found }'; then
    printf '%s\n' "$PROCESS"
  fi
done
exit 0
