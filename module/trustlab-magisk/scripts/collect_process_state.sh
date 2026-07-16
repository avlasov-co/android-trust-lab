#!/system/bin/sh
printf '=== PS ===\n'
CONTEXT_OUTPUT=$(ps -AZ 2>/dev/null)
BASIC_OUTPUT=$(ps 2>/dev/null)
for PROCESS in init adbd zygote zygote64 system_server magisk magiskd
do
  PATTERN="(^|[[:space:]])${PROCESS}($|[[:space:]])"
  LINE=$(printf '%s\n' "$CONTEXT_OUTPUT" | grep -E "$PATTERN" | head -n 1)
  if [ -n "$LINE" ]; then
    CONTEXT=$(printf '%s\n' "$LINE" | awk '{print $1}')
    case "$CONTEXT" in
      u:*) printf '%s %s\n' "$CONTEXT" "$PROCESS" ;;
      *) printf '%s\n' "$PROCESS" ;;
    esac
  elif printf '%s\n' "$BASIC_OUTPUT" | grep -Eq "$PATTERN"; then
    printf '%s\n' "$PROCESS"
  fi
done
exit 0
