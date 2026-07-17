#!/system/bin/sh
printf '=== ROOT_PROBE ===\n'

UID_VALUE="$(id -u 2>/dev/null)"
UID_STATUS=$?
if [ "$UID_STATUS" -ne 0 ]; then
  printf 'observer_effective_uid_is_root=observed_absent\n'
  printf 'root_shell_available=observed_absent\n'
  printf 'su_binary_observed=observed_absent\n'
  printf 'su_invocation_tested=observed_absent\n'
  printf 'su_invocation_result=not_tested\n'
  printf 'root_management_artifact_observed=observed_absent\n'
  exit 12
fi
case "$UID_VALUE" in
  ''|*[!0-9]*)
    printf 'observer_effective_uid_is_root=observed_absent\n'
    printf 'root_shell_available=observed_absent\n'
    printf 'su_binary_observed=observed_absent\n'
    printf 'su_invocation_tested=observed_absent\n'
    printf 'su_invocation_result=not_tested\n'
    printf 'root_management_artifact_observed=observed_absent\n'
    exit 12
    ;;
esac
if [ "$UID_VALUE" = "0" ]; then
  printf 'observer_effective_uid_is_root=observed\n'
  printf 'root_shell_available=observed\n'
else
  printf 'observer_effective_uid_is_root=observed_absent\n'
  printf 'root_shell_available=observed_absent\n'
fi

if command -v su >/dev/null 2>&1; then
  printf 'su_binary_observed=observed\n'
else
  printf 'su_binary_observed=observed_absent\n'
fi
printf 'su_invocation_tested=observed_absent\n'
printf 'su_invocation_result=not_tested\n'

if command -v magisk >/dev/null 2>&1 || [ -d /data/adb/magisk ]; then
  printf 'root_management_artifact_observed=observed\n'
else
  printf 'root_management_artifact_observed=observed_absent\n'
fi
exit 0
