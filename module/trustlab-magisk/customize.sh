#!/system/bin/sh
# Magisk applies default 0644 permissions to regular module files before this
# script is sourced. Android Trust Lab checks write_report.sh with -x, so make
# every shipped shell script executable explicitly.

ui_print "- Verifying Android Trust Lab scripts"

REQUIRED_SCRIPTS="
$MODPATH/action.sh
$MODPATH/post-fs-data.sh
$MODPATH/service.sh
$MODPATH/uninstall.sh
$MODPATH/scripts/collect_boot_state.sh
$MODPATH/scripts/collect_magisk_state.sh
$MODPATH/scripts/collect_mounts.sh
$MODPATH/scripts/collect_process_state.sh
$MODPATH/scripts/collect_props.sh
$MODPATH/scripts/collect_root_state.sh
$MODPATH/scripts/collect_selinux.sh
$MODPATH/scripts/write_report.sh
"

for SCRIPT_PATH in $REQUIRED_SCRIPTS; do
  [ -f "$SCRIPT_PATH" ] || abort "! Missing required module script: ${SCRIPT_PATH#$MODPATH/}"
  set_perm "$SCRIPT_PATH" 0 0 0755 \
    || abort "! Could not set executable permission: ${SCRIPT_PATH#$MODPATH/}"
done

ui_print "- Script permissions verified"
