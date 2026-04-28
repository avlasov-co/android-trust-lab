#!/system/bin/sh
COLLECTION_METHOD="$1"
[ -z "$COLLECTION_METHOD" ] && COLLECTION_METHOD="magisk_module_manual"
case "$COLLECTION_METHOD" in
  magisk_module_boot|magisk_module_manual) ;;
  *) COLLECTION_METHOD="magisk_module_manual" ;;
esac

OUT_DIR="/data/local/tmp/android-trust-lab/reports"
mkdir -p "$OUT_DIR" 2>/dev/null
chmod 0755 "$OUT_DIR" 2>/dev/null

TS_FILE="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null)"
TS_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
[ -z "$TS_FILE" ] && TS_FILE="unknown-time"
[ -z "$TS_ISO" ] && TS_ISO="$TS_FILE"
RAW="$OUT_DIR/raw_${TS_FILE}.txt"
OUT="$OUT_DIR/collector_manifest_${TS_FILE}.json"
MODDIR="${0%/*}/.."

{
  "$MODDIR/scripts/collect_boot_state.sh"
  "$MODDIR/scripts/collect_props.sh"
  "$MODDIR/scripts/collect_mounts.sh"
  printf '=== ID ===\n'
  id 2>/dev/null || true
  "$MODDIR/scripts/collect_selinux.sh"
  printf '=== CMDLINE ===\n'
  cat /proc/cmdline 2>/dev/null || true
  printf '\n=== SU_PATHS ===\n'
  command -v su 2>/dev/null || true
  ls /system/bin/su /system/xbin/su /sbin/su /su/bin/su 2>/dev/null || true
  "$MODDIR/scripts/collect_magisk_state.sh"
  "$MODDIR/scripts/collect_process_state.sh"
} > "$RAW" 2>&1
chmod 0644 "$RAW" 2>/dev/null

# This is an on-device collection manifest, not a normalized trust_report.schema.json report.
# Normalize the raw text artifact with the host analyzer.
{
  printf '{\n'
  printf '  "manifest_id": "atl-root-manifest-%s",\n' "$TS_FILE"
  printf '  "schema_version": "collection-manifest-0.1",\n'
  printf '  "collection_timestamp": "%s",\n' "$TS_ISO"
  printf '  "experiment_id": "E05_magisk_collector",\n'
  printf '  "observer": {"observer_type": "root_collector", "privilege_level": "root", "collection_method": "%s"},\n' "$COLLECTION_METHOD"
  printf '  "raw_artifact": "%s",\n' "$RAW"
  printf '  "normalization": "Run trustlab normalize --observer root_collector --collection-method %s --input %s",\n' "$COLLECTION_METHOD" "$RAW"
  printf '  "note": "Read-only root-side raw snapshot manifest. This file is not a normalized trust report."\n'
  printf '}\n'
} > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"
chmod 0644 "$OUT" 2>/dev/null
printf '%s\n' "$OUT"
exit 0
