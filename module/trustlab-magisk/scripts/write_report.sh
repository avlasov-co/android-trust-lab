#!/system/bin/sh
umask 077

COLLECTION_METHOD="$1"
[ -z "$COLLECTION_METHOD" ] && COLLECTION_METHOD="magisk_module_manual"
case "$COLLECTION_METHOD" in
  magisk_module_boot|magisk_module_manual) ;;
  *) COLLECTION_METHOD="magisk_module_manual" ;;
esac

BASE_DIR="/data/adb/android-trust-lab"
OUT_DIR="$BASE_DIR/reports"
if [ -L "$BASE_DIR" ] || [ -L "$OUT_DIR" ]; then
  printf 'Android Trust Lab: refusing symlinked output directory\n' >&2
  exit 1
fi
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then
  printf 'Android Trust Lab: could not create private output directory\n' >&2
  exit 1
fi
if [ -L "$BASE_DIR" ] || [ -L "$OUT_DIR" ]; then
  printf 'Android Trust Lab: refusing symlinked output directory\n' >&2
  exit 1
fi
if ! chmod 0700 "$BASE_DIR" "$OUT_DIR" 2>/dev/null; then
  printf 'Android Trust Lab: could not protect output directory\n' >&2
  exit 1
fi

TS_FILE="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null)"
TS_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
[ -z "$TS_FILE" ] && TS_FILE="unknown-time"
[ -z "$TS_ISO" ] && TS_ISO="$TS_FILE"
RUN_DIR=$(mktemp -d "$OUT_DIR/run_${TS_FILE}.XXXXXX" 2>/dev/null)
case "$RUN_DIR" in
  "$OUT_DIR"/run_*) ;;
  *)
    printf 'Android Trust Lab: invalid exclusive report directory\n' >&2
    exit 1
    ;;
esac
if [ -z "$RUN_DIR" ] || [ ! -d "$RUN_DIR" ] || [ -L "$RUN_DIR" ]; then
  printf 'Android Trust Lab: could not create exclusive report directory\n' >&2
  exit 1
fi
if ! chmod 0700 "$RUN_DIR" 2>/dev/null; then
  rm -rf "$RUN_DIR" 2>/dev/null
  printf 'Android Trust Lab: could not protect report directory\n' >&2
  exit 1
fi
RUN_ID=${RUN_DIR##*/}
RAW="$RUN_DIR/raw.txt"
OUT="$RUN_DIR/collector_manifest.json"
TMP="$RUN_DIR/.collector_manifest.tmp"
MODDIR="${0%/*}/.."

if ! {
  "$MODDIR/scripts/collect_boot_state.sh"
  "$MODDIR/scripts/collect_props.sh"
  "$MODDIR/scripts/collect_mounts.sh"
  printf '=== ID ===\n'
  id 2>/dev/null || true
  "$MODDIR/scripts/collect_selinux.sh"
  printf '=== SU_PATHS ===\n'
  command -v su 2>/dev/null || true
  ls /system/bin/su /system/xbin/su /sbin/su /su/bin/su 2>/dev/null || true
  "$MODDIR/scripts/collect_magisk_state.sh"
  "$MODDIR/scripts/collect_process_state.sh"
} > "$RAW" 2>&1; then
  rm -rf "$RUN_DIR" 2>/dev/null
  printf 'Android Trust Lab: raw collection failed\n' >&2
  exit 1
fi
if ! chmod 0600 "$RAW" 2>/dev/null; then
  rm -rf "$RUN_DIR" 2>/dev/null
  printf 'Android Trust Lab: could not protect raw report\n' >&2
  exit 1
fi

# This is an on-device collection manifest, not a normalized trust_report.schema.json report.
# Normalize the raw text artifact with the host analyzer.
if ! {
  printf '{\n'
  printf '  "manifest_id": "atl-root-manifest-%s",\n' "$RUN_ID"
  printf '  "schema_version": "collection-manifest-0.1",\n'
  printf '  "collection_timestamp": "%s",\n' "$TS_ISO"
  printf '  "experiment_id": "E05_magisk_collector",\n'
  printf '  "observer": {"observer_type": "root_collector", "privilege_level": "root", "collection_method": "%s"},\n' "$COLLECTION_METHOD"
  printf '  "raw_artifact": "%s",\n' "$RAW"
  printf '  "normalization": "Run trustlab normalize --observer root_collector --collection-method %s --input %s",\n' "$COLLECTION_METHOD" "$RAW"
  printf '  "note": "Read-only root-side raw snapshot manifest. This file is not a normalized trust report."\n'
  printf '}\n'
} > "$TMP"; then
  rm -rf "$RUN_DIR" 2>/dev/null
  printf 'Android Trust Lab: manifest creation failed\n' >&2
  exit 1
fi
if ! chmod 0600 "$TMP" 2>/dev/null || ! mv "$TMP" "$OUT" 2>/dev/null; then
  rm -rf "$RUN_DIR" 2>/dev/null
  printf 'Android Trust Lab: manifest publication failed\n' >&2
  exit 1
fi
chmod 0600 "$OUT" 2>/dev/null || true
printf '%s\n' "$OUT"
exit 0
