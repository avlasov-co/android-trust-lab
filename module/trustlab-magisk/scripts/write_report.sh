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
TS_START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
if [ -z "$TS_FILE" ] || [ -z "$TS_START_ISO" ]; then
  printf 'Android Trust Lab: could not obtain a UTC collection timestamp\n' >&2
  exit 1
fi
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
TARGET_TOKEN_FILE="$BASE_DIR/target_pseudonym"

if [ -L "$TARGET_TOKEN_FILE" ]; then
  rm -rf "$RUN_DIR" 2>/dev/null
  printf 'Android Trust Lab: refusing symlinked target pseudonym\n' >&2
  exit 1
fi
if [ ! -f "$TARGET_TOKEN_FILE" ]; then
  TARGET_CANDIDATE="$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | sha256sum 2>/dev/null | awk '{print substr($1,1,16)}')"
  TARGET_TMP="$RUN_DIR/.target_pseudonym"
  if ! printf '%s\n' "$TARGET_CANDIDATE" | grep -Eq '^[0-9a-f]{16}$' || \
    ! printf '%s\n' "$TARGET_CANDIDATE" > "$TARGET_TMP" || \
    ! chmod 0600 "$TARGET_TMP" 2>/dev/null; then
    rm -rf "$RUN_DIR" 2>/dev/null
    printf 'Android Trust Lab: could not create target pseudonym\n' >&2
    exit 1
  fi
  if ! ln "$TARGET_TMP" "$TARGET_TOKEN_FILE" 2>/dev/null && \
    { [ ! -f "$TARGET_TOKEN_FILE" ] || [ -L "$TARGET_TOKEN_FILE" ]; }; then
    rm -rf "$RUN_DIR" 2>/dev/null
    printf 'Android Trust Lab: could not publish target pseudonym\n' >&2
    exit 1
  fi
  rm -f "$TARGET_TMP" 2>/dev/null
fi
TARGET_TOKEN="$(sed -n '1p' "$TARGET_TOKEN_FILE" 2>/dev/null)"
TARGET_TOKEN_SIZE="$(wc -c < "$TARGET_TOKEN_FILE" 2>/dev/null | tr -d '[:space:]')"
if [ "$TARGET_TOKEN_SIZE" != "17" ] || \
  ! printf '%s\n' "$TARGET_TOKEN" | grep -Eq '^[0-9a-f]{16}$'; then
  rm -rf "$RUN_DIR" 2>/dev/null
  printf 'Android Trust Lab: invalid target pseudonym\n' >&2
  exit 1
fi

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

RAW_SHA256="$(sha256sum "$RAW" 2>/dev/null | awk '{print $1}')"
RAW_SIZE="$(wc -c < "$RAW" 2>/dev/null | tr -d '[:space:]')"
TS_END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
COLLECTOR_VERSION="$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -n 1)"
COLLECTION_TOKEN="$(printf '%s:%s' "$RUN_ID" "$RAW_SHA256" | sha256sum 2>/dev/null | awk '{print substr($1,1,16)}')"
if ! printf '%s\n' "$RAW_SHA256" | grep -Eq '^[0-9a-f]{64}$' || \
  ! printf '%s\n' "$RAW_SIZE" | grep -Eq '^[0-9]+$' || \
  [ "$RAW_SIZE" -gt 67108864 ] || \
  ! printf '%s\n' "$TS_START_ISO" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' || \
  ! printf '%s\n' "$TS_END_ISO" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' || \
  ! printf '%s\n' "$COLLECTOR_VERSION" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z][0-9A-Za-z.-]*)?$' || \
  ! printf '%s\n' "$COLLECTION_TOKEN" | grep -Eq '^[0-9a-f]{16}$'; then
  rm -rf "$RUN_DIR" 2>/dev/null
  printf 'Android Trust Lab: could not bind collection provenance\n' >&2
  exit 1
fi

# This is a portable collection-manifest v1 document, not a normalized report.
if ! {
  printf '{\n'
  printf '  "collection_id": "atlcol-%s",\n' "$COLLECTION_TOKEN"
  printf '  "schema_version": "1.0.0",\n'
  printf '  "experiment_id": "E05_magisk_collector",\n'
  printf '  "collector": {"name": "trustlab-magisk", "version": "%s"},\n' "$COLLECTOR_VERSION"
  printf '  "observer": {"observer_type": "root_collector", "privilege_level": "root", "collection_method": "%s"},\n' "$COLLECTION_METHOD"
  printf '  "target": {"pseudonymous_id": "target-%s", "target_type": "unknown"},\n' "$TARGET_TOKEN"
  printf '  "started_at": "%s",\n' "$TS_START_ISO"
  printf '  "ended_at": "%s",\n' "$TS_END_ISO"
  printf '  "completion_status": "partial",\n'
  printf '  "tool_versions": {"android_shell": "toybox", "trustlab_magisk": "%s"},\n' "$COLLECTOR_VERSION"
  printf '  "environment": {"platform": "android", "transport": "on_device", "execution_context": "magisk_module"},\n'
  printf '  "warnings": [],\n'
  printf '  "redaction_policy": {"policy_id": "atl_portable_v1", "redaction_state": "applied", "direct_identifiers_removed": true, "serials_removed": true, "secrets_removed": true},\n'
  printf '  "artifacts": [\n'
  printf '    {"logical_name": "raw_report", "relative_path": "raw.txt", "media_type": "text/plain", "byte_size": %s, "sha256": "%s", "probe_id": "magisk.readonly_snapshot", "status": "observed", "exit_code": 0, "timed_out": false, "sensitivity": "sensitive", "redaction_state": "redacted", "detail": null},\n' "$RAW_SIZE" "$RAW_SHA256"
  printf '    {"logical_name": "command_results", "relative_path": null, "media_type": "application/json", "byte_size": null, "sha256": null, "probe_id": "magisk.command_results", "status": "not_collected", "exit_code": null, "timed_out": false, "sensitivity": "internal", "redaction_state": "withheld", "detail": null}\n'
  printf '  ]\n'
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
