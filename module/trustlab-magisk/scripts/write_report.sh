#!/system/bin/sh
# Read-only Magisk collection runtime.  The completion manifest is the publish
# marker: it is created only after every retained artifact has a size and hash.
umask 077

MAX_ARTIFACT_BYTES=67108864
MAX_BUNDLE_BYTES=134217728
OWNERLESS_STALE_SECONDS=300
COLLECTION_METHOD=${1:-magisk_module_manual}
REQUESTED_BOOT_RESULT=${2:-auto}
case "$COLLECTION_METHOD" in
  magisk_module_boot|magisk_module_manual|magisk_module_webui) ;;
  *) COLLECTION_METHOD=magisk_module_manual ;;
esac
case "$REQUESTED_BOOT_RESULT" in
  auto|complete|incomplete|interrupted|timeout) ;;
  *) REQUESTED_BOOT_RESULT=auto ;;
esac

BASE_DIR="/data/adb/android-trust-lab"
OUT_DIR="$BASE_DIR/reports"
EVENT_DIR="$BASE_DIR/events"
LOCK_DIR="$BASE_DIR/collector.lock"
RECOVERY_LOCK="$BASE_DIR/collector.lock.recovery"
MODDIR="${0%/*}/.."
TARGET_TOKEN_FILE="$BASE_DIR/target_pseudonym"
LOCK_HELD=0
RECOVERY_HELD=0

fail() {
  printf 'Android Trust Lab: %s\n' "$1" >&2
}

# Covers setup before the full partial-publication handler is installed. No
# usable capture exists in this window, so cleanup without publication is honest.
# shellcheck disable=SC2329
early_interrupt() {
  if [ "${RECOVERY_HELD:-0}" -eq 1 ]; then
    rmdir "$RECOVERY_LOCK" 2>/dev/null
  fi
  if [ "${LOCK_HELD:-0}" -eq 1 ]; then
    rm -f "$LOCK_DIR/entropy" "$LOCK_DIR/owner" 2>/dev/null
    rmdir "$LOCK_DIR" 2>/dev/null
  fi
  exit 130
}
trap 'early_interrupt' HUP INT TERM

utc_file_time() {
  date -u +%Y%m%dT%H%M%SZ 2>/dev/null
}

utc_iso_time() {
  date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null
}

random_nonce() {
  ENTROPY_FILE="$LOCK_DIR/entropy"
  rm -f "$ENTROPY_FILE" 2>/dev/null
  if ! dd if=/dev/urandom of="$ENTROPY_FILE" bs=32 count=1 2>/dev/null \
    || ! chmod 0600 "$ENTROPY_FILE" 2>/dev/null; then
    rm -f "$ENTROPY_FILE" 2>/dev/null
    return 1
  fi
  ENTROPY_SIZE=$(wc -c < "$ENTROPY_FILE" 2>/dev/null | tr -d '[:space:]')
  if [ "$ENTROPY_SIZE" != 32 ]; then
    rm -f "$ENTROPY_FILE" 2>/dev/null
    return 1
  fi
  ENTROPY_HASH=$(sha256sum "$ENTROPY_FILE" 2>/dev/null | awk '{print $1}')
  rm -f "$ENTROPY_FILE" 2>/dev/null
  printf '%s\n' "$ENTROPY_HASH" | grep -Eq '^[0-9a-f]{64}$' || return 1
  printf '%s\n' "$ENTROPY_HASH" | cut -c 1-16
}

valid_file_time() {
  printf '%s\n' "$1" | grep -Eq '^[0-9]{8}T[0-9]{6}Z$'
}

valid_iso_time() {
  printf '%s\n' "$1" \
    | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
}

valid_hex16() {
  printf '%s\n' "$1" | grep -Eq '^[0-9a-f]{16}$'
}

process_start_ticks() {
  awk '{print $22}' "/proc/$1/stat" 2>/dev/null
}

lock_owner_is_stale() {
  [ -f "$LOCK_DIR/owner" ] && [ ! -L "$LOCK_DIR/owner" ] || return 1
  STALE_PID=$(sed -n 's/^pid=//p' "$LOCK_DIR/owner" 2>/dev/null | head -n 1)
  STALE_START=$(sed -n 's/^pid_start_ticks=//p' "$LOCK_DIR/owner" 2>/dev/null | head -n 1)
  printf '%s\n' "$STALE_PID" | grep -Eq '^[1-9][0-9]*$' || return 1
  if ! kill -0 "$STALE_PID" 2>/dev/null; then
    return 0
  fi
  if printf '%s\n' "$STALE_START" | grep -Eq '^[0-9]+$'; then
    CURRENT_START=$(process_start_ticks "$STALE_PID")
    if printf '%s\n' "$CURRENT_START" | grep -Eq '^[0-9]+$' \
      && [ "$CURRENT_START" != "$STALE_START" ]; then
      return 0
    fi
  fi
  return 1
}

empty_lock_is_aged() {
  AGED_LOCK=$1
  [ -d "$AGED_LOCK" ] && [ ! -L "$AGED_LOCK" ] || return 1
  AGED_MTIME=$(stat -c %Y "$AGED_LOCK" 2>/dev/null)
  if ! printf '%s\n' "$AGED_MTIME" | grep -Eq '^[0-9]+$'; then
    AGED_MTIME=$(stat -f %m "$AGED_LOCK" 2>/dev/null)
  fi
  AGED_NOW=$(date -u +%s 2>/dev/null)
  printf '%s\n' "$AGED_MTIME" | grep -Eq '^[0-9]+$' || return 1
  printf '%s\n' "$AGED_NOW" | grep -Eq '^[0-9]+$' || return 1
  [ "$AGED_NOW" -ge "$AGED_MTIME" ] 2>/dev/null || return 1
  AGED_SECONDS=$((AGED_NOW - AGED_MTIME))
  [ "$AGED_SECONDS" -ge "$OWNERLESS_STALE_SECONDS" ]
}

release_recovery_lock() {
  rmdir "$RECOVERY_LOCK" 2>/dev/null
  RECOVERY_HELD=0
}

acquire_recovery_lock() {
  if mkdir "$RECOVERY_LOCK" 2>/dev/null; then
    RECOVERY_HELD=1
  elif empty_lock_is_aged "$RECOVERY_LOCK" \
    && rmdir "$RECOVERY_LOCK" 2>/dev/null \
    && mkdir "$RECOVERY_LOCK" 2>/dev/null; then
    RECOVERY_HELD=1
  else
    return 1
  fi
  if ! chmod 0700 "$RECOVERY_LOCK" 2>/dev/null; then
    release_recovery_lock
    return 1
  fi
  return 0
}

acquire_collector_lock() {
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    LOCK_HELD=1
    return 0
  fi
  acquire_recovery_lock || return 1
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    LOCK_HELD=1
    release_recovery_lock
    return 0
  fi
  if lock_owner_is_stale; then
    # Entropy is the only transient file allowed beside the validated owner.
    # A SIGKILL during nonce generation may leave it behind, so remove both
    # known lock-owned files only after proving that the owner is stale.
    rm -f "$LOCK_DIR/entropy" "$LOCK_DIR/owner" 2>/dev/null
    if rmdir "$LOCK_DIR" 2>/dev/null && mkdir "$LOCK_DIR" 2>/dev/null; then
      LOCK_HELD=1
      release_recovery_lock
      return 0
    fi
  elif empty_lock_is_aged "$LOCK_DIR"; then
    # `rmdir` is the structural check: unknown files make reclamation fail.
    if rmdir "$LOCK_DIR" 2>/dev/null && mkdir "$LOCK_DIR" 2>/dev/null; then
      LOCK_HELD=1
      release_recovery_lock
      return 0
    fi
  fi
  release_recovery_lock
  return 1
}

if [ -L "$BASE_DIR" ] || [ -L "$OUT_DIR" ] || [ -L "$EVENT_DIR" ]; then
  fail 'refusing symlinked output directory'
  exit 1
fi
if ! mkdir -p "$OUT_DIR" "$EVENT_DIR" 2>/dev/null; then
  fail 'could not create private output directories'
  exit 1
fi
if [ -L "$BASE_DIR" ] || [ -L "$OUT_DIR" ] || [ -L "$EVENT_DIR" ]; then
  fail 'refusing symlinked output directory'
  exit 1
fi
if ! chmod 0700 "$BASE_DIR" "$OUT_DIR" "$EVENT_DIR" 2>/dev/null; then
  fail 'could not protect output directories'
  exit 1
fi

TS_FILE=$(utc_file_time)
TS_START_ISO=$(utc_iso_time)
if ! valid_file_time "$TS_FILE" || ! valid_iso_time "$TS_START_ISO"; then
  fail 'could not create a UTC collection timestamp'
  exit 1
fi

record_already_running() {
  EVENT_PATH="$EVENT_DIR/already_running_${TS_FILE}_$$"
  if mkdir "$EVENT_PATH" 2>/dev/null; then
    chmod 0700 "$EVENT_PATH" 2>/dev/null || return
    {
      printf 'status=already_running\n'
      printf 'recorded_at=%s\n' "$TS_START_ISO"
    } > "$EVENT_PATH/status.log" 2>/dev/null || return
    chmod 0600 "$EVENT_PATH/status.log" 2>/dev/null || return
  fi
}

if ! acquire_collector_lock; then
  record_already_running
  fail 'already_running'
  exit 75
fi
LOCK_HELD=1
OWNER_START_TICKS=$(process_start_ticks $$)
printf '%s\n' "$OWNER_START_TICKS" | grep -Eq '^[0-9]+$' || OWNER_START_TICKS=unknown
if ! chmod 0700 "$LOCK_DIR" 2>/dev/null \
  || ! {
    printf 'pid=%s\n' "$$"
    printf 'pid_start_ticks=%s\n' "$OWNER_START_TICKS"
    printf 'status=active\n'
  } > "$LOCK_DIR/owner" 2>/dev/null \
  || ! chmod 0600 "$LOCK_DIR/owner" 2>/dev/null; then
  rm -f "$LOCK_DIR/owner" 2>/dev/null
  rmdir "$LOCK_DIR" 2>/dev/null
  fail 'could not protect collector lock'
  exit 1
fi

RUN_NONCE=$(random_nonce)
if ! valid_hex16 "$RUN_NONCE"; then
  rm -f "$LOCK_DIR/entropy" "$LOCK_DIR/owner" 2>/dev/null
  rmdir "$LOCK_DIR" 2>/dev/null
  LOCK_HELD=0
  fail 'could not create verified collection entropy'
  exit 1
fi
RUN_ID="run_${TS_FILE}_${RUN_NONCE}"
STAGING_DIR="$OUT_DIR/.partial_${TS_FILE}_${RUN_NONCE}"
FINAL_DIR="$OUT_DIR/$RUN_ID"
if ! {
  printf 'pid=%s\n' "$$"
  printf 'pid_start_ticks=%s\n' "$OWNER_START_TICKS"
  printf 'collection_id=%s\n' "$RUN_ID"
} > "$LOCK_DIR/owner" 2>/dev/null \
  || ! chmod 0600 "$LOCK_DIR/owner" 2>/dev/null; then
  rm -f "$LOCK_DIR/entropy" "$LOCK_DIR/owner" 2>/dev/null
  rmdir "$LOCK_DIR" 2>/dev/null
  LOCK_HELD=0
  fail 'could not bind collector lock owner'
  exit 1
fi

PUBLISHED=0
FINALIZING=0
FINAL_CLAIMED=0
INTERRUPTED=0
ACTIVE_CHILD=''
ACTIVE_PROBE=''

# Invoked through trap(1), which ShellCheck cannot resolve statically.
# shellcheck disable=SC2329
cleanup() {
  if [ "$PUBLISHED" -ne 1 ] && [ "${FINAL_CLAIMED:-0}" -eq 1 ]; then
    case "$FINAL_DIR" in
      "$OUT_DIR"/run_*)
        rm -f "$FINAL_DIR"/captures/*.txt "$FINAL_DIR"/*.txt \
          "$FINAL_DIR"/*.json "$FINAL_DIR"/*.log 2>/dev/null
        rmdir "$FINAL_DIR/captures" 2>/dev/null
        rmdir "$FINAL_DIR" 2>/dev/null
        ;;
    esac
  fi
  if [ "$PUBLISHED" -ne 1 ] && [ -n "${STAGING_DIR:-}" ]; then
    case "$STAGING_DIR" in
      "$OUT_DIR"/.partial_*)
        rm -f "$STAGING_DIR"/captures/*.txt "$STAGING_DIR"/*.txt \
          "$STAGING_DIR"/*.json "$STAGING_DIR"/*.log "$STAGING_DIR"/.*.tmp \
          "$STAGING_DIR"/.*.stderr "$STAGING_DIR"/.*.capture \
          "$STAGING_DIR"/.target_pseudonym 2>/dev/null
        rmdir "$STAGING_DIR/captures" 2>/dev/null
        rmdir "$STAGING_DIR" 2>/dev/null
        ;;
    esac
  fi
  if [ "${LOCK_HELD:-0}" -eq 1 ]; then
    rm -f "$LOCK_DIR/entropy" "$LOCK_DIR/owner" 2>/dev/null
    rmdir "$LOCK_DIR" 2>/dev/null
    LOCK_HELD=0
  fi
}
trap cleanup 0
trap 'cleanup; exit 130' HUP INT TERM

if [ -e "$STAGING_DIR" ] || ! mkdir "$STAGING_DIR" 2>/dev/null; then
  fail 'exclusive staging directory collision'
  exit 1
fi
CAPTURE_DIR="$STAGING_DIR/captures"
if ! mkdir "$CAPTURE_DIR" 2>/dev/null \
  || ! chmod 0700 "$STAGING_DIR" "$CAPTURE_DIR" 2>/dev/null; then
  fail 'could not create private staging directory'
  exit 1
fi

RAW="$STAGING_DIR/raw.txt"
RESULTS="$STAGING_DIR/command_results.json"
LOG="$STAGING_DIR/collector.log"
MANIFEST="$STAGING_DIR/collector_manifest.json"
MANIFEST_TMP="$STAGING_DIR/.collector_manifest.tmp"
RESULTS_TMP="$STAGING_DIR/.command_results.tmp"

BOOT_STATE_STATUS=not_collected
BOOT_STATE_EXIT=null
PROPERTIES_STATUS=not_collected
PROPERTIES_EXIT=null
MOUNTS_STATUS=not_collected
MOUNTS_EXIT=null
SELINUX_STATUS=not_collected
SELINUX_EXIT=null
ROOT_STATE_STATUS=not_collected
ROOT_STATE_EXIT=null
MAGISK_STATE_STATUS=not_collected
MAGISK_STATE_EXIT=null
PROCESS_STATE_STATUS=not_collected
PROCESS_STATE_EXIT=null
BOOT_COMPLETION_STATUS=not_collected
BOOT_COMPLETION_EXIT=null
BOOT_COMPLETION_TIMED_OUT=false

set_probe_result() {
  case "$1" in
    boot_state) BOOT_STATE_STATUS=$2; BOOT_STATE_EXIT=$3 ;;
    properties) PROPERTIES_STATUS=$2; PROPERTIES_EXIT=$3 ;;
    mounts) MOUNTS_STATUS=$2; MOUNTS_EXIT=$3 ;;
    selinux) SELINUX_STATUS=$2; SELINUX_EXIT=$3 ;;
    root_state) ROOT_STATE_STATUS=$2; ROOT_STATE_EXIT=$3 ;;
    magisk_state) MAGISK_STATE_STATUS=$2; MAGISK_STATE_EXIT=$3 ;;
    process_state) PROCESS_STATE_STATUS=$2; PROCESS_STATE_EXIT=$3 ;;
  esac
}

capture_probe() {
  PROBE_NAME=$1
  PROBE_SCRIPT=$2
  PROBE_PATH="$CAPTURE_DIR/$PROBE_NAME.txt"
  PROBE_TMP="$STAGING_DIR/.${PROBE_NAME}.capture"
  PROBE_ERROR="$STAGING_DIR/.${PROBE_NAME}.stderr"
  ACTIVE_PROBE=$PROBE_NAME
  sh "$PROBE_SCRIPT" > "$PROBE_TMP" 2> "$PROBE_ERROR" &
  ACTIVE_CHILD=$!
  wait "$ACTIVE_CHILD"
  PROBE_EXIT=$?
  rm -f "$PROBE_ERROR" 2>/dev/null
  if [ "$PROBE_EXIT" -eq 0 ] && [ -s "$PROBE_TMP" ]; then
    PROBE_SIZE=$(wc -c < "$PROBE_TMP" 2>/dev/null | tr -d '[:space:]')
    if printf '%s\n' "$PROBE_SIZE" | grep -Eq '^[0-9]+$' \
      && [ "$PROBE_SIZE" -le "$MAX_ARTIFACT_BYTES" ] \
      && chmod 0600 "$PROBE_TMP" 2>/dev/null \
      && mv "$PROBE_TMP" "$PROBE_PATH" 2>/dev/null; then
      set_probe_result "$PROBE_NAME" observed 0
      ACTIVE_CHILD=''
      ACTIVE_PROBE=''
      return 0
    fi
    PROBE_EXIT=1
  fi
  case "$PROBE_EXIT" in
    10) PROBE_STATUS=inaccessible ;;
    11) PROBE_STATUS=unsupported; PROBE_EXIT=null ;;
    ''|*[!0-9]*|0) PROBE_STATUS=command_error; PROBE_EXIT=1 ;;
    *)
      PROBE_STATUS=command_error
      [ "$PROBE_EXIT" -le 255 ] 2>/dev/null || PROBE_EXIT=1
      ;;
  esac
  rm -f "$PROBE_TMP" "$PROBE_PATH" 2>/dev/null
  set_probe_result "$PROBE_NAME" "$PROBE_STATUS" "$PROBE_EXIT"
  ACTIVE_CHILD=''
  ACTIVE_PROBE=''
  return 0
}

append_capture() {
  APPEND_NAME=$1
  APPEND_SECTION=$2
  APPEND_STATUS=$3
  if [ "$APPEND_STATUS" = observed ]; then
    cat "$CAPTURE_DIR/$APPEND_NAME.txt" >> "$RAW" 2>/dev/null || return 1
  elif [ "$APPEND_STATUS" != not_collected ]; then
    case "$APPEND_STATUS" in
      inaccessible) APPEND_MARKER='trustlab: inaccessible' ;;
      unsupported) APPEND_MARKER='trustlab: unsupported' ;;
      *) APPEND_MARKER='trustlab: command error' ;;
    esac
    printf '=== %s ===\n%s\n' "$APPEND_SECTION" "$APPEND_MARKER" >> "$RAW" || return 1
  fi
  return 0
}

artifact_size() {
  wc -c < "$1" 2>/dev/null | tr -d '[:space:]'
}

artifact_sha256() {
  sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

valid_artifact_binding() {
  BIND_PATH=$1
  BIND_SIZE=$2
  BIND_SHA=$3
  [ -f "$BIND_PATH" ] && [ ! -L "$BIND_PATH" ] \
    && printf '%s\n' "$BIND_SIZE" | grep -Eq '^[0-9]+$' \
    && [ "$BIND_SIZE" -le "$MAX_ARTIFACT_BYTES" ] \
    && printf '%s\n' "$BIND_SHA" | grep -Eq '^[0-9a-f]{64}$'
}

emit_capture_artifact() {
  ARTIFACT_NAME=$1
  ARTIFACT_PROBE=$2
  ARTIFACT_SENSITIVITY=$3
  ARTIFACT_STATUS=$4
  ARTIFACT_EXIT=$5
  ARTIFACT_PATH="$CAPTURE_DIR/$ARTIFACT_NAME.txt"
  if [ "$ARTIFACT_STATUS" = observed ]; then
    ARTIFACT_SIZE=$(artifact_size "$ARTIFACT_PATH")
    ARTIFACT_SHA=$(artifact_sha256 "$ARTIFACT_PATH")
    if ! valid_artifact_binding "$ARTIFACT_PATH" "$ARTIFACT_SIZE" "$ARTIFACT_SHA"; then
      return 1
    fi
    printf '    {"logical_name": "%s", "relative_path": "captures/%s.txt", "media_type": "text/plain", "byte_size": %s, "sha256": "%s", "probe_id": "magisk.%s", "status": "observed", "exit_code": 0, "timed_out": false, "sensitivity": "%s", "redaction_state": "redacted", "detail": null}' \
      "$ARTIFACT_NAME" "$ARTIFACT_NAME" "$ARTIFACT_SIZE" "$ARTIFACT_SHA" \
      "$ARTIFACT_PROBE" "$ARTIFACT_SENSITIVITY"
  else
    printf '    {"logical_name": "%s", "relative_path": null, "media_type": "text/plain", "byte_size": null, "sha256": null, "probe_id": "magisk.%s", "status": "%s", "exit_code": %s, "timed_out": false, "sensitivity": "%s", "redaction_state": "withheld", "detail": null}' \
      "$ARTIFACT_NAME" "$ARTIFACT_PROBE" "$ARTIFACT_STATUS" "$ARTIFACT_EXIT" \
      "$ARTIFACT_SENSITIVITY"
  fi
}

publish_capture() {
  [ "$2" = observed ] || return 0
  mv "$CAPTURE_DIR/$1.txt" "$FINAL_DIR/captures/" 2>/dev/null
}

finalize_collection() {
  if [ "$FINALIZING" -eq 1 ]; then
    return 1
  fi
  FINALIZING=1
  # Publication is a short critical section.  Preserve a coherent partial
  # collection rather than allowing a second signal to tear its manifest.
  trap '' HUP INT TERM

  rm -f "$RAW" "$RESULTS" "$MANIFEST" "$MANIFEST_TMP" "$RESULTS_TMP" \
    "$STAGING_DIR"/.*.stderr 2>/dev/null
  : > "$RAW" || return 1
  append_capture boot_state BOOT_STATE "$BOOT_STATE_STATUS" || return 1
  append_capture properties GETPROP "$PROPERTIES_STATUS" || return 1
  append_capture mounts MOUNTINFO "$MOUNTS_STATUS" || return 1
  append_capture selinux GETENFORCE "$SELINUX_STATUS" || return 1
  append_capture root_state ROOT_PROBE "$ROOT_STATE_STATUS" || return 1
  append_capture magisk_state MAGISK "$MAGISK_STATE_STATUS" || return 1
  append_capture process_state PS_SELECTED "$PROCESS_STATE_STATUS" || return 1
  if [ ! -s "$RAW" ]; then
    printf '=== BOOT_STATE ===\ntrustlab: command error\n' > "$RAW" || return 1
  fi
  chmod 0600 "$RAW" 2>/dev/null || return 1

  if ! {
    printf '{\n'
    printf '  "schema_version": "1.0.0",\n'
    printf '  "redaction_policy_version": "atl_portable_v1",\n'
    printf '  "boot_completion": {"status": "%s"},\n' "$BOOT_RESULT"
    printf '  "commands": [\n'
    printf '    {"command_id": "boot_state", "status": "%s", "exit_code": %s, "timed_out": false},\n' "$BOOT_STATE_STATUS" "$BOOT_STATE_EXIT"
    printf '    {"command_id": "properties", "status": "%s", "exit_code": %s, "timed_out": false},\n' "$PROPERTIES_STATUS" "$PROPERTIES_EXIT"
    printf '    {"command_id": "mounts", "status": "%s", "exit_code": %s, "timed_out": false},\n' "$MOUNTS_STATUS" "$MOUNTS_EXIT"
    printf '    {"command_id": "selinux", "status": "%s", "exit_code": %s, "timed_out": false},\n' "$SELINUX_STATUS" "$SELINUX_EXIT"
    printf '    {"command_id": "root_state", "status": "%s", "exit_code": %s, "timed_out": false},\n' "$ROOT_STATE_STATUS" "$ROOT_STATE_EXIT"
    printf '    {"command_id": "magisk_state", "status": "%s", "exit_code": %s, "timed_out": false},\n' "$MAGISK_STATE_STATUS" "$MAGISK_STATE_EXIT"
    printf '    {"command_id": "process_state", "status": "%s", "exit_code": %s, "timed_out": false}\n' "$PROCESS_STATE_STATUS" "$PROCESS_STATE_EXIT"
    printf '  ]\n'
    printf '}\n'
  } > "$RESULTS_TMP"; then
    return 1
  fi
  chmod 0600 "$RESULTS_TMP" 2>/dev/null || return 1
  mv "$RESULTS_TMP" "$RESULTS" 2>/dev/null || return 1

  COMPLETION_STATUS=complete
  if { [ "$BOOT_RESULT" = timeout ] || [ "$BOOT_RESULT" = interrupted ]; } \
    || [ "$BOOT_STATE_STATUS" != observed ] \
    || [ "$PROPERTIES_STATUS" != observed ] \
    || [ "$MOUNTS_STATUS" != observed ] \
    || [ "$SELINUX_STATUS" != observed ] \
    || [ "$ROOT_STATE_STATUS" != observed ] \
    || [ "$MAGISK_STATE_STATUS" != observed ] \
    || [ "$PROCESS_STATE_STATUS" != observed ]; then
    COMPLETION_STATUS=partial
  fi
  {
    printf 'collector=trustlab-magisk\n'
    printf 'collection_method=%s\n' "$COLLECTION_METHOD"
    printf 'redaction_policy_version=atl_portable_v1\n'
    printf 'boot_completion=%s\n' "$BOOT_RESULT"
    if [ "$INTERRUPTED" -eq 1 ]; then
      printf 'warning=collector_interrupted\n'
    fi
    printf 'command=boot_state status=%s exit_code=%s\n' "$BOOT_STATE_STATUS" "$BOOT_STATE_EXIT"
    printf 'command=properties status=%s exit_code=%s\n' "$PROPERTIES_STATUS" "$PROPERTIES_EXIT"
    printf 'command=mounts status=%s exit_code=%s\n' "$MOUNTS_STATUS" "$MOUNTS_EXIT"
    printf 'command=selinux status=%s exit_code=%s\n' "$SELINUX_STATUS" "$SELINUX_EXIT"
    printf 'command=root_state status=%s exit_code=%s\n' "$ROOT_STATE_STATUS" "$ROOT_STATE_EXIT"
    printf 'command=magisk_state status=%s exit_code=%s\n' "$MAGISK_STATE_STATUS" "$MAGISK_STATE_EXIT"
    printf 'command=process_state status=%s exit_code=%s\n' "$PROCESS_STATE_STATUS" "$PROCESS_STATE_EXIT"
    printf 'completion_status=%s\n' "$COMPLETION_STATUS"
  } > "$LOG" || return 1
  chmod 0600 "$LOG" 2>/dev/null || return 1

  RAW_SIZE=$(artifact_size "$RAW")
  RAW_SHA256=$(sha256sum "$RAW" 2>/dev/null | awk '{print $1}')
  RESULTS_SIZE=$(artifact_size "$RESULTS")
  RESULTS_SHA256=$(artifact_sha256 "$RESULTS")
  LOG_SIZE=$(artifact_size "$LOG")
  LOG_SHA256=$(artifact_sha256 "$LOG")
  if ! valid_artifact_binding "$RAW" "$RAW_SIZE" "$RAW_SHA256" \
    || ! valid_artifact_binding "$RESULTS" "$RESULTS_SIZE" "$RESULTS_SHA256" \
    || ! valid_artifact_binding "$LOG" "$LOG_SIZE" "$LOG_SHA256"; then
    return 1
  fi
  BUNDLE_SIZE=$((RAW_SIZE + RESULTS_SIZE + LOG_SIZE))
  for BUNDLE_FILE in "$CAPTURE_DIR"/*.txt; do
    [ -f "$BUNDLE_FILE" ] || continue
    BUNDLE_FILE_SIZE=$(artifact_size "$BUNDLE_FILE")
    if ! printf '%s\n' "$BUNDLE_FILE_SIZE" | grep -Eq '^[0-9]+$'; then
      return 1
    fi
    BUNDLE_SIZE=$((BUNDLE_SIZE + BUNDLE_FILE_SIZE))
    [ "$BUNDLE_SIZE" -le "$MAX_BUNDLE_BYTES" ] || return 1
  done

  TS_END_ISO=$(utc_iso_time)
  [ -n "$TS_END_ISO" ] || TS_END_ISO=$TS_START_ISO
  COLLECTOR_VERSION=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -n 1)
  # Installer-only development suffixes are module packaging metadata, not a
  # collector schema version. Keep emitted portable manifests on the canonical
  # collector version used by the host validator.
  COLLECTOR_VERSION=${COLLECTOR_VERSION%%.installfix.*}
  COLLECTION_TOKEN=$(printf '%s:%s' "$RUN_ID" "$RAW_SHA256" \
    | sha256sum 2>/dev/null | awk '{print substr($1,1,16)}')
  if ! valid_iso_time "$TS_END_ISO" \
    || ! printf '%s\n' "$COLLECTOR_VERSION" \
      | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z][0-9A-Za-z.-]*)?$' \
    || ! valid_hex16 "$COLLECTION_TOKEN"; then
    return 1
  fi

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
    printf '  "completion_status": "%s",\n' "$COMPLETION_STATUS"
    printf '  "tool_versions": {"android_shell": "toybox", "trustlab_magisk": "%s"},\n' "$COLLECTOR_VERSION"
    printf '  "environment": {"platform": "android", "transport": "on_device", "execution_context": "magisk_module"},\n'
    printf '  "warnings": [],\n'
    printf '  "redaction_policy": {"policy_id": "atl_portable_v1", "redaction_state": "applied", "direct_identifiers_removed": true, "serials_removed": true, "secrets_removed": true},\n'
    printf '  "artifacts": [\n'
    printf '    {"logical_name": "raw_report", "relative_path": "raw.txt", "media_type": "text/plain", "byte_size": %s, "sha256": "%s", "probe_id": "magisk.readonly_snapshot", "status": "observed", "exit_code": 0, "timed_out": false, "sensitivity": "sensitive", "redaction_state": "redacted", "detail": null},\n' "$RAW_SIZE" "$RAW_SHA256"
    printf '    {"logical_name": "command_results", "relative_path": "command_results.json", "media_type": "application/json", "byte_size": %s, "sha256": "%s", "probe_id": "magisk.command_results", "status": "observed", "exit_code": 0, "timed_out": false, "sensitivity": "internal", "redaction_state": "redacted", "detail": null},\n' "$RESULTS_SIZE" "$RESULTS_SHA256"
    printf '    {"logical_name": "collector_log", "relative_path": "collector.log", "media_type": "text/plain", "byte_size": %s, "sha256": "%s", "probe_id": "magisk.collector_log", "status": "observed", "exit_code": 0, "timed_out": false, "sensitivity": "internal", "redaction_state": "redacted", "detail": null},\n' "$LOG_SIZE" "$LOG_SHA256"
    if [ "$BOOT_COMPLETION_STATUS" = observed ]; then
      BOOT_COMPLETION_PATH="$CAPTURE_DIR/boot_completion.txt"
      BOOT_COMPLETION_SIZE=$(artifact_size "$BOOT_COMPLETION_PATH")
      BOOT_COMPLETION_SHA=$(artifact_sha256 "$BOOT_COMPLETION_PATH")
      valid_artifact_binding "$BOOT_COMPLETION_PATH" "$BOOT_COMPLETION_SIZE" "$BOOT_COMPLETION_SHA" || return 1
      printf '    {"logical_name": "boot_completion", "relative_path": "captures/boot_completion.txt", "media_type": "text/plain", "byte_size": %s, "sha256": "%s", "probe_id": "magisk.boot_completion", "status": "observed", "exit_code": 0, "timed_out": false, "sensitivity": "internal", "redaction_state": "redacted", "detail": null},\n' "$BOOT_COMPLETION_SIZE" "$BOOT_COMPLETION_SHA"
    else
      printf '    {"logical_name": "boot_completion", "relative_path": null, "media_type": "text/plain", "byte_size": null, "sha256": null, "probe_id": "magisk.boot_completion", "status": "%s", "exit_code": %s, "timed_out": %s, "sensitivity": "internal", "redaction_state": "withheld", "detail": null},\n' "$BOOT_COMPLETION_STATUS" "$BOOT_COMPLETION_EXIT" "$BOOT_COMPLETION_TIMED_OUT"
    fi
    emit_capture_artifact boot_state boot_state internal "$BOOT_STATE_STATUS" "$BOOT_STATE_EXIT" || return 1
    printf ',\n'
    emit_capture_artifact properties properties sensitive "$PROPERTIES_STATUS" "$PROPERTIES_EXIT" || return 1
    printf ',\n'
    emit_capture_artifact mounts mounts sensitive "$MOUNTS_STATUS" "$MOUNTS_EXIT" || return 1
    printf ',\n'
    emit_capture_artifact selinux selinux internal "$SELINUX_STATUS" "$SELINUX_EXIT" || return 1
    printf ',\n'
    emit_capture_artifact root_state root_state restricted "$ROOT_STATE_STATUS" "$ROOT_STATE_EXIT" || return 1
    printf ',\n'
    emit_capture_artifact magisk_state magisk_state internal "$MAGISK_STATE_STATUS" "$MAGISK_STATE_EXIT" || return 1
    printf ',\n'
    emit_capture_artifact process_state process_state restricted "$PROCESS_STATE_STATUS" "$PROCESS_STATE_EXIT" || return 1
    printf '\n  ]\n'
    printf '}\n'
  } > "$MANIFEST_TMP"; then
    return 1
  fi
  chmod 0600 "$MANIFEST_TMP" 2>/dev/null || return 1
  mv "$MANIFEST_TMP" "$MANIFEST" 2>/dev/null || return 1

  # mkdir is the portable no-replace claim.  The final manifest hard link is
  # the atomic publication marker and cannot replace an existing file.
  if ! mkdir "$FINAL_DIR" 2>/dev/null; then
    fail 'final collection collision; existing output was preserved'
    return 1
  fi
  FINAL_CLAIMED=1
  chmod 0700 "$FINAL_DIR" 2>/dev/null || return 1
  if ! mkdir "$FINAL_DIR/captures" 2>/dev/null \
    || ! chmod 0700 "$FINAL_DIR/captures" 2>/dev/null; then
    rmdir "$FINAL_DIR" 2>/dev/null
    return 1
  fi
  if [ "$BOOT_COMPLETION_STATUS" = observed ]; then
    mv "$CAPTURE_DIR/boot_completion.txt" "$FINAL_DIR/captures/" 2>/dev/null || return 1
  fi
  publish_capture boot_state "$BOOT_STATE_STATUS" || return 1
  publish_capture properties "$PROPERTIES_STATUS" || return 1
  publish_capture mounts "$MOUNTS_STATUS" || return 1
  publish_capture selinux "$SELINUX_STATUS" || return 1
  publish_capture root_state "$ROOT_STATE_STATUS" || return 1
  publish_capture magisk_state "$MAGISK_STATE_STATUS" || return 1
  publish_capture process_state "$PROCESS_STATE_STATUS" || return 1
  if ! mv "$RAW" "$RESULTS" "$LOG" "$FINAL_DIR/" 2>/dev/null \
    || ! ln "$MANIFEST" "$FINAL_DIR/collector_manifest.json" 2>/dev/null; then
    fail 'atomic completion-manifest publication failed'
    return 1
  fi
  rm -f "$MANIFEST" 2>/dev/null
  rmdir "$CAPTURE_DIR" 2>/dev/null || return 1
  rmdir "$STAGING_DIR" 2>/dev/null || return 1
  PUBLISHED=1
  FINAL_CLAIMED=0
  STAGING_DIR=''
  printf '%s\n' "$FINAL_DIR/collector_manifest.json"
  [ "$COMPLETION_STATUS" = complete ]
}

# Invoked through trap(1), which ShellCheck cannot resolve statically.
# shellcheck disable=SC2329
on_interrupt() {
  trap '' HUP INT TERM
  INTERRUPTED=1
  if [ -n "$ACTIVE_CHILD" ]; then
    kill -TERM "$ACTIVE_CHILD" 2>/dev/null
    wait "$ACTIVE_CHILD" 2>/dev/null
  fi
  if [ -n "$ACTIVE_PROBE" ]; then
    rm -f "$CAPTURE_DIR/$ACTIVE_PROBE.txt" \
      "$STAGING_DIR/.${ACTIVE_PROBE}.capture" 2>/dev/null
    set_probe_result "$ACTIVE_PROBE" command_error 143
  fi
  finalize_collection || true
  exit 130
}
if [ -L "$TARGET_TOKEN_FILE" ] || { [ -e "$TARGET_TOKEN_FILE" ] && [ ! -f "$TARGET_TOKEN_FILE" ]; }; then
  fail 'refusing invalid target pseudonym path'
  exit 1
fi
if [ ! -f "$TARGET_TOKEN_FILE" ]; then
  TARGET_CANDIDATE=$(random_nonce)
  TARGET_TMP="$STAGING_DIR/.target_pseudonym"
  if ! valid_hex16 "$TARGET_CANDIDATE" \
    || ! printf '%s\n' "$TARGET_CANDIDATE" > "$TARGET_TMP" \
    || ! chmod 0600 "$TARGET_TMP" 2>/dev/null \
    || ! ln "$TARGET_TMP" "$TARGET_TOKEN_FILE" 2>/dev/null; then
    fail 'could not create target pseudonym'
    exit 1
  fi
  rm -f "$TARGET_TMP" 2>/dev/null
fi
chmod 0600 "$TARGET_TOKEN_FILE" 2>/dev/null || {
  fail 'could not protect target pseudonym'
  exit 1
}
TARGET_TOKEN=$(sed -n '1p' "$TARGET_TOKEN_FILE" 2>/dev/null)
TARGET_TOKEN_SIZE=$(wc -c < "$TARGET_TOKEN_FILE" 2>/dev/null | tr -d '[:space:]')
if [ "$TARGET_TOKEN_SIZE" != 17 ] || ! valid_hex16 "$TARGET_TOKEN"; then
  fail 'invalid target pseudonym'
  exit 1
fi

CURRENT_BOOT=$(getprop sys.boot_completed 2>&1)
CURRENT_BOOT_STATUS=$?
[ "$CURRENT_BOOT_STATUS" -eq 0 ] || CURRENT_BOOT=unknown
case "$CURRENT_BOOT" in 0|1) ;; *) CURRENT_BOOT=unknown ;; esac
BOOT_RESULT=$REQUESTED_BOOT_RESULT
if [ "$BOOT_RESULT" = auto ]; then
  if [ "$CURRENT_BOOT" = 1 ]; then BOOT_RESULT=complete; else BOOT_RESULT=incomplete; fi
elif [ "$BOOT_RESULT" = complete ] && [ "$CURRENT_BOOT" != 1 ]; then
  BOOT_RESULT=incomplete
fi
case "$BOOT_RESULT" in
  complete)
    if ! printf 'boot_completed=1\n' > "$CAPTURE_DIR/boot_completion.txt" \
      || ! chmod 0600 "$CAPTURE_DIR/boot_completion.txt" 2>/dev/null; then
      fail 'could not record boot completion result'
      exit 1
    fi
    BOOT_COMPLETION_STATUS=observed
    BOOT_COMPLETION_EXIT=0
    ;;
  incomplete)
    BOOT_COMPLETION_STATUS=observed_absent
    BOOT_COMPLETION_EXIT=0
    ;;
  timeout)
    BOOT_COMPLETION_STATUS=command_error
    BOOT_COMPLETION_EXIT=null
    BOOT_COMPLETION_TIMED_OUT=true
    ;;
  interrupted)
    BOOT_COMPLETION_STATUS=command_error
    BOOT_COMPLETION_EXIT=143
    ;;
esac

# Setup now contains a validated target and boot result, so an interruption can
# honestly publish retained evidence and structured unavailable statuses.
trap 'on_interrupt' HUP INT TERM

capture_probe boot_state "$MODDIR/scripts/collect_boot_state.sh"
capture_probe properties "$MODDIR/scripts/collect_props.sh"
capture_probe mounts "$MODDIR/scripts/collect_mounts.sh"
capture_probe selinux "$MODDIR/scripts/collect_selinux.sh"
capture_probe root_state "$MODDIR/scripts/collect_root_state.sh"
capture_probe magisk_state "$MODDIR/scripts/collect_magisk_state.sh"
capture_probe process_state "$MODDIR/scripts/collect_process_state.sh"

if finalize_collection; then
  exit 0
fi
if [ "$PUBLISHED" -eq 1 ]; then
  exit 2
fi
fail 'collection finalization failed'
exit 1
