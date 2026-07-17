#!/system/bin/sh
# Constrained KernelSU WebUI API v1. This is intentionally not a shell API.
umask 077

API_VERSION=1
MAX_LIST=50
BASE_DIR="/data/adb/android-trust-lab"
OUT_DIR="$BASE_DIR/reports"
LOCK_DIR="$BASE_DIR/collector.lock"
EXPORT_PARENT="/sdcard/Download/AndroidTrustLab"
MODDIR=${0%/*}/..
RUNNER="$MODDIR/scripts/run_collection.sh"

json_string() {
  # JSON cannot carry raw controls. Preserve line boundaries only as spaces;
  # backend data is display metadata, never evidence content.
  printf '"'
  printf '%s' "$1" | awk 'BEGIN { ORS="" } { if (NR > 1) printf " "; gsub(/[[:cntrl:]]/, " "); gsub(/["\\]/, "\\\\&"); printf "%s", $0 }'
  printf '"'
}
success() { printf '{"apiVersion":%s,"ok":true,"data":%s}\n' "$API_VERSION" "$1"; }
failure() { printf '{"apiVersion":%s,"ok":false,"error":{"code":' "$API_VERSION"; json_string "$1"; printf ',"message":'; json_string "$2"; printf '}}\n'; }

valid_id() {
  case "$1" in .|..|''|*[!A-Za-z0-9._-]*|?????????????????????????????????????????????????????????????????????????????????????????????????*) return 1;; esac
  printf '%s\n' "$1" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$'
}
bundle_path() {
  valid_id "$1" || return 1
  BUNDLE="$OUT_DIR/$1"
  case "$BUNDLE" in "$OUT_DIR"/*) ;; *) return 1;; esac
  [ -d "$BUNDLE" ] && [ ! -L "$BUNDLE" ]
}
manifest_value() { sed -n "s/^[[:space:]]*\"$1\": \"\([^\"]*\)\".*/\1/p" "$2" | head -n 1; }
source_for_bundle() {
  method=$(sed -n 's/.*"collection_method": "\([a-z_]*\)".*/\1/p' "$1" | head -n 1)
  case "$method" in magisk_module_boot) printf boot;; magisk_module_webui) printf webui;; *) printf action;; esac
}
safe_artifact_path() {
  case "$1" in raw.txt|command_results.json|collector.log) return 0;; captures/*)
    base=${1#captures/}; case "$base" in ''|*/*|.txt|*[!a-z0-9_]*.txt) return 1;; *) return 0;; esac;; *) return 1;; esac
}
bundle_size() { find "$1" -type f -exec wc -c {} \; 2>/dev/null | awk '{s += $1} END {print s + 0}'; }
artifact_count() { sed -n 's/.*"logical_name": "[A-Za-z0-9_]*".*"status": "observed".*/x/p' "$1" | wc -l | tr -d '[:space:]'; }
cleanup_verify_tmp() {
  case "${VERIFY_TMP:-}" in "$BASE_DIR"/.webui_verify_*) rm -rf "$VERIFY_TMP" 2>/dev/null;; esac
  VERIFY_TMP=''
}

# Verify the actual closed collection tree. No diagnostics or evidence leave it.
verify_bundle() {
  VERIFY_CODE=verification_failed; VERIFY_ARTIFACTS=0; VERIFY_DIR=$1; manifest="$VERIFY_DIR/collector_manifest.json"
  [ -d "$VERIFY_DIR" ] && [ ! -L "$VERIFY_DIR" ] && [ -f "$manifest" ] && [ ! -L "$manifest" ] || return 1
  grep -Eq '^[[:space:]]*"schema_version": "1\.0\.0",?$' "$manifest" || return 1
  grep -Eq '^[[:space:]]*"completion_status": "complete",?$' "$manifest" || { VERIFY_CODE=incomplete_collection; return 1; }
  find "$VERIFY_DIR" -type l -print 2>/dev/null | grep -q . && return 1
  find "$VERIFY_DIR" -mindepth 1 ! -type f ! -type d -print 2>/dev/null | grep -q . && return 1
  VERIFY_TMP="$BASE_DIR/.webui_verify_$$"; rm -rf "$VERIFY_TMP" 2>/dev/null; mkdir "$VERIFY_TMP" 2>/dev/null || return 1
  sed -n 's/.*"relative_path": "\([^"]*\)".*"byte_size": \([0-9][0-9]*\), "sha256": "\([0-9a-f][0-9a-f]*\)".*/\1|\2|\3/p' "$manifest" > "$VERIFY_TMP/declared"
  [ -s "$VERIFY_TMP/declared" ] || { rm -rf "$VERIFY_TMP"; return 1; }
  # shellcheck disable=SC2094
  while IFS='|' read -r rel size digest; do
    if ! safe_artifact_path "$rel" \
      || ! printf '%s\n' "$size" | grep -Eq '^[0-9]+$' \
      || ! printf '%s\n' "$digest" | grep -Eq '^[0-9a-f]{64}$'; then
      cleanup_verify_tmp
      return 1
    fi
    [ "$(grep -Fxc "$rel|$size|$digest" "$VERIFY_TMP/declared")" -eq 1 ] || { cleanup_verify_tmp; return 1; }
    file="$VERIFY_DIR/$rel"; [ -f "$file" ] && [ ! -L "$file" ] || { cleanup_verify_tmp; return 1; }
    [ "$(wc -c < "$file" 2>/dev/null | tr -d '[:space:]')" = "$size" ] && [ "$(sha256sum "$file" 2>/dev/null | awk '{print $1}')" = "$digest" ] || { cleanup_verify_tmp; return 1; }
    VERIFY_ARTIFACTS=$((VERIFY_ARTIFACTS + 1))
  done < "$VERIFY_TMP/declared"
  find "$VERIFY_DIR" -type f -print 2>/dev/null > "$VERIFY_TMP/files"
  while IFS= read -r file; do
    rel=${file#"$VERIFY_DIR"/}; [ "$rel" = collector_manifest.json ] && continue
    awk -F'|' -v p="$rel" '$1 == p {ok=1} END {exit ok ? 0 : 1}' "$VERIFY_TMP/declared" || { cleanup_verify_tmp; return 1; }
  done < "$VERIFY_TMP/files"
  VERIFY_CODE=verified
  return 0
}
last_complete_id() {
  find "$OUT_DIR" -mindepth 1 -maxdepth 1 -type d -name 'run_*' -print 2>/dev/null | sort -r | while IFS= read -r dir; do
    if [ ! -f "$dir/collector_manifest.json" ] \
      || ! grep -Eq '^[[:space:]]*"completion_status": "complete",?$' "$dir/collector_manifest.json"; then
      continue
    fi
    basename "$dir"; break
  done
}

op_info() {
  id=$(sed -n 's/^id=\([a-z0-9._-]*\)$/\1/p' "$MODDIR/module.prop" | head -n 1); version=$(sed -n 's/^version=\([A-Za-z0-9._-]*\)$/\1/p' "$MODDIR/module.prop" | head -n 1)
  [ -n "$id" ] && [ -n "$version" ] || { failure internal_error 'Module metadata is unavailable.'; return; }
  collector=${version%%.installfix.*}
  success "{\"moduleId\":$(json_string "$id"),\"moduleVersion\":$(json_string "$version"),\"collectorVersion\":$(json_string "$collector"),\"webuiApiVersion\":1,\"observerType\":\"root_collector\",\"capabilities\":[\"status\",\"collect\",\"list\",\"inspect\",\"verify\",\"export\",\"delete\"],\"privateOutputNotice\":\"Evidence remains private until you explicitly export a verified collection.\"}"
}
op_status() {
  state=idle; lock=unlocked; current=''; stage=idle
  if [ -d "$LOCK_DIR" ] && [ ! -L "$LOCK_DIR" ]; then state=running; lock=locked; stage=collecting; current=$(sed -n 's/^collection_id=\([A-Za-z0-9._-]*\)$/\1/p' "$LOCK_DIR/owner" 2>/dev/null | head -n1); valid_id "$current" || current=''
  elif find "$OUT_DIR" -mindepth 1 -maxdepth 1 -type d -name '.partial_*' -print 2>/dev/null | grep -q .; then state=partial; stage=partial_publication; fi
  last=$(last_complete_id)
  success "{\"state\":$(json_string "$state"),\"currentCollectionId\":$(json_string "$current"),\"startedAt\":null,\"stage\":$(json_string "$stage"),\"lastCompleteCollection\":$(json_string "$last"),\"warningCount\":0,\"lockState\":$(json_string "$lock")}"
}
op_list() {
  printf '{"apiVersion":%s,"ok":true,"data":{"collections":[' "$API_VERSION"; first=1
  find "$OUT_DIR" -mindepth 1 -maxdepth 1 -type d -name 'run_*' -print 2>/dev/null | sort -r | head -n "$MAX_LIST" | while IFS= read -r dir; do
    id=$(basename "$dir"); valid_id "$id" || continue; manifest="$dir/collector_manifest.json"; status=partial; source=action; started=''; ended=''; digest=''; count=0; verified=false
    if [ -f "$manifest" ] && [ ! -L "$manifest" ]; then status=$(manifest_value completion_status "$manifest"); case "$status" in complete|partial|failed) ;; *) status=error;; esac; source=$(source_for_bundle "$manifest"); started=$(manifest_value started_at "$manifest"); ended=$(manifest_value ended_at "$manifest"); digest=$(sha256sum "$manifest" 2>/dev/null | awk '{print $1}'); count=$(artifact_count "$manifest"); verify_bundle "$dir" && verified=true; cleanup_verify_tmp; fi
    [ "$first" -eq 1 ] || printf ','; first=0
    printf '{"collectionId":%s,"source":%s,"startedAt":%s,"endedAt":%s,"status":%s,"totalSize":%s,"artifactCount":%s,"warningCount":0,"manifestDigest":%s,"verified":%s}' "$(json_string "$id")" "$(json_string "$source")" "$(json_string "$started")" "$(json_string "$ended")" "$(json_string "$status")" "$(bundle_size "$dir")" "$count" "$(json_string "$digest")" "$verified"
  done
  printf ']}}\n'
}
op_inspect() {
  bundle_path "$1" || { failure not_found 'The private collection was not found.'; return; }; manifest="$BUNDLE/collector_manifest.json"; [ -f "$manifest" ] && [ ! -L "$manifest" ] || { failure verification_failed 'The collection manifest is unavailable.'; return; }
  printf '{"apiVersion":%s,"ok":true,"data":{"collectionId":%s,"identity":%s,"source":%s,"startedAt":%s,"endedAt":%s,"completion":%s,"schemaVersion":%s,"artifacts":[' "$API_VERSION" "$(json_string "$1")" "$(json_string "$(manifest_value collection_id "$manifest")")" "$(json_string "$(source_for_bundle "$manifest")")" "$(json_string "$(manifest_value started_at "$manifest")")" "$(json_string "$(manifest_value ended_at "$manifest")")" "$(json_string "$(manifest_value completion_status "$manifest")")" "$(json_string "$(manifest_value schema_version "$manifest")")"
  first=1; sed -n 's/.*"logical_name": "\([A-Za-z0-9_]*\)".*"relative_path": \("[^"]*"\|null\).*"byte_size": \([0-9]*\|null\).*"sha256": \("[0-9a-f]*"\|null\).*"status": "\([a-z_]*\)".*/\1|\2|\3|\4|\5/p' "$manifest" | while IFS='|' read -r name _path size hash status; do [ "$first" -eq 1 ] || printf ','; first=0; hash=${hash#\"}; hash=${hash%\"}; [ "$hash" = null ] && hash=''; [ "$size" = null ] && size=0; printf '{"name":%s,"status":%s,"size":%s,"sha256":%s}' "$(json_string "$name")" "$(json_string "$status")" "$size" "$(json_string "$hash")"; done
  printf '],"warningCount":0,"limitations":["Raw evidence is not displayed in WebUI v1.","This collector does not certify device security."]}}\n'
}
op_verify() { bundle_path "$1" || { failure not_found 'The private collection was not found.'; return; }; if verify_bundle "$BUNDLE"; then count=$VERIFY_ARTIFACTS; cleanup_verify_tmp; success "{\"collectionId\":$(json_string "$1"),\"verified\":true,\"artifactCount\":$count}"; elif [ "$VERIFY_CODE" = incomplete_collection ]; then cleanup_verify_tmp; failure incomplete_collection 'Only complete collections can be verified.'; else cleanup_verify_tmp; failure verification_failed 'The collection did not pass integrity verification.'; fi; }
op_collect() { [ -x "$RUNNER" ] || { failure internal_error 'Collection runner is unavailable.'; return; }; sh "$RUNNER" webui >/dev/null 2>/dev/null; case "$?" in 0) success '{"started":true,"source":"webui"}';; 75) failure busy 'A collection is already running.';; *) failure collection_failed 'Collection did not complete.';; esac; }
op_export() {
  bundle_path "$1" || { failure not_found 'The private collection was not found.'; return; }; verify_bundle "$BUNDLE" || { cleanup_verify_tmp; failure "$VERIFY_CODE" 'The collection must be complete and pass verification before export.'; return; }
  [ -L "$EXPORT_PARENT" ] && { cleanup_verify_tmp; failure export_failed 'The fixed export location is unavailable.'; return; }; mkdir -p "$EXPORT_PARENT" 2>/dev/null || { cleanup_verify_tmp; failure export_failed 'The fixed export location is unavailable.'; return; }; [ -d "$EXPORT_PARENT" ] && [ ! -L "$EXPORT_PARENT" ] || { cleanup_verify_tmp; failure export_failed 'The fixed export location is unavailable.'; return; }; dest="$EXPORT_PARENT/$1"; [ ! -e "$dest" ] || { cleanup_verify_tmp; failure export_exists 'An export with this collection ID already exists.'; return; }; tmp="$EXPORT_PARENT/.partial_$1_$$"; mkdir "$tmp" 2>/dev/null || { cleanup_verify_tmp; failure export_failed 'Could not prepare the export.'; return; }
  # Atomically claim the non-overwriting destination before touching it. This
  # prevents a shared-storage symlink swap from redirecting root's writes.
  if ! mkdir "$dest" 2>/dev/null || [ -L "$dest" ]; then rm -rf "$tmp"; cleanup_verify_tmp; failure export_exists 'An export with this collection ID already exists.'; return; fi
  while IFS='|' read -r rel size hash; do target="$tmp/$rel"; if ! mkdir -p "$(dirname "$target")" 2>/dev/null || ! cp "$BUNDLE/$rel" "$target" 2>/dev/null; then rm -rf "$tmp" "$dest"; cleanup_verify_tmp; failure export_failed 'Could not copy the verified collection.'; return; fi; done < "$VERIFY_TMP/declared"
  while IFS='|' read -r rel size hash; do target="$dest/$rel"; if [ -L "$EXPORT_PARENT" ] || [ -L "$dest" ] || ! mkdir -p "$(dirname "$target")" 2>/dev/null || ! mv "$tmp/$rel" "$target" 2>/dev/null; then rm -rf "$tmp" "$dest"; cleanup_verify_tmp; failure export_failed 'Could not publish the export.'; return; fi; done < "$VERIFY_TMP/declared"
  if ! cp "$BUNDLE/collector_manifest.json" "$dest/collector_manifest.json" 2>/dev/null; then rm -rf "$tmp" "$dest"; cleanup_verify_tmp; failure export_failed 'Could not publish the export.'; return; fi; rm -rf "$tmp"; cleanup_verify_tmp; success "{\"collectionId\":$(json_string "$1"),\"path\":$(json_string "$dest")}";
}
op_delete() {
  bundle_path "$1" || { failure not_found 'The private collection was not found.'; return; }; [ "$2" = "DELETE:$1" ] || { failure delete_refused 'The deletion confirmation did not match this collection.'; return; }; active=$(sed -n 's/^collection_id=\([A-Za-z0-9._-]*\)$/\1/p' "$LOCK_DIR/owner" 2>/dev/null | head -n1); [ "$active" != "$1" ] || { failure delete_refused 'The active collection cannot be deleted.'; return; }; find "$BUNDLE" -type l -print 2>/dev/null | grep -q . && { failure delete_refused 'Linked collections cannot be deleted.'; return; }; rm -rf "$BUNDLE" 2>/dev/null; [ ! -e "$BUNDLE" ] || { failure delete_refused 'The private collection could not be deleted.'; return; }; success "{\"collectionId\":$(json_string "$1"),\"deleted\":true}";
}

case "$#:$1" in
  1:info) op_info;; 1:status) op_status;; 1:list) op_list;; 1:collect) op_collect;;
  2:inspect) if valid_id "$2"; then op_inspect "$2"; else failure invalid_id 'The collection ID is invalid.'; fi;;
  2:verify) if valid_id "$2"; then op_verify "$2"; else failure invalid_id 'The collection ID is invalid.'; fi;;
  2:export) if valid_id "$2"; then op_export "$2"; else failure invalid_id 'The collection ID is invalid.'; fi;;
  3:delete) if valid_id "$2"; then op_delete "$2" "$3"; else failure invalid_id 'The collection ID is invalid.'; fi;;
  0:*|1:*) failure invalid_command 'The requested operation is not available.';; *) failure invalid_arguments 'This operation received invalid arguments.';;
esac
