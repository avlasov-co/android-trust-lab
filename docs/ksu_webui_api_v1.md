# KernelSU WebUI API v1

This document freezes the Android Trust Lab KernelSU WebUI boundary before the
user interface is implemented.  The WebUI is a privileged *management view*,
not a shell.  It can invoke only `scripts/webui_api.sh` through KernelSU's
official `spawn(command, args, options)` bridge with a fixed executable path
and a separately supplied argument array.

## Envelope

Every response written to standard output is one bounded JSON object:

```json
{"apiVersion":1,"ok":true,"data":{}}
```

or

```json
{"apiVersion":1,"ok":false,"error":{"code":"stable_machine_code","message":"Sanitized user-readable message."}}
```

Diagnostics never appear on standard output.  The frontend treats malformed or
oversized output as an `invalid_response` failure.

## Operations

`info`, `status`, and `list` take no arguments. `list` returns at most 50
newest-first summaries. `inspect ID`, `verify ID`, `export ID`, and `delete ID
DELETE:ID` require a canonical private collection directory ID. `collect` takes
no arguments and runs the same collection runner as boot and the module Action
button, with source `webui`.

The only accepted collection-ID grammar is:

```text
^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$
```

The backend additionally rejects `.` and `..`; it never consumes a path from
the WebUI. The delete confirmation is exactly `DELETE:<collection-id>`.

`inspect` exposes only manifest-derived identity, provenance, completion,
artifact names/statuses/sizes/hashes, warning count, and fixed limitations. It
does not return artifact contents. `verify` checks the complete manifest
publication marker, supported manifest version, regular manifest-declared files,
no links or special files, containment, declared-file closure, byte sizes, and
SHA-256 values. `export` first performs that same verification, then copies only
verified declared files to the fixed non-overwriting location
`/sdcard/Download/AndroidTrustLab/<id>/`, publishing the manifest last.

`delete` only deletes a verified private directory below the fixed collection
root. It refuses the root, links, aliases, malformed IDs, and an active locked
collection. It never operates on shared storage.

## Stable errors

The v1 error codes are `invalid_command`, `invalid_arguments`, `invalid_id`,
`not_found`, `busy`, `incomplete_collection`, `verification_failed`,
`export_exists`, `export_failed`, `delete_refused`, `collection_failed`, and
`internal_error`. Their messages are deliberately non-diagnostic.
