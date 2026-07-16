# Host Snapshot Collection

Collect bounded host-side provenance before target collection:

```bash
trustlab collect host --output PRIVATE_COLLECTION_ROOT
```

Each successful run publishes one uniquely named `atlcol-*` directory beneath
the requested root. Publication is atomic, files are private by default, and
`collector_manifest.json` is written only after every other collection file.
The command follows the CLI write contract and is silent on success.

## Collects

- project and Python versions;
- host OS, kernel release summary, and architecture;
- `adb version` without contacting an Android target;
- Android SDK manager, AVD manager, and emulator versions; and
- an optional emulator AVD inventory with names replaced by collection-local
  ordinal labels.

Every reviewed subprocess uses an exact argument array, a five-second default
timeout, bounded stdout/stderr capture, and an explicit status, exit code, and
timeout flag. Windows resolves reviewed `.exe`, `.bat`, or `.cmd` tool names to
an executable path without recording that host path. Missing tools are recorded
as `unsupported`; non-zero exits and timeouts are non-fatal `command_error`
results. Version-command output is reduced to version tokens and redacted-line
placeholders before it is written. Windows collection requires Python 3.13 or
newer so the private staging directory receives a restricted current-user ACL.
Windows commands are started suspended inside a kill-on-close Job Object so a
timeout also terminates descendants that inherited capture handles.

The collector never records usernames, home-directory paths, environment
secrets, process lists, transport serials, or unrelated host data. Its ADB
allowlist contains only `adb version`: it does not enumerate or invoke a target.

## Purpose

Preserve provenance with
`collector/schema/collection_manifest_v1_0_0.schema.json`. Host, ADB, app, and
root observers use this same contract; observed artifacts are bound by relative
path, byte size, and SHA-256. Reports without portable provenance are not
suitable for reproducible comparison.

This Step 26 output is provenance-only and does not contain the `raw_report`
artifact required by `trustlab normalize --manifest`. Retain it beside later
target collections; do not treat host vocabulary as Android target evidence.
