# ADB Snapshot Collection

`trustlab collect adb --serial SERIAL --output PRIVATE_COLLECTION_ROOT` records
shell-visible trust-state evidence from one owned or explicitly authorized target.
The command is read-only: it does not root, remount, reboot, install, pull, push,
or write to the target.

## Selection and identity

Collection first runs the bounded host query `adb devices`, requires exactly one
listed target matching `SERIAL` in the `device` state, and then confirms that
selection with `adb -s SERIAL get-state`. No shell command runs before both
checks succeed. Offline, unauthorized, multiple-device, permission, missing-tool,
and timeout failures are distinct and never include the serial in diagnostics.

The raw serial exists only in the process argument array and the in-memory
device-list comparison. Portable provenance uses `<selected-target>` and a
`target-<16 hex>` HMAC pseudonym derived from the serial and the private 32-byte
project salt at
`PRIVATE_COLLECTION_ROOT/.trustlab-adb-private/.trustlab-adb-project-salt`.
The dedicated state directory is mode `0700`, the salt is mode `0600`, neither
enters a collection directory, and the pseudonym is stable only for that
project output root.

Windows uses an external project secret instead of relying on inherited file
ACLs: set `TRUSTLAB_ADB_PROJECT_SALT` to exactly 64 lowercase hexadecimal
characters. The value is read only for HMAC derivation, is removed from child
process environments, and is never serialized.

## Reviewed command interface

Every device command is an exact argument array beginning with
`adb -s SERIAL`. The immutable allowlist contains only:

```text
adb devices
adb -s SERIAL get-state
adb -s SERIAL shell getprop EXACT_ALLOWLISTED_KEY
adb -s SERIAL shell id
adb -s SERIAL shell getenforce
adb -s SERIAL shell cat /proc/self/mountinfo
adb -s SERIAL shell cat /proc/mounts
adb -s SERIAL shell id -Z
adb -s SERIAL shell ps -A -o LABEL,NAME
adb -s SERIAL shell ps -A -o NAME
```

`/proc/mounts` is attempted only when `/proc/self/mountinfo` is unavailable,
empty, truncated, or malformed. The name-only `ps` form is likewise a
compatibility fallback. The collector never invokes `mount`, a shell wrapper,
redirection, a broad `getprop`, the kernel command line, process arguments, or
any mutation command.

The selected property allowlist is:

```text
ro.boot.verifiedbootstate
ro.boot.flash.locked
ro.boot.vbmeta.device_state
ro.boot.veritymode
ro.build.version.release
ro.build.version.sdk
ro.debuggable
ro.secure
ro.adb.secure
sys.boot_completed
ro.kernel.qemu
```

The four `ro.boot.*` fields are the narrowly scoped boot-state evidence;
`sys.boot_completed` records boot completion; `ro.kernel.qemu` classifies the
controlled emulator context without collecting product identity or a build
fingerprint.

Process output is projected in memory to the exact names `init`, `adbd`,
`zygote`, `zygote64`, `system_server`, `magisk`, and `magiskd`. Portable output
retains only those names and sanitized SELinux domains—never PIDs, users,
arguments, unrelated process names, or raw stderr. A selected process view
cannot prove that an unlisted process is absent.

## Output contract

Each `atlcol-*` directory is mode `0700`; files are mode `0600`. Collection uses
an exclusive lock, randomized staging directory, bounded stdout/stderr capture,
per-command deadlines, process-tree cleanup, hashes, and one atomic directory
rename. `collector_manifest.json` is validated and written last.

```text
atlcol-<id>/
  captures/*.txt
  adb_snapshot.txt
  adb_provenance.json
  collector_manifest.json
```

`adb_snapshot.txt` is the unique normalizable `raw_report` and uses the legacy
section markers `GETPROP`, `MOUNTINFO`, `PROC_MOUNTS`, `ID`, `GETENFORCE`,
`SELINUX_CONTEXT`, and `PS_SELECTED`. `adb_provenance.json` records each redacted
logical argv, timeout, exit code, status, stdout/stderr disposition,
sensitivity, redaction state, and closed reason code. The outer manifest also
records every probe outcome so a failed preferred command plus a usable fallback
is an honest `partial` collection rather than an apparent absence.

Normalize a completed or partial collection with:

```bash
trustlab normalize \
  --manifest PRIVATE_COLLECTION_ROOT/atlcol-ID/collector_manifest.json \
  --output report.json
```

All captures remain sensitive lab evidence even after serial and identifier
projection. Share only under the repository privacy policy.
