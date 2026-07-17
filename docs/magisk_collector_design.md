# Magisk Collector Design

The Magisk module is a read-only privileged observer for Android Trust Lab. It
captures a root-side view without changing properties, SELinux policy, mounts,
boot state, Magisk installation, root visibility, or integrity behavior.
`skip_mount` remains present; the module has no overlay payload.

## Collection boundary

The collector may observe reviewed boot and security properties, projected
mount state, SELinux mode and its own context, fixed root/Magisk facts, and the
seven project-selected process names. Root visibility is useful comparative
evidence, not hardware-backed proof.

The runtime never invokes `adb root`, `adb remount`, `su`, `setprop`, `mount`,
reboot or bootloader commands, boot patching, Magisk installation, hiding, or
integrity-bypass behavior. It reads `/proc/self/mountinfo` and `/proc/mounts`
directly and projects them field by field; it does not execute the `mount`
utility.

The property set exactly matches the host/ADB collector:

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

Each value passes a field-specific grammar or becomes `unknown`. The collector
does not retain build fingerprints, product identity, boot reason, slot-derived
identity, device serials, raw process rows, command arguments, arbitrary
SELinux contexts, mount sources, device identifiers, or unreviewed paths.
Magisk version names are projected to a fixed redacted token. Arbitrary stderr
is never copied into portable output.

## Runtime lifecycle

1. Set `umask 077`, create and re-protect the base, reports, and event
   directories as `0700`, and reject symlinked output anchors.
2. Acquire `/data/adb/android-trust-lab/collector.lock` with atomic `mkdir`.
   A losing invocation writes only a unique private `already_running` event and
   exits `75`; it never removes a live winning lock or starts another collection.
   The private owner record binds the shell PID and `/proc` start tick so a
   definitively dead or PID-reused owner can be recovered without stealing a
   live lock after abnormal termination. An uncatchable stop before that record
   is written can leave an ownerless directory. Only a structurally empty lock
   (or empty recovery mutex) aged at least five minutes is reclaimable; fresh
   locks and locks with unknown contents remain conservatively unavailable.
3. Read exactly 32 bytes from `/dev/urandom` into a mode-`0600` lock-owned file,
   verify its length, hash it, and derive a 16-hex nonce. The run directory name
   combines that nonce with a UTC timestamp.
4. Create a private hidden staging directory and capture each probe through a
   host-executable POSIX-shell orchestrator. Fixed exit-code classes become
   `observed`, `inaccessible`, `unsupported`, or `command_error`; unstarted
   probes remain `not_collected`.
5. Generate the deterministic raw aggregate, structured
   `command_results.json`, sanitized `collector.log`, sizes, SHA-256 digests,
   and strict collection-manifest `1.0.0` document.
6. Atomically claim a fresh final directory with `mkdir`, move only complete
   artifacts into it, and hard-link `collector_manifest.json` last. The hard
   link is same-filesystem, atomic, and non-replacing. Consumers treat only that
   validated manifest as the publication marker.
7. Remove the staging directory and owned lock. `HUP`, `INT`, and `TERM` stop
   the active child and pass through the same finalization path as a valid
   partial collection. `KILL` cannot be trapped and can leave staging or a lock
   quarantined for stale recovery, but no completion marker.

Existing final paths are never replaced or nested into. Directories are `0700`
and retained files are `0600`. The stable `target_pseudonym` is random,
mode `0600`, validated before use, and never derived from a serial or evidence
bytes.

## Output contract

```text
/data/adb/android-trust-lab/reports/run_<UTC>_<16-hex-nonce>/
  captures/                    0700
    boot_completion.txt        0600 when observed
    boot_state.txt             0600 when observed
    properties.txt             0600 when observed
    mounts.txt                 0600 when observed
    selinux.txt                0600 when observed
    root_state.txt             0600 when observed
    magisk_state.txt           0600 when observed
    process_state.txt          0600 when observed
  raw.txt                      0600
  command_results.json         0600
  collector.log                0600
  collector_manifest.json      0600, linked last
```

The manifest records module/collector version, start and end UTC timestamps,
collection method, boot-completion outcome, per-probe statuses and timeout
flags, warnings (reserved as an empty array), redaction policy version,
sensitivity, file sizes, and SHA-256 digests. `atl_portable_v1` is the explicit
redaction version.

A boot-service timeout is `boot_completion: command_error` with
`timed_out: true` and makes the collection partial. An interruption or required
probe failure also makes it partial. A manual run that successfully observes
`sys.boot_completed=0` records `boot_completion: observed_absent`; it does not
mislabel a successful observation as a command failure.

Complete output can be verified, privately copied, normalized, and
content-addressed with:

```bash
trustlab import magisk --input COLLECTION_DIR --output PRIVATE_IMPORT_ROOT
```

Partial output remains intentionally rejected by that default import path and
can be examined explicitly with `trustlab normalize --manifest`.

## Entrypoints

- `post-fs-data.sh` performs no early-boot collection or mutation.
- `service.sh` waits up to 120 seconds, reports timeout explicitly, invokes one
  late-boot collection without suppressing its output or exit status, and exits.
  `HUP`, `INT`, or `TERM` during the wait invokes the writer with an explicit
  interrupted boot outcome and publishes a valid partial collection.
- `action.sh` starts one manual collection through the Magisk action UI.
- `uninstall.sh` preserves private reports, event records, and target identity.

## Limitations

The mount projection intentionally trades raw topology detail for portable
privacy. Filtered process evidence cannot prove that an unlisted process is
absent. Hashes establish internal integrity and identity, not producer
authentication or hardware-backed trust.
