# App Probe Design and Contract

The Android observer is an optional, unprivileged, user-initiated measurement
source. It reports only facts visible through public Android APIs or bounded
reads from the app's own sandbox view. It does not certify a device, calculate
a trust score, or attempt to obtain a stronger observer position.

## Versioning and compatibility

`app_probe_v1_0_0.schema.json` is a historical, command-shaped placeholder. It
remains readable so existing fixtures and reports do not change, but the app
never writes it.

The write contract is `app_probe_v2_0_0.schema.json` with artifact kind
`app_probe_json`. Version 2 is a closed typed document: it has no stdout,
stderr, shell exit status, arbitrary source path, free-form warning, or
unbounded key/value channel. The analyzer selects the schema by the declared
version and never treats an unknown version as the newest version.

The collection-manifest and normalized-report wire versions remain 1.0.0 and
6.0.0 respectively. A v1 collection manifest binds the v2 JSON as its unique
observed `raw_report`, with relative path `app_probe.json`, media type
`application/json`, probe ID `app.raw_report`, exact byte length and SHA-256,
and redaction state `redacted`.

Artifact and manifest metadata must agree exactly for collector version,
observer, collection ID, experiment, target, timestamps, completion state,
environment, and redaction policy. The analyzer rejects a mismatch. Every
non-observed probe is also represented by a null-path manifest outcome so a
partial collection cannot hide which capability was inaccessible,
unsupported, or failed.

The target pseudonym is a random app-scoped value stored in private app
preferences and reused across collections so repeated measurements remain
comparable. It is not derived from a hardware, account, advertising, Android,
or network identifier. Clearing app data intentionally creates a new target
context; every collection still receives a fresh collection ID.

## Artifact layout

The top-level v2 object contains:

- fixed artifact, collector, observer, environment, and redaction metadata;
- collection ID, experiment, pseudonymous target, start/end timestamps, and
  completion status;
- exactly one result for every required probe.

Each result contains a closed probe ID, mechanism (`public_api`, `procfs`, or
`filesystem`), a capability name and minimum SDK, a semantic source reference,
one of the four statuses below, a typed value, and a sanitized diagnostic.

| Status | Meaning |
|---|---|
| `observed` | The public API or bounded read completed and produced a typed value. A negative value or empty indicator set is still observed evidence. |
| `inaccessible` | The capability exists, but the app sandbox or platform denied access. |
| `unsupported` | The public API or pseudo-file capability is not available on this platform. |
| `error` | The capability was attempted but bounded I/O, parsing, or an unexpected platform failure prevented a trustworthy value. |

An observed result has a non-null value and no diagnostic. Every other result
has a null value and one categorical diagnostic. Raw exception messages,
stack traces, errno text, paths, and arbitrary exception class names are never
serialized. The app maps expected failures to an allowlist of exception classes
and stable message codes.

The required probe set is fixed and duplicate or missing results are invalid:

- `build_version`;
- `app_identity`;
- `install_source`;
- `selinux_self_context`;
- `file_system_shell`;
- `file_system_su`;
- `file_system_xbin_su`;
- `file_vendor_bin_su`;
- `file_sbin_su`;
- `proc_self_status`;
- `proc_self_mountinfo`;
- `emulator_indicators`.

The five file probes use fixed internal paths but export only logical path IDs.
Existence and readability are distinct typed outcomes, so an observed existing
file remains recorded even if access is denied. Readability uses the public,
non-opening `Os.access` check after `Os.stat`, so a replaced FIFO or device node
cannot block collection. `ENOENT` is an
observed negative existence result for these allowlisted paths; access denial
is never converted to absence.

## Collected and redacted fields

The build probe retains only SDK, release, security patch, base OS, categorized
build type/tags, supported ABI tokens, and a SHA-256 of the build fingerprint.
It never reads or exports `Build.SERIAL`, `getSerial`, build host/user,
Android ID, radio identifiers, or hardware identifiers.

The identity probe records `Process.myUid()` and whether this installed app has
`ApplicationInfo.FLAG_DEBUGGABLE`. The latter is explicitly an app property,
not the device-wide `ro.debuggable` property. No Android user/profile ID is
derived from the UID.

The install-source probe queries only the observer package. It uses
`getInstallSourceInfo` on API 30 and newer and the narrow legacy self-package
fallback on API 26 through 29. It emits the API variant, whether an installer
was present, and an allowlisted source category; it does not emit package names,
initiating/originating identities, signatures, or package inventory.

The SELinux probe performs a bounded read of `/proc/self/attr/current`, parses
one context, strips MLS/MCS categories, and exports only the safe base context.
It does not use hidden `android.os.SELinux` APIs.

The `/proc/self/status` probe retains only `NoNewPrivs`, `Seccomp`,
`Seccomp_filters`, and whether `CapEff` and `CapBnd` are nonzero. It excludes
process names, PIDs, parent/tracer IDs, groups, command lines, environment,
maps, file descriptors, and raw lines.

The mountinfo probe reads at most 1 MiB and parses the app's own mount namespace
on-device. It exports bounded counts and selected logical mount categories with
a sanitized filesystem type, read-only flag, and overlay flag. It never exports
raw lines, mount IDs, device numbers, sources, options, arbitrary APEX labels,
app-private paths, or user-storage paths. This filtered view is app-visible
context and is not promoted to a complete device-global mount assessment.

Emulator indicators are a closed set derived from the already-read Build
fields. An empty set means only that no selected indicator was observed; it is
not evidence that the target is physical.

## Analyzer mapping

The v2 Python adapter validates the complete typed document before extracting
evidence. It maps Build version to report Android-version/SDK evidence, the
sanitized SELinux context to current-context evidence, and emulator indicators
to emulator evidence. It does not manufacture system properties, boot state,
root-shell availability, Magisk state, complete process visibility, or global
mount integrity.

The remaining typed values and every probe status are retained in the strict
`org.androidtrustlab.app-probe` report extension. Raw app `error` becomes the
portable report status `command_error`; the adapter extension retains the raw
four-state status. The `app_visible_state` registry dimension activates only
when this validated v2 extension exists. Reports without it return the
canonical `not_collected` sentinel; observer metadata alone never creates app
evidence.

## Android implementation boundary

Probe code lives below
`app/observer/src/main/kotlin/org/androidtrustlab/observer/probe/`:

- closed contract models and invariant validation;
- a dependency-free ATL Canonical JSON v1 encoder;
- public-API and bounded-file platform sources behind test seams;
- field-aware redaction and categorical exception mapping;
- fixed-order orchestration with per-probe exception isolation;
- deterministic artifact and manifest bundle construction.

`MainActivity` remains collection-free in Step 32. Step 33 owns explicit user
consent, progress, preview, and scoped export. No startup collection,
background scheduler, network capability, shell execution, reflection, native
code, package enumeration, root bridge, or dynamic download is permitted.
