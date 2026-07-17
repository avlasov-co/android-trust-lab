# App review and export flow

The Android observer exposes one deliberately narrow foreground flow:

1. read the fixed probe scope and limitations;
2. acknowledge them and explicitly press **Start collection**;
3. review progress across the 12 fixed checks;
4. review outcomes grouped as `observed`, `inaccessible`, `unsupported`, or
   `error`;
5. keep the capability and interpretation limitations visible;
6. review the six redaction transformations and exact redacted artifact;
7. choose a local Storage Access Framework folder for export.

Opening or recreating the activity never starts collection. A process-local
controller retains a running or completed session across configuration changes
without placing artifact bytes in saved instance state. Process death returns
to the scope screen and never recollects automatically. Collection is canceled
between bounded probes if the activity leaves the foreground for a reason other
than configuration change.

The app has no account, package-inventory, network, service, receiver, worker,
alarm, or startup collection capability. It does not persist a folder grant.
Provider URIs, filesystem paths, exception types, and exception messages do not
enter presentation state.

## Review contract

The categorized result view shows a friendly name and one of the four closed
outcomes for every fixed probe. It does not show a score, pass/fail state,
trusted/untrusted label, or physical-device verdict. `inaccessible`,
`unsupported`, and `error` are capability bounds, not evidence of absence.
Emulator indicators remain heuristics. The UI states explicitly that the app
does not certify device security.

The redaction preview is mapped directly from the app-probe v2
`redaction_policy.applied_fields` contract:

- build fingerprint hashed;
- diagnostics categorized;
- file paths replaced by fixed logical identifiers;
- installer package categorized;
- mount fields allowlisted;
- SELinux categories removed.

The exact canonical `app_probe.json` bytes are visible before export. Text is
selectable, controls use at least 48 dp touch height, progress and export status
use polite accessibility live regions, and the layout has no fixed text height
or maximum line count so Android large-text settings can reflow it.

## Export package

The fully staged in-memory ZIP contains only these fixed, flat entries:

| Entry | Purpose |
|---|---|
| `app_probe.json` | exact canonical redacted artifact |
| `manifest.json` | collection manifest bound to the artifact hash |
| `export_metadata.json` | app and schema versions, collection ID, timestamps, completion status, and both hashes |
| `SHA256SUMS.txt` | artifact, manifest, and export-metadata SHA-256 values |

The archive builder verifies both bundle hashes before packaging, rejects an
archive over 4 MiB, fixes entry order and ZIP metadata, and uses no directory
or caller-controlled entry name. Each export request gets an ASCII UTC filename
containing the random collection ID and an additional random suffix; it never
contains the target pseudonym.

The app uses `ACTION_OPEN_DOCUMENT_TREE` with `EXTRA_LOCAL_ONLY` and transient
read/write grants. It does not enumerate the selected directory. Publication
creates a random temporary document, requires provider write/delete/rename
capabilities, writes and syncs the complete staged archive, reopens it to verify
the exact byte count and SHA-256, and performs one provider rename to the final
unique name. It then verifies final metadata and content again. Any failure is
reported categorically and triggers best-effort deletion of the current
temporary or renamed document.

Android defines the DocumentsProvider rename operation but does not promise
filesystem-style atomicity for every third-party provider. The implemented
contract is therefore a verified temporary document followed by a single
rename publication, with providers lacking the necessary capabilities rejected
before publication. It does not claim universal provider-level atomicity.
