# Report Schema v5

Report schema `5.0.0` is the sole current writer contract. Its canonical packaged
resource is `trust_report_v5_0_0.schema.json`. Report versions `1.0.0` through
`4.0.0` remain frozen readable inputs through exact local schemas and the
registered migration chain.

V5 is a major change because SELinux and selected-process evidence is now
structured, source-referenced, and identity-bearing. V4 retained only a mode
summary and substring-derived process booleans, so it could not preserve capture
scope, command outcome, sanitized contexts, or the difference between invisible
and affirmatively absent evidence.

## SELinux evidence

`selinux` records the source observer, policy mode, the observer's current
context, denial-collection status, and explicit limitations. Each evidence item
uses `observed`, `observed_absent`, `inaccessible`, `not_collected`,
`command_error`, or `unsupported` as applicable. Direct observations carry
portable relative evidence references.

Current contexts retain only the Android process domain and sensitivity level,
such as `u:r:shell:s0`. MLS/MCS category sets that can correlate with an Android
app or user assignment are removed. Filesystem-label rows are never interpreted
as the current process context.

Denial collection is a collection fact, not a conclusion about whether denials
occurred. Missing or inaccessible denial evidence cannot establish that no
denial exists.

## Selected-process evidence

`process_state` records capture status, source format, scope, completeness,
limitations, and exactly these canonical names in fixed order:

```text
init, adbd, zygote, zygote64, system_server, magisk, magiskd
```

Only an exact selected name, a sanitized SELinux context when available, and a
capture-level relative path survive normalization. Capture-level references are
used deliberately because standalone reports cannot verify source line numbers.
The process capture also carries that identity-bound source reference, including
when a complete table supports an absence claim. PIDs, UIDs/users, raw rows, and
command arguments are discarded at the parser boundary and never enter the
portable report.

The supported parser accepts conservative toybox/toolbox tables with an
unambiguous trailing `NAME`, `CMD`, or `COMMAND` column, plus explicitly scoped
selected-name lists. Duplicate or ambiguous headers, nonnumeric declared PIDs,
short rows, repeated headers, unsupported headerless tables, and truncated input
are reported rather than guessed.

An exact missing name becomes `observed_absent` only when an observed,
successfully and completely parsed full process table was declared. A selected
filter, partial table, app-sandbox view, inaccessible capture, unsupported
format, command error, or omitted capture yields an unavailable status instead.
This prevents a filtered absence from becoming a claim of nonexistence.

## Compatibility, identity, and diffs

The report chain is:

```text
1.0.0 -> 2.0.0 -> 3.0.0 -> 4.0.0 -> 5.0.0
```

`report-v4-to-v5` is pure and deterministic. It preserves the exact canonical
v4 source in the digest-bound `org.androidtrustlab.migration-v5` extension.
Historical v4 process booleans are not reconstructed because their original
substring matches and source rows were discarded; all v5 selected-process
observations therefore remain `not_collected` after migration. Historical mode
evidence is retained exactly, while unavailable context and denial structure is
marked explicitly. Direct normalization writes v5 from parsed source evidence
without an artificial migration claim.

The structured security model participates in `content_digest`, so changing an
evidence status, sanitized context, scope, completeness, limitation, or selected
observation changes report content identity. Evidence references are retained in
reports but excluded from semantic diff values.

Diff schema `2.2.0` is the current writer. It migrates readable inputs to report
v5 and adds status-aware dimensions for current SELinux context, denial
collection, and selected-process visibility. Consequently, an inaccessible
process view differs from a complete observation of absence without leaking
source references into the changed value.

Typed-adapter warning text and stderr are not copied into portable reports. The
adapter retains fixed parser/status diagnostics and replaces arbitrary source
warnings with bounded withheld markers. Collection-manifest warnings and artifact
details remain part of their exact digest-bound provenance, so the portable v1
profile requires an empty warning list and null artifact details; outcomes use
the structured completion, evidence-status, exit-code, and timeout fields. The
Magisk legacy raw format likewise uses fixed `trustlab:` failure markers so access
denial, unsupported commands, and command errors remain distinct without
publishing device diagnostics.

The structured mount model introduced in report v4 remains unchanged and
identity-bearing. See [Report Schema v4](report_schema_v4.md) for mount parsing,
source selection, and modern Android layout semantics.
