# Content provenance and identity

Android Trust Lab separates source-byte integrity, collection events, normalized
evidence content, and complete report documents. These are related but not
interchangeable identities.

## Identity layers

| Value | Meaning | Construction |
|---|---|---|
| Raw artifact `sha256` | One exact source byte sequence | SHA-256 over the bytes before UTF-8 decoding or parsing |
| `collection_id` | Collector-assigned collection key | Manifest value, or a deterministic 128-bit fallback derived from event metadata and the raw digest |
| `collection_event_id` | One collection occurrence | `atlevent-` plus 128 bits of a framed canonical digest over collection ID, timestamp, experiment, target class, observer, method, and—when present—the exact canonical collection-manifest digest |
| `content_digest` | Path-independent normalized evidence identity | Full SHA-256 of the report v5 evidence projection using ATL Canonical JSON v1 |
| `report_id` | One event's report for exact evidence | `atlrep-` plus 128 bits of a framed canonical digest over `collection_event_id` and `content_digest` |
| Diff `content_digest` | Exact canonical diff payload identity | Full SHA-256 over the diff v2.2 payload, including both report and content identities |
| `diff_id` | Compact diff identifier | `atldiff-` plus the first 128 bits of the diff content digest |

The 128-bit displayed event, report, and diff identifiers are
collision-resistant identifiers, not substitutes for the full 256-bit digests.
Real collectors must issue non-reused collection IDs; fallback IDs include the
raw digest and event metadata and never include a filesystem path.

## Structured raw references

Report v3 introduced closed `raw_artifacts` objects, retained by reports v4/v5. Each
entry records:

- logical ID;
- normalized relative path;
- exact SHA-256 and byte size;
- media type;
- collector name and version;
- collection ID;
- observed-source status;
- redaction state.

Absolute paths, drive-qualified paths, backslashes, traversal, control
characters, duplicate logical IDs, duplicate paths, non-observed source
references, mixed collectors, and noncanonical logical-ID/path ordering are
rejected. All raw references in one report must belong to one collection.

For manifest-backed normalization, the analyzer reads a bounded immutable byte
snapshot, checks its size and digest against the collection manifest, and only
then decodes or parses it. A mismatch therefore cannot be normalized into a
plausible report. Direct legacy normalization follows the same hash-before-parse
order but has no external expected digest unless the caller supplies one.

## Report content projection

The report v5 `content_digest` includes these normalized evidence fields in
their entirety:

- `target`;
- `observer`;
- `boot_state`;
- `verified_boot`;
- `selinux`;
- `mounts`;
- `properties`;
- `root_state`;
- `magisk_state`;
- `process_state`;
- `emulator_state`;
- `limitations`.

For a directly normalized raw artifact, it additionally includes `sha256`,
`byte_size`, `media_type`, `status`, and `redaction_state`. Changed collection
bytes therefore change evidence identity even when their normalized
interpretation happens to be the same.

A migrated v2 report has no trustworthy raw-byte digest—only legacy path
strings. Its exact canonical v2 wrapper remains bound in migration provenance,
but that wrapper reference is excluded from evidence content identity. The
copied normalized evidence fields still determine `content_digest`; changing
only the v2 timestamp or raw path cannot manufacture an evidence change.

The following volatile, routing, and document-management fields are deliberately
excluded from evidence content identity:

- `report_id`, `collection_event_id`, and `content_digest`;
- `collection_timestamp` and `experiment_id`;
- `provenance`, including normalizer/generator versions, migration records, and
  command-result bookkeeping;
- `extensions`;
- raw-artifact logical ID, relative path, collector name/version, and collection
  ID.

The schema version remains domain-separated in the digest frame even though it
is not duplicated in the projection. Exclusion does not mean a field is
unvalidated: the strict schema and semantic validator still validate every
field. It means that renaming or moving an artifact, regenerating with the same
evidence, or changing only the collection timestamp does not claim that the
observed evidence changed.

A timestamp-only change preserves `content_digest` but changes
`collection_event_id` and therefore `report_id`. Moving a direct, unmanifested
raw reference preserves all three identities. Editing a relative path inside a
bound collection manifest preserves `content_digest` but changes the manifest
digest, `collection_event_id`, and `report_id`. A provenance-only document
change can preserve `report_id`; where exact whole-document distinction is
needed, diff v2.2 also records a deterministic `original_document_digest`.

## ATL Canonical JSON v1

Identity-bearing values use the data model and serialization defined in
[ADR 0001](adr/0001-schema-evolution-and-compatibility.md): strict UTF-8, sorted
object keys, preserved array order, compact separators, scalar Unicode without
normalization, interoperable integers, and no floats, non-finite values,
duplicate members, BOM, or isolated surrogates.

The unambiguous frame is:

```text
ATL-CONTENT-ID\0v1\0{family}\0{schema-version}\0{len}:{canonical-json}
```

`len` is the ASCII byte length of the canonical JSON. Current family tokens are
`report`, `diff`, and `collection_event`. Tests freeze both canonical bytes and
the full digest, verify dictionary-order independence, and reject ambiguous JSON.

The analyzer's bounded ATL-v1 profile accepts at most 64 MiB of canonical bytes,
64 non-empty container levels (root depth zero), and 100,000 visited values
including the root and empty containers. These are normative resource limits for
this implementation profile, not alternate encodings. Boundary and over-limit
vectors are tested before recursive JSON Schema evaluation.

## Migrations and diffs

Report v1 through v4 remain readable. Migration is explicit and validated at
every step: `1.0.0` → `2.0.0` → `3.0.0` → `4.0.0` → `5.0.0`.
V2-to-v3 migration preserves the complete
ATL-canonical v2 source and digest in
`org.androidtrustlab.migration-v3`, creates a structured source reference, and
records the migration implementation. It never overwrites the historical input.
Migration refuses to embed nonportable legacy raw-artifact paths; a sensitive
historical source requires a separate, explicit redaction workflow before v3
publication. It also fails closed for recognizable unredacted host absolute
paths in carried free text and for legacy strings (such as isolated UTF-16
surrogates) outside the bounded canonical v3 model. The historical report
remains readable under its original schema even when publication as v3 is
refused. V3-to-v4 preserves the exact canonical v3 source and represents the
new structured mount model as unavailable instead of reconstructing evidence.
V4-to-v5 preserves the exact canonical v4 source and does not reconstruct
discarded process rows or contexts from historical summary booleans.

Diff v2.2 validates each input first, migrates readable historical reports in
memory to report v5, and records, for each side:

- original report ID and schema version;
- deterministic original-document digest;
- original content digest when the input is v3, v4, or v5;
- exact common report ID, content digest, and schema version;
- applied migration chain and implementation versions.

The complete structure is covered by the diff content digest. Rehashing a
forged provenance object cannot bypass the semantic check that its common-report
identity exactly matches the compared report.

## Security and scope

These digests provide deterministic integrity and internal binding. They do not
authenticate a collector, prove device attestation, establish trusted time, or
make synthetic evidence physical evidence. Authenticity requires a separate
signed provenance or attestation design.
