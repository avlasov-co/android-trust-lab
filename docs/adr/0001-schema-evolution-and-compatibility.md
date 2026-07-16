# ADR 0001: Schema evolution and compatibility

- Status: Accepted
- Date: 2026-07-16
- Owners: analyzer and evidence-contract maintainers

## Context

Android Trust Lab has independently produced report, diff, dataset-manifest,
collection-manifest, and experiment records. The original report and diff
contracts are versioned `1.0.0`; the historical dataset manifest also declared
`1.0.0` without integrity bindings. The former collection-manifest sample used the
pre-policy label `collection-manifest-0.1`, and experiments are unversioned
Markdown. Treating package releases, collector releases, or these data contracts
as one version would make compatibility and provenance ambiguous.

## Decision

### Independent version domains

Each domain advances independently. A release may change none, one, or several
of them, and matching numeric values do not imply compatibility.

| Domain | Meaning | Current state |
|---|---|---|
| Analyzer package version | Python distribution and CLI implementation release | PEP 440 `0.3.0.dev0` |
| Collector version | Magisk collector implementation release plus monotonic Android `versionCode` | `0.3.0-dev0`, code `300` |
| Report-schema version | Normalized trust-report contract | `3.0.0` writable; `1.0.0`, `2.0.0`, and `3.0.0` readable |
| Diff-schema version | Trust-diff output contract | `2.0.0` writable; `1.0.0` and `2.0.0` readable |
| Dataset-manifest version | Dataset index and integrity contract | `2.0.0` writable; frozen `1.0.0` and strict `2.0.0` readable |
| Collection-manifest version | Portable collection/provenance contract | `1.0.0` readable and writable |
| Experiment-spec version | Machine-readable experiment contract | no supported version; `1.0.0` planned |

The machine-readable authority for schema support is
`trustlab.compatibility.SCHEMA_SUPPORT`. The retired
`collection-manifest-0.1` label is not a registered schema version; unversioned
Markdown experiments remain design inputs.

### Identifiers and semantic versions

New JSON Schemas use Draft 2020-12 and a logical, versioned `$id`:

```text
https://github.com/avlasov-co/android-trust-lab/schema/{family}/{major.minor.patch}
```

`family` is one of `report`, `diff`, `dataset-manifest`, `dataset-source`,
`collection-manifest`, or `experiment-spec`. Identifiers name contracts; the
validator must not fetch them over the network. Existing v1 report and diff
`$id` values are frozen legacy aliases and must never be repurposed for another
contract.

Schema versions are strict SemVer `MAJOR.MINOR.PATCH` without prefixes or
prerelease/build suffixes:

- MAJOR changes when a valid older document may become invalid, meaning changes,
  or a reader cannot preserve the old meaning.
- MINOR adds optional fields or enum members under a contract that explicitly
  permits them. Readers for that major must ignore only additions the schema and
  ADR declare ignorable.
- PATCH clarifies documentation or tightens an implementation bug without
  changing the accepted document set or meaning.

Changing a required field, type, default meaning, canonicalization, identity
input, or evidence status is a major change. Package and collector versions do
not select a schema implicitly; every artifact declares its schema version.

### Supported versions and validation registry

The analyzer keeps two immutable, fail-closed tables:

- `SCHEMA_SUPPORT` declares exact readable versions, the sole current write
  version, and any planned version for each family.
- `SCHEMA_RESOURCE_REGISTRY` maps an exact `(family, version)` pair to a packaged
  local JSON Schema resource.

There is no `latest` alias, major-only fallback, filename guessing, or network
resolution. An unknown string version is unsupported. A missing or non-string
version is validated against the current schema only to return complete
diagnostics; it never becomes an accepted current-version document. A supported
version without a registered validator fails as a configuration error. Writers
emit only `current_write_version`; readers may accept every declared readable
version and migrate it explicitly.

Dataset manifest v1 is a frozen read-only compatibility contract. V2 is the sole
writable contract and adds complete artifact bindings, provenance metadata, and
a closed reference graph. The separate dataset-source v1 schema governs
author-maintained generator input and is not a `SchemaFamily` writer output.
Collection manifest `1.0.0` is strict and registered. Experiment specs remain
unsupported until their strict schema and validator are registered.

### Canonical evidence states

Every v2 evidence-bearing field uses an explicit status, not a magic string or a
nullable value whose meaning must be guessed:

| Status | Meaning |
|---|---|
| `observed` | Collection completed and produced a usable positive/value observation. |
| `observed_absent` | Collection completed successfully and affirmatively found no matching value or object. |
| `inaccessible` | The signal is meaningful for the target, but the observer was denied access. |
| `not_collected` | No usable attempt is recorded, including a deliberate omission or an ambiguous legacy omission; a reason must explain which. |
| `command_error` | Collection was attempted but the command, parser, timeout, or transport failed. |
| `unsupported` | The signal or collection capability does not apply to this target or collector version. |

The canonical spellings are defined by `trustlab.compatibility.EvidenceStatus`.
`unknown`, an empty string, `null`, and a missing property cannot stand in for
these states. A value is present only where its status permits it. Migrations from
ambiguous v1 `unknown` values must retain the original value and a migration
reason; they must not claim observed absence, inaccessibility, or command failure
without supporting v1 evidence.

### Compatibility and migration

The analyzer owns migrations. Collectors are deliberately simple and emit only
the current write version. A migration is a pure, deterministic function of the
source document and declared source version: it performs no collection, network
access, clock reads, or filesystem-dependent identity work; it does not modify
the source; and it records source version and migration implementation.

Within a major version, a reader accepts only explicitly listed versions. Across
major versions, a reader first validates the source, applies a registered
migration, and validates the result against the exact registered target schema
after every migration step. Only a target-valid result may be published,
analyzed, or used as the input to another migration. There is no implicit
cross-major coercion. Missing migration paths, target-validation failures, and
unsupported versions fail before analysis.

Diffing follows the same rule:

1. Validate both source reports against their exact registered schemas.
2. If their versions differ, migrate each through registered deterministic paths
   to one common representation, validating every intermediate and final target.
3. Diff only that common representation and record both original versions and
   applied migrations in provenance.
4. Refuse the diff if either version or path is unsupported.

Consequently, v1-to-v2 diffing is allowed only after the v1-to-v2 migration is
registered and tested. Comparing raw fields from different majors is forbidden.
Diff-schema versions remain independent of both input report-schema versions.

### Canonical JSON and content identity

`ATL Canonical JSON v1` is the implemented identity representation for current
report, diff, and collection-event identities. Canonicalization first parses
JSON while rejecting duplicate object member names, then serializes the
resulting data model as follows:

- UTF-8 without BOM and without Unicode normalization;
- object keys sorted lexicographically by Unicode scalar-value sequence;
- array order preserved;
- compact `,` and `:` separators with no insignificant whitespace;
- strings enclosed by U+0022 quotation marks; U+0022 and U+005C escaped as
  `\"` and `\\`; U+0008, U+0009, U+000A, U+000C, and U+000D escaped as
  `\b`, `\t`, `\n`, `\f`, and `\r`; every other U+0000 through U+001F
  escaped as `\u00xx` with lowercase hexadecimal; solidus never escaped;
- all other Unicode scalar values encoded directly as UTF-8; isolated UTF-16
  surrogates rejected;
- integers rendered in minimal base-10 form with ASCII `-` only for negatives,
  no leading zeroes, and restricted to the interoperable range
  `-(2^53)+1` through `(2^53)-1`;
- values limited to objects, arrays, strings, integers, booleans, and `null`;
- floats, `NaN`, and infinities rejected.

The analyzer's bounded ATL-v1 profile additionally limits canonical input/output
to 64 MiB, nesting to 64 non-empty container levels with root at depth zero, and
the iterative walk to 100,000 visited values including root and empty
containers. Values outside this resource profile are rejected before recursive
schema evaluation; they do not acquire a project content identity.

Human-readable files may use deterministic pretty printing. Content IDs hash
this unambiguous byte frame, where `len` is the ASCII decimal byte length of
`canonical-json` without leading zeroes, `schema-version` is its strict SemVer
ASCII spelling, and `family` is one of the registered identity domains
`report`, `diff`, or `collection_event`:

```text
ATL-CONTENT-ID\0v1\0{family}\0{schema-version}\0{len}:{canonical-json}
```

The displayed `\0` is one zero byte, and all other framing characters are the
shown ASCII bytes. The digest is lowercase hexadecimal SHA-256 of the complete
frame. Repository path, absolute path, filename, modification time, current
time, and host environment are excluded. Moving identical content must preserve
identity; changing canonical content must change it. Frozen canonical vectors
and cross-order, path, byte, and timestamp tests verify the implementation.

Historical v1/v2 `report_id` and v1 `diff_id` values are legacy event/derived
identifiers, not canonical content identities: report IDs can include
filename-derived input, and diff IDs hash an unframed subset. They remain
supported for read compatibility but are not represented as path-independent
content digests. Report v3 adds a separate event identity and content digest;
diff v2 binds the exact original and canonical report identities. The complete
projection and exclusions are defined in
[Content provenance and identity](../content_identity.md).

### Deprecation and removal

Read support begins deprecation only in a stable release that emits a documented
warning and ships a migration. It remains available for at least two subsequent
public package minor releases and 180 days, whichever is longer. Prereleases do
not start the time period. Removal requires a new schema major, an ADR or explicit
compatibility decision, migration fixtures, and release notes. Write support may
move earlier because writers emit only the current version, but old read support
continues through the full window.

### Samples and captured evidence

- Generator-owned synthetic samples are regenerated from their checked-in raw
  inputs when the current writer changes. They are not hand-migrated in place.
- Manually authored old-version fixtures remain immutable historical inputs;
  migrated expectations are separate generated or manually reviewed fixtures.
- Captured device evidence is never overwritten. Migration creates a derived
  artifact linked to the source digest, schema version, and migration record.
- Generated outputs are updated only through the canonical generator, with
  freshness and deterministic-output tests.
- Dataset v2 verification regenerates reports from exact bound raw bytes and
  diffs from those in-memory reports. Updating a generated artifact and its
  digest together therefore cannot conceal staleness. SHA-256 proves internal
  bundle consistency, not external authenticity or device attestation.

## Consequences

The support boundary is reviewable in code, evidence failures retain their real
semantics, and later schema work has explicit compatibility rules. The cost is
maintaining validators, migration fixtures, and deprecation notes for every
readable major. The implemented report v3, diff v2, and manifest contracts apply
these rules while keeping their version domains independent.
