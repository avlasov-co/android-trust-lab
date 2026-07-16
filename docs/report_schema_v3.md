# Report Schema v3

Report schema `3.0.0` is the sole current writer contract. Its canonical packaged
resource is `trust_report_v3_0_0.schema.json`. Frozen report versions `1.0.0` and
`2.0.0` remain readable through exact local schema resources and explicit
migrations.

V3 is a major change because it replaces string raw-artifact paths, changes
report identity inputs, and adds required content/event identities. It retains
the strict evidence envelopes introduced by v2.

## Required identity and provenance

Every report contains:

- a full deterministic `content_digest`;
- a separate `collection_event_id`;
- a `report_id` binding the event and content identities;
- structured `raw_artifacts` with exact source byte bindings;
- normalizer and generator name/version;
- source schema version and complete migration history;
- command-result provenance.

The schema is closed. All nested report objects are closed except the bounded,
reverse-DNS `extensions` map. Semantic validation additionally rejects duplicate
raw IDs or paths, nonportable paths, mixed collection IDs, invalid migration
chains, preserved-source mismatches, content-digest mismatches, and report-ID
mismatches.

The exact content projection, volatile exclusions, canonical framing, and
event/report distinction are specified in
[Content provenance and identity](content_identity.md).

## Structured source references

Each raw reference records `logical_id`, `relative_path`, `sha256`, `byte_size`,
`media_type`, `collector_name`, `collector_version`, `collection_id`, `status`,
and `redaction_state`. The reference always describes observed source bytes;
unavailable probe outcomes remain in command results and limitations. Manifest
normalization verifies SHA-256 and size before
parsing and copies the manifest's collector, collection, status, media, and
redaction metadata into the reference.

Direct raw-file normalization defaults to the portable basename, hashes the
exact bytes, and derives deterministic fallback IDs without absolute host paths.
Callers and reproducible fixtures may supply stable logical, collection, and
collector metadata explicitly.

## Compatibility and migration

The supported report chain is:

```text
1.0.0 --report-v1-to-v2--> 2.0.0 --report-v2-to-v3--> 3.0.0
```

`migrate_report_v1_to_v2` remains available as the pinned historical library
step. `migrate_report_v2_to_v3` binds the exact canonical v2 document and emits a
v3 report. `migrate_report_to_current` and `trustlab migrate-report` execute the
complete registered chain and return a validated v3 document; a v3 input is
validated and copied without inventing a migration.

Because v3 embeds the canonical legacy source for auditability, migration to v3
fails closed if v2—or a preserved v1 source inside it—contains an absolute,
platform-specific, traversing, empty, or overlong raw-artifact reference. Redact
or rewrite a separate copy under an explicit evidence-handling workflow; never
overwrite the historical source merely to make it portable.

Migration also refuses recognizable unredacted host absolute paths in carried
free text and legacy strings outside ATL Canonical JSON v1, including isolated
UTF-16 surrogates. Such inputs remain readable under their historical schemas;
readability does not promise that every loose legacy value is safe to publish in
the stricter current format.

Manually retained fixtures cover all readable versions:

- `tests/fixtures/report_v1_historical.json`;
- `tests/fixtures/report_v2_historical.json`;
- current generated `tests/fixtures/sample_normalized_report.json`.

Generated repository reports are regenerated directly from integrity-bound raw
inputs rather than hand-migrated. Historical fixtures are never overwritten.

## Diff contract

Diff schema `2.0.0` is the current writer. It accepts validated report v1, v2,
and v3 inputs only through registered migrations to report v3. Its base and
compare identities contain the exact current `report_id`, `content_digest`, and
schema version; provenance retains original-document identities and migration
chains. Frozen diff v1 remains readable only.
