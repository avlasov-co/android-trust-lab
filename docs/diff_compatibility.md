# Diff Input Compatibility

Trust diff schema `2.7.0` compares only validated report documents. The library and CLI use the same `trustlab.compatibility.prepare_report_for_comparison` path for both inputs. Diffs through `2.6.0` remain readable and frozen.

Before comparison, that path:

1. requires a strict semantic `schema_version` registered as readable;
2. validates the document against that exact versioned report schema;
3. verifies content and report identities for content-addressed report versions;
4. resolves an upgrade-only path through `REPORT_MIGRATION_REGISTRY`;
5. creates a temporary canonical report in memory without modifying either input; and
6. records the input version, migration chain, warning, canonical schema, and canonical report identity in the diff.

Malformed versions, unsupported versions, invalid JSON objects, schema-invalid reports, unregistered migration paths, and tampered identities are errors. They never become low-confidence observations.

The emitted `compatibility` object records the input versions and the exact registered migration steps. `migration_mode` is `temporary_in_memory`; the CLI does not persist migrated inputs. The `provenance` object separately binds each original document digest and the identity of its canonical comparison representation.
