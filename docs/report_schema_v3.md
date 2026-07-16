# Report Schema v3

Report schema `3.0.0` is a frozen readable compatibility contract. Its canonical
resource is `trust_report_v3_0_0.schema.json`; report `6.0.0` is the sole current
writer.

V3 introduced structured raw-artifact references, `content_digest`,
`collection_event_id`, and a `report_id` that binds the event and evidence
identities. It retained report v2’s closed evidence envelopes. Historical v3
identity framing and semantic validation remain unchanged.

Every v3 report contains deterministic content and event identities, structured
source byte bindings, normalizer and generator identities, migration history,
and command-result provenance. The schema is closed except for the bounded
reverse-DNS `extensions` map. Semantic validation rejects nonportable or
duplicate source paths, mixed collection IDs, invalid migration chains,
preserved-source mismatches, and identity mismatches.

The historical chain to v3 is:

```text
1.0.0 --report-v1-to-v2--> 2.0.0 --report-v2-to-v3--> 3.0.0
```

`report-v2-to-v3` preserves the exact canonical v2 document and refuses unsafe
host-specific paths or noncanonical strings. `report-v3-to-v4` then preserves
the exact canonical v3 source and marks the richer v4 mount fields unavailable;
it does not infer topology from v3 summaries.

See [Report Schema v4](report_schema_v4.md) for the mount model,
[Report Schema v5](report_schema_v5.md) for the current contract, and
[Content provenance and identity](content_identity.md) for canonical framing.
