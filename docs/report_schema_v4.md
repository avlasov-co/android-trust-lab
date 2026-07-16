# Report Schema v4

Report schema `4.0.0` is a frozen readable contract. Its canonical packaged
resource is `trust_report_v4_0_0.schema.json`; report `6.0.0` is the sole current
writer. V4 remains the authority for the structured mount model retained by v5.

V4 is a major change because structured mount topology, source attempts, and
layout resolution are required identity-bearing evidence. Keeping these facts in
an extension would not bind them into `content_digest`; changing report v3 in
place would violate its frozen contract.

## Mount source selection

Collectors may provide all three source families. The analyzer evaluates them in
this fixed order, independent of capture-array order:

1. `/proc/self/mountinfo` (`mountinfo`);
2. `/proc/mounts` (`proc_mounts`);
3. common `mount` output (`mounts`).

The first source with at least one usable record is selected. Partial mountinfo
remains preferred when it contains usable records. Empty, inaccessible,
command-error, malformed, and fallback attempts remain in `mounts.observation`;
they are not collapsed into “missing.” Every selected record carries its source
reference and one-based line suffix.

The two `/proc` source names have fixed matching formats. Historical generic
`MOUNT` sections retain their detected format; `mixed` is used only when one such
legacy capture contains more than one accepted line syntax.

Mountinfo records preserve mount ID, parent ID, major/minor device, root, mount
point, per-mount options, optional fields, filesystem type, source, superblock
options, propagation IDs, parse status, raw line, and evidence path. Linux mount
field escapes are decoded once. `/proc/mounts` and common `mount` output leave
their unavailable `root` and topology fields null instead of inventing values.

## Modern Android layouts

`mounts.system_resolution` distinguishes:

- one exact `/system` mount;
- system-as-root, represented by the observed `/` record;
- ambiguous stacked `/system` or `/` records;
- unresolved evidence.

Absence-based conclusions require a complete selected capture. A partial table
can still establish a directly observed `/system` or dynamic-partition record,
but a lone `/` record remains unresolved and a missing dm/mapper record remains
unknown until the capture is complete.

Nested paths such as `/system/bin` never stand in for `/system`. System-as-root
never creates a synthetic `/system` record. Dynamic-partition evidence records
the matching dm/mapper records and exact sources. `apex_set` reports sorted,
unique package names, referenced mount records, and deterministic access,
overlay, and bind aggregates, while retaining every original APEX mount record.

Access, overlay, and bind are orthogonal observations. For mountinfo, effective
read-only/read-write state comes from per-mount options, not superblock options.
Overlay does not imply writable. Bind state is “detected” only when an explicit
bind/rbind option is present; otherwise it stays unknown rather than being
inferred from a non-root mountinfo root.

Writable sensitive paths and overlays remain contextual evidence. V4 explicitly
marks mount integrity as `not_assessed`; it does not declare platform failure
from a writable path without target and observer context.

## Compatibility and identity

The report chain is:

```text
1.0.0 -> 2.0.0 -> 3.0.0 -> 4.0.0 -> 5.0.0 -> 6.0.0
```

`report-v3-to-v4` is pure and deterministic. It preserves the exact canonical v3
source in a digest-bound migration extension and marks unavailable structured
mount records as not parsed; it never reconstructs topology from the older
summary. Direct normalization writes v4 from parsed source evidence without an
artificial migration claim.

The v4 mount model is part of the existing report evidence projection, so any
record, source status, resolution, or APEX-set change changes `content_digest`.
Report v3 identity framing remains unchanged for historical validation.

Diff schemas `2.1.0` through `2.5.0` are frozen and readable. Current diff `2.6.0` migrates
readable report inputs to v5, binds both common v5 identities, and records every
applied report migration. See [Report Schema v5](report_schema_v5.md).
