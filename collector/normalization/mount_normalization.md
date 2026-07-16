# Mount Normalization

Mount normalization preserves source and uncertainty before interpretation.

## Source order

The fixed source preference is `/proc/self/mountinfo`, `/proc/mounts`, then
common `mount` output. Capture-array order does not affect selection. Empty,
inaccessible, failed, malformed, and partial attempts remain recorded even when
a fallback source is selected.

Mountinfo supplies topology: mount/parent IDs, device major/minor, root, mount
point, per-mount options, optional propagation fields, filesystem, source, and
superblock options. Other formats leave unavailable topology fields null.
Escaped whitespace and backslashes are decoded once from the kernel form.

## Independent observations

- access: `read_only`, `writable`, or `unknown`;
- overlay: `detected`, `not_detected`, or `unknown`;
- bind: `detected`, `not_detected`, or `unknown`;
- per-record parse status and one source-line evidence path.

For mountinfo, access comes from per-mount options; superblock options are kept
separately. Overlay does not imply writable. A non-`/` mount root does not prove
a bind mount, so bind is detected only from an explicit bind/rbind option.

## Android layout resolution

Only an exact `/system` record is the explicit system mount. If none exists and
one exact `/` record is present, the layout is system-as-root and the observed
root record remains `/`; no synthetic `/system` record is created. Nested paths
never substitute for a parent. Stacked candidates are ambiguous.

Dynamic dm/mapper sources and their record indices are retained. APEX package
names are normalized into a sorted unique set while every package/version mount
record remains available. Aggregates count access, overlay, and bind states.

Sensitive writable paths and overlays are observations for contextual review,
not a standalone integrity verdict. The report explicitly leaves mount
integrity `not_assessed`.
