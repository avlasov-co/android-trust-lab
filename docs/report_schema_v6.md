# Report Schema v6

Report schema `6.0.0` is the sole writer contract. Versions `1.0.0` through
`5.0.0` remain readable and migrate through explicit, source-bound major steps.
Diff schema `2.6.0` adds structured status transitions to comparison-axis classification introduced by frozen diff `2.5.0`.

## Root evidence

V6 keeps these observations independent:

- whether the observer's effective UID is root;
- whether a root shell was explicitly available;
- whether a `su` binary was observed;
- whether `su` invocation was tested and, if so, its result; and
- whether a root-management artifact was observed.

UID 0 never creates `su` evidence. A missing invocation test remains
`not_collected`; it is not reported as a failed invocation. Every direct fact
binds a semantic capture reference, and the report records when the independent
root probe was not collected.

## Magisk evidence

Binary, daemon, process, and Zygisk visibility are separate fields. Magisk
version name (`magisk -v`) and numeric version code (`magisk -V`) are parsed
independently through a fixed grammar. Module context and command status are
also independent. Process visibility remains observer- and scope-specific, and
a filesystem Zygisk indicator is not described as proof of active runtime
injection.

## Confidence

Verified-boot confidence is a structured assessment containing:

- level;
- source quality;
- command success;
- observer capability;
- corroborating signal count;
- target limitations; and
- evidence references.

No supporting signal produces `unassessed`. Direct, complete property evidence
can produce at most `medium` because current collectors do not verify
hardware-backed attestation. AVD status is a recorded limitation, not a blanket
confidence assignment.

## Portable-output privacy

Normalization applies privacy controls before content identity is calculated:

- reportable properties use an exact allowlist plus field-specific value
  grammars, including numeric Android-release syntax and enumerated filename
  encryption modes;
- serials, transport IDs, network addresses, account-like values, host paths,
  credential syntax, and boot identifiers are withheld or replaced by
  deterministic category labels that do not encode the source value;
- caller-controlled filenames become semantic capture references;
- raw mount rows and option values are withheld, while derived access, bind,
  overlay, allowlisted filesystem, and source-class facts remain; APEX labels
  use deterministic ordinals within the report;
- raw-artifact labels and collection IDs are remapped to portable identifiers;
- report and diff provenance use registered product names, semantic command
  identifiers, and fixed value-free outcome details;
  a final field-aware privacy gate covers reports, diffs, Markdown, migration
  sources, and collection manifests even when schema validation is skipped; and
- historical v5 sources containing recognized sensitive identifiers are
  rejected until separately redacted.

Portable category labels and ordinals are not hashes or keyed projections of
the source. This prevents offline confirmation of guessed low-entropy values
such as usernames while retaining deterministic output structure.

## Migration

The supported chain is:

```text
1.0.0 -> 2.0.0 -> 3.0.0 -> 4.0.0 -> 5.0.0 -> 6.0.0
```

V5-to-v6 migration preserves the exact canonical v5 source in
`org.androidtrustlab.migration-v6`. It carries the exact observed UID fact but
does not reinterpret v5 `su_present`, root-shell, substring-derived Magisk, or
target-based confidence fields. Missing independent evidence becomes
`not_collected` with `historical_structure_unavailable`.
