# Dataset Manifest v2

The race-resistant verifier and repository generator currently require POSIX
directory-descriptor APIs (`dir_fd`, `O_NOFOLLOW`, and `O_DIRECTORY`). They fail
closed on platforms that cannot provide those primitives; Windows is not a
supported platform for these two operations in this release.

Dataset manifest `2.0.0` is the integrity and provenance contract for a portable
Android Trust Lab dataset bundle. It replaces the historical loose v1 index.
The frozen v1 schema remains readable for compatibility, but writers and
`trustlab dataset verify` use v2 only.

## Authoritative inputs and generated outputs

`datasets/source.json` is the validated, author-maintained declarative source.
It contains dataset metadata, the closed artifact registry, sample definitions,
and diff derivations. Raw text and collection manifests are source evidence.
Normalized reports, derived diffs, and `datasets/manifest.json` are generated.
The generator never rewrites source evidence.

Within this v2 dataset profile, an observed collection manifest must retain
exactly one observed `raw_report`, and that file must be the sample's bound raw
artifact. Other probe entries must honestly remain non-observed. A collection
that retains multiple observed files requires a future dataset contract that
can bind every one of them; this verifier rejects such a bundle instead of
silently ignoring supporting evidence.

All artifact paths are relative to the directory containing the dataset
manifest. The checked-in layout is:

```text
datasets/
├── source.json                   author-maintained dataset source
├── manifest.json                 generated strict v2 manifest
├── samples/                      raw evidence, collection manifests, reports
└── derived/diffs/                generated machine-readable diffs
```

The dataset source schema is `dataset_source_v1_0_0.schema.json`. The generated
manifest schema is `dataset_manifest_v2_0_0.schema.json`. Canonical packaged
copies live under `analyzer/trustlab/schemas/`; byte-identical collector
compatibility copies live under `collector/schema/`.

The checked-in v2 profile binds report schema `3.0.0` and diff schema `2.0.0`.
Freshness regeneration carries each source artifact's structured provenance into
the report and verifies its declared byte size and SHA-256 before parsing.
The v2 manifest reader also accepts internally consistent historical role
profiles whose report, diff, and collection-manifest versions remain in the
compatibility registry. The declarative source and generator must use the
current role profile; historical v2 manifests are validate-only compatibility
fixtures rather than inputs to current freshness regeneration.

## Contract

The root records:

- dataset ID and independent dataset version;
- SPDX license declaration and scope;
- the exact set of sample origin classifications;
- authorization or consent classification and statement;
- physical-data disclosure state;
- redaction status, policy, and statement;
- creation tool name, version, and command;
- the supported schema profile for each artifact role;
- aggregate limitations;
- samples and diff derivations.

Every source definition and v2 binding has a globally unique artifact ID and
portable relative path, plus its role, media type, schema family and version,
producer kind/name/version, and redaction state. V2 additionally binds the exact
bytes with lowercase SHA-256 and byte size. The registry covers the declarative
source, every raw artifact, every collection manifest, every normalized report,
and every derived diff. Unreferenced registry entries and unbound recognized
evidence files fail validation.

Sample origins use exactly these values:

| Origin | Meaning | Required relationship |
|---|---|---|
| `synthetic` | Project-authored fixture evidence; no collection event is claimed | Must not claim a physical target or use a captured collection method |
| `avd_captured` | Evidence acquired from an authorized Android Virtual Device | A matching observed collection manifest is required |
| `physical_captured` | Evidence acquired from an owned, consented, or explicitly authorized physical device | A matching collection manifest, physical-data disclosure, physical authorization/consent, and applied or verified redaction are required |

The current checked-in dataset contains only `synthetic` samples. A fixture that
models AVD output is not described as captured evidence.
For a synthetic sample, collection relationship `observed` means that a
manually authored collection-manifest fixture is present and bound; it does not
claim that the modeled collector ran or that a collection event occurred.

## Verification

Run verification from any current directory:

```bash
trustlab dataset verify /path/to/datasets/manifest.json
```

Success prints exactly `dataset verified`. Verification performs these checks
without writing to the bundle:

1. Read strict UTF-8 JSON, rejecting duplicate keys and non-finite values.
2. Validate the exact manifest and source schema versions and semantic graph.
3. Reject absolute, non-normalized, URI-like, backslash, control-character, and
   traversal paths.
4. Reject symlinks, non-regular artifacts, symlinked intermediate directories,
   oversized files, missing files, size mismatches, and digest mismatches.
5. Validate every collection manifest, report, and diff against its intrinsic
   schema.
6. Require the generated v2 metadata and artifact definitions to match the
   exact bound `source.json` declaration.
7. Cross-check collection metadata and its raw-artifact binding against the
   referenced sample.
8. Regenerate each report from the exact verified raw byte snapshot and each
   diff from the in-memory regenerated reports, then compare the deterministic
   pretty-JSON bytes exactly.
9. Reject recognized raw, manifest, report, or diff files that are absent from
   the closed graph.

Rechecking derivations is essential: an attacker or accidental edit can update
a generated file and its manifest digest together. Hash comparison alone would
accept that internally consistent but stale pair; deterministic regeneration
does not.

Expected failures use the normal CLI contract: missing artifacts return 3,
invalid JSON 4, unsupported schema versions 5, contract failures 6, and
integrity or freshness failures 7. Error messages do not expose host paths.

## Generation

Regenerate after intentionally editing `source.json` or source evidence:

```bash
python tools/generate_report.py
trustlab dataset verify datasets/manifest.json
```

Use `python tools/generate_report.py --check` in review and CI. The generator
validates all declarative inputs and computes every output before it writes. It
uses atomic replacement, emits reports and diffs from in-memory values, and
publishes the dataset manifest last. Check mode is non-mutating.

SHA-256 bindings prove internal consistency of this bundle. They are not a
signature, external timestamp, device attestation, or proof that a collection
claim is authentic. External authenticity requires a separately trusted
publication or signing mechanism.
