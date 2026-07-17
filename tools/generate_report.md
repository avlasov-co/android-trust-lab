# Generate Report

Regenerate checked-in sample reports, dataset-bound diffs, the linked
cross-observer reports and diffs, result tables, the strict dataset manifest,
and the broader generated-artifact manifest:

```bash
python tools/generate_report.py
```

Verify generated artifacts are up to date without modifying files:

```bash
python tools/generate_report.py --check
```

The generated outputs are derived from checked-in synthetic / AVD-limited raw samples. They validate the pipeline. They do not prove physical-device AVB, TEE, attestation, Widevine, or OEM boot-chain behavior.

Sample and diff definitions live in the validated `datasets/source.json`, not in
Python constants. The generator preserves source evidence, computes every output
before writing, atomically replaces changed generated files, and publishes
`datasets/manifest.json` last. Verify its integrity and freshness with:

```bash
trustlab dataset verify datasets/manifest.json
```

The separate Step 35 source graph is driven by the manually authored
`tests/fixtures/cross_observer_bundle/expectations.json`. The generator validates
all three source hashes and collection manifests, evaluates expectations against
the in-memory reports and pairwise diffs, and only then publishes its generated
files. It remains outside frozen dataset source v1 because its typed app raw
artifact is `application/json`.

See `docs/dataset_manifest_v2.md` for the artifact graph and origin rules.
