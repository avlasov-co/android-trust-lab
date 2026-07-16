# Generate Report

Regenerate checked-in sample reports, dataset-bound diffs, result tables, the
strict dataset manifest, and the broader generated-artifact manifest:

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

See `docs/dataset_manifest_v2.md` for the artifact graph and origin rules.
