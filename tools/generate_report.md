# Generate Report

Regenerate checked-in sample reports, diffs, result tables, and the dataset manifest:

```bash
python tools/generate_report.py
```

Verify generated artifacts are up to date without modifying files:

```bash
python tools/generate_report.py --check
```

The generated outputs are derived from checked-in synthetic / AVD-limited raw samples. They validate the pipeline. They do not prove physical-device AVB, TEE, attestation, Widevine, or OEM boot-chain behavior.
