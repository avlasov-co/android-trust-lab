# Datasets

`source.json` is the validated declarative definition. `manifest.json`, sample
reports, and `derived/diffs/` are generated from it and the separately preserved
raw evidence. Verify the complete bundle with:

```bash
trustlab dataset verify datasets/manifest.json
```

Every current sample is explicitly `synthetic`. A fixture that models an AVD is
not captured evidence. Physical-device claims require authorized physical source
artifacts, disclosure, redaction, and matching collection manifests.

Raw artifacts should be preserved where safe. Do not commit private identifiers.
See `docs/dataset_manifest_v2.md` for the contract, generator, and threat model.
