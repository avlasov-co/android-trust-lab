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

The Step 35 typed app/ADB/root bundle intentionally lives at
`tests/fixtures/cross_observer_bundle/`, outside this closed graph. Dataset
source v1 and manifest v2 reserve raw dataset artifacts for text, while the app
source is correctly typed `application/json`. The canonical generator still
validates that separate bundle, its three collection manifests and manual
expectations, and generates its reports, diffs, and result matrix. See
`docs/cross_observer_fixture.md`.
