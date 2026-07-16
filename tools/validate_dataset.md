# Validate Dataset

Verify the complete dataset graph, byte bindings, relationships, and generated
freshness:

```bash
trustlab dataset verify datasets/manifest.json
```

Individual report and diff validation remains available for diagnosis:

```bash
trustlab validate-report datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json
trustlab validate-diff datasets/derived/diffs/stock_adb_vs_rooted_adb.json
```

Bundle verification checks:

- strict source and manifest schemas;
- portable, traversal-free paths and regular non-symlink files;
- byte sizes and SHA-256 digests;
- closed sample, collection, report, and diff relationships;
- exact regeneration of reports and diffs;
- origin, authorization, physical-data disclosure, and redaction semantics.
