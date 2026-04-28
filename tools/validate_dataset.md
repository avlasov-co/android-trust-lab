# Validate Dataset

Validate JSON reports and diffs:

```bash
trustlab validate-report datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json
trustlab validate-diff tests/fixtures/sample_diff.json
```

Check:

- manifest paths exist
- reports validate against schema
- diffs validate against schema
- limitations fields are present
- emulator samples do not claim physical-device evidence
