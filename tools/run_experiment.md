# Run Experiment

1. Choose experiment id.
2. Collect host snapshot.
3. Collect adb snapshot.
4. Optionally collect root snapshot.
5. Normalize report.
6. Validate report.
7. Generate diff.
8. Store artifacts.

```bash
trustlab normalize --input raw.txt --output report.json --experiment-id E01_stock_avd --target-type avd --observer adb_shell
trustlab validate-report report.json
trustlab diff --base baseline.json --compare report.json --output diff.json
```
