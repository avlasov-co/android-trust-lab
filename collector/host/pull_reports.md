# Pull Reports

Supported paths:

```text
/sdcard/Android/data/dev.androidtrustlab/files/reports/
/data/local/tmp/android-trust-lab/reports/
adb stdout capture
```

## Naming convention

```text
E01_stock_avd__observer-adb__timestamp.json
collector_manifest_timestamp.json
```

## Example

```bash
adb pull /data/local/tmp/android-trust-lab/reports/ ./datasets/samples/magisk_collector/raw/
```
