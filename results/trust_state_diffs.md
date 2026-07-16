# Trust State Diffs

These diffs are generated from checked-in sample reports with `tools/generate_report.py`. They are useful for validating the analyzer pipeline, not for claiming hardware-backed trust behavior.

## E01 stock AVD ADB observer vs E02 rooted AVD ADB observer

1 dimensions changed, 10 dimensions unchanged.

| Dimension | Severity | Before | After | Interpretation |
|---|---|---|---|---|
| root_presence | medium | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | Root-related evidence changed between reports. This is an observation, not an app verdict or bypass claim. |

## E02 rooted AVD ADB observer vs E02 rooted AVD root observer

1 dimensions changed, 10 dimensions unchanged.

| Dimension | Severity | Before | After | Interpretation |
|---|---|---|---|---|
| observer_privilege | info | `shell` | `root` | Observer privilege changed, so visibility differences may be caused by privilege boundary rather than target mutation. |

## E01 stock AVD vs E03 writable-system AVD

1 dimensions changed, 10 dimensions unchanged.

| Dimension | Severity | Before | After | Interpretation |
|---|---|---|---|---|
| mount_integrity | high | `{"overlay_detected": {"status": "observed_absent", "value": false}, "writable_sensitive_mounts": {"status": "observed_absent", "value": []}}` | `{"overlay_detected": {"status": "observed", "value": true}, "writable_sensitive_mounts": {"status": "observed", "value": ["/system"]}}` | Sensitive mount state changed. Review raw mount evidence before making any platform-integrity conclusion. |

## E02 rooted ADB observer vs E05 Magisk root collector fixture

2 dimensions changed, 9 dimensions unchanged.

| Dimension | Severity | Before | After | Interpretation |
|---|---|---|---|---|
| magisk_presence | medium | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | Magisk-related visibility changed between reports. The project records visibility and does not hide or modify it. |
| observer_privilege | info | `shell` | `root` | Observer privilege changed, so visibility differences may be caused by privilege boundary rather than target mutation. |
