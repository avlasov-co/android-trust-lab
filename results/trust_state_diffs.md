# Trust State Diffs

These diffs are generated from checked-in sample reports with `tools/generate_report.py`. They are useful for validating the analyzer pipeline, not for claiming hardware-backed trust behavior.

## E01 stock AVD ADB observer vs E02 rooted AVD ADB observer

1 dimensions changed, 16 dimensions unchanged.

| Dimension | Severity | Before | After | Interpretation |
|---|---|---|---|---|
| root_presence | medium | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | Root-related evidence changed between reports. This is an observation, not an app verdict or bypass claim. |

## E02 rooted AVD ADB observer vs E02 rooted AVD root observer

1 dimensions changed, 16 dimensions unchanged.

| Dimension | Severity | Before | After | Interpretation |
|---|---|---|---|---|
| observer_privilege | info | `shell` | `root` | Observer privilege changed, so visibility differences may be caused by privilege boundary rather than target mutation. |

## E01 stock AVD vs E03 writable-system AVD

2 dimensions changed, 15 dimensions unchanged.

| Dimension | Severity | Before | After | Interpretation |
|---|---|---|---|---|
| mount_integrity | high | `{"overlay_detected": {"status": "observed_absent", "value": false}, "writable_sensitive_mounts": {"status": "observed_absent", "value": []}}` | `{"overlay_detected": {"status": "observed", "value": true}, "writable_sensitive_mounts": {"status": "observed", "value": ["/system"]}}` | Sensitive mount state changed. Review raw mount evidence before making any platform-integrity conclusion. |
| dynamic_partition_state | low | `{"record_indices": [0, 1, 2, 3, 4, 5], "sources": ["/dev/block/dm-1", "/dev/block/dm-2", "/dev/block/dm-3", "/dev/block/dm-4", "/dev/block/dm-5", "/dev/block/dm-6"], "state": "detected"}` | `{"record_indices": [1, 2, 3, 4, 5], "sources": ["/dev/block/dm-2", "/dev/block/dm-3", "/dev/block/dm-4", "/dev/block/dm-5", "/dev/block/dm-6"], "state": "detected"}` | Dynamic-partition evidence changed. This records layout evidence, not an integrity verdict. |

## E02 rooted ADB observer vs E05 Magisk root collector fixture

3 dimensions changed, 14 dimensions unchanged.

| Dimension | Severity | Before | After | Interpretation |
|---|---|---|---|---|
| selected_process_visibility | medium | `{'name': 'init', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:init:s0'}}, {'name': 'adbd', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:adbd:s0'}}, {'name': 'zygote', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'zygote64', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:zygote:s0'}}, {'name': 'system_server', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:system_server:s0'}}, {'name': 'magisk', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'magiskd', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}` | `{'name': 'init', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:init:s0'}}, {'name': 'adbd', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:adbd:s0'}}, {'name': 'zygote', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'zygote64', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:zygote:s0'}}, {'name': 'system_server', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:system_server:s0'}}, {'name': 'magisk', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'magiskd', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:magisk:s0'}}` | Selected process visibility or sanitized contexts changed. Inconclusive scoped evidence is distinct from observed absence. |
| magisk_presence | medium | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | Magisk-related visibility changed between reports. The project records visibility and does not hide or modify it. |
| observer_privilege | info | `shell` | `root` | Observer privilege changed, so visibility differences may be caused by privilege boundary rather than target mutation. |
