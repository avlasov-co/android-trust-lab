# Trust State Diffs

These diffs are generated from checked-in sample reports with `tools/generate_report.py`. They are useful for validating the analyzer pipeline, not for claiming hardware-backed trust behavior.

## E01 stock AVD ADB observer vs E02 rooted AVD ADB observer

1 dimensions changed, 28 dimensions unchanged.

Input schemas: base `6.0.0`, compare `6.0.0`; canonical comparison schema: `6.0.0`; migration mode: `temporary_in_memory`.

| Dimension | Severity | Before | After | Interpretation |
|---|---|---|---|---|
| su_binary_visibility | medium | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |

## E02 rooted AVD ADB observer vs E02 rooted AVD root observer

2 dimensions changed, 27 dimensions unchanged.

Input schemas: base `6.0.0`, compare `6.0.0`; canonical comparison schema: `6.0.0`; migration mode: `temporary_in_memory`.

| Dimension | Severity | Before | After | Interpretation |
|---|---|---|---|---|
| observer_uid_root | medium | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| observer_privilege | info | `shell` | `root` | Observer privilege changed, so visibility differences may be caused by privilege boundary rather than target mutation. |

## E01 stock AVD vs E03 writable-system AVD

2 dimensions changed, 27 dimensions unchanged.

Input schemas: base `6.0.0`, compare `6.0.0`; canonical comparison schema: `6.0.0`; migration mode: `temporary_in_memory`.

| Dimension | Severity | Before | After | Interpretation |
|---|---|---|---|---|
| mount_integrity | high | `{"overlay_detected": {"status": "observed_absent", "value": false}, "writable_sensitive_mounts": {"status": "observed_absent", "value": []}}` | `{"overlay_detected": {"status": "observed", "value": true}, "writable_sensitive_mounts": {"status": "observed", "value": ["/system"]}}` | Sensitive mount state changed. Review raw mount evidence before making any platform-integrity conclusion. |
| dynamic_partition_state | low | `{"record_indices": [0, 1, 2, 3, 4, 5], "sources": ["/dev/block/dm-redacted"], "state": "detected"}` | `{"record_indices": [1, 2, 3, 4, 5], "sources": ["/dev/block/dm-redacted"], "state": "detected"}` | Dynamic-partition evidence changed. This records layout evidence, not an integrity verdict. |

## E02 rooted ADB observer vs E05 Magisk root collector fixture

13 dimensions changed, 16 dimensions unchanged.

Input schemas: base `6.0.0`, compare `6.0.0`; canonical comparison schema: `6.0.0`; migration mode: `temporary_in_memory`.

| Dimension | Severity | Before | After | Interpretation |
|---|---|---|---|---|
| selected_process_visibility | medium | `{'name': 'init', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:init:s0'}}, {'name': 'adbd', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:adbd:s0'}}, {'name': 'zygote', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'zygote64', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:zygote:s0'}}, {'name': 'system_server', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:system_server:s0'}}, {'name': 'magisk', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'magiskd', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}` | `{'name': 'init', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:init:s0'}}, {'name': 'adbd', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:adbd:s0'}}, {'name': 'zygote', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'zygote64', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:zygote:s0'}}, {'name': 'system_server', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:system_server:s0'}}, {'name': 'magisk', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'magiskd', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:magisk:s0'}}` | Selected process visibility or sanitized contexts changed. Inconclusive scoped evidence is distinct from observed absence. |
| observer_uid_root | medium | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| root_shell_availability | medium | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| su_invocation_tested | low | `{"status": "not_collected", "value": null}` | `{"status": "observed_absent", "value": false}` | Trust-state dimension changed between reports. |
| root_management_artifact | medium | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| magisk_binary_visibility | medium | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| magisk_daemon_visibility | medium | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| magisk_process_visibility | medium | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| zygisk_visibility | medium | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| magisk_version_name | info | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": "28.1"}` | Trust-state dimension changed between reports. |
| magisk_version_code | info | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": "28100"}` | Trust-state dimension changed between reports. |
| magisk_module_context | info | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": "androidtrustlab"}` | Trust-state dimension changed between reports. |
| observer_privilege | info | `shell` | `root` | Observer privilege changed, so visibility differences may be caused by privilege boundary rather than target mutation. |
