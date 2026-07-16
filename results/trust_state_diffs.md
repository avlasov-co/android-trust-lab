# Trust State Diffs

These diffs are generated from checked-in sample reports with `tools/generate_report.py`. They are useful for validating the analyzer pipeline, not for claiming hardware-backed trust behavior.

## Comparison axis: `same_target_state_change`

### E01 stock AVD ADB observer vs E02 rooted AVD ADB observer

1 dimensions changed, 26 dimensions unchanged; 0 signals became available, 0 signals became unavailable.

Comparability: `comparable`. Reasons: target_identity_matches, target_class_matches, state_identity_differs, experiment_differs, protocol_matches, observer_matches, observer_privilege_matches, observer_effective_uid_matches, report_schema_matches, environment_context_matches, measurement_differs.
Input schemas: base `6.0.0`, compare `6.0.0`; canonical comparison schema: `6.0.0`; migration mode: `temporary_in_memory`.

| Dimension | Severity | Transition | Before | After | Interpretation |
|---|---|---|---|---|---|
| su_binary_visibility | medium | state_change (observed_absent → observed) | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |

### E01 stock AVD vs E03 writable-system AVD

2 dimensions changed, 25 dimensions unchanged; 0 signals became available, 0 signals became unavailable.

Comparability: `comparable`. Reasons: target_identity_matches, target_class_matches, state_identity_differs, experiment_differs, protocol_matches, observer_matches, observer_privilege_matches, observer_effective_uid_matches, report_schema_matches, environment_context_matches, measurement_differs.
Input schemas: base `6.0.0`, compare `6.0.0`; canonical comparison schema: `6.0.0`; migration mode: `temporary_in_memory`.

| Dimension | Severity | Transition | Before | After | Interpretation |
|---|---|---|---|---|---|
| mount_integrity | high | state_change (observed_absent → observed) | `{"overlay_detected": {"status": "observed_absent", "value": false}, "writable_sensitive_mounts": {"status": "observed_absent", "value": []}}` | `{"overlay_detected": {"status": "observed", "value": true}, "writable_sensitive_mounts": {"status": "observed", "value": ["/system"]}}` | Sensitive mount state changed. Review raw mount evidence before making any platform-integrity conclusion. |
| dynamic_partition_state | low | state_change (observed → observed) | `{"record_indices": [0, 1, 2, 3, 4, 5], "sources": ["/dev/block/dm-redacted"], "state": "detected"}` | `{"record_indices": [1, 2, 3, 4, 5], "sources": ["/dev/block/dm-redacted"], "state": "detected"}` | Dynamic-partition evidence changed. This records layout evidence, not an integrity verdict. |

## Comparison axis: `same_state_observer_change`

### E02 rooted AVD ADB observer vs E02 rooted AVD root observer

0 dimensions changed, 27 dimensions unchanged; 0 signals became available, 0 signals became unavailable.

Comparability: `comparable`. Reasons: target_identity_matches, target_class_matches, state_identity_matches, experiment_matches, protocol_differs, observer_differs, observer_privilege_differs, observer_effective_uid_differs, report_schema_matches, environment_context_matches, measurement_differs.
Input schemas: base `6.0.0`, compare `6.0.0`; canonical comparison schema: `6.0.0`; migration mode: `temporary_in_memory`.

> **Comparison warning:** `observer_context_changed_visibility_may_differ`

| Dimension | Severity | Transition | Before | After | Interpretation |
|---|---|---|---|---|---|
| none | info | unchanged | `unchanged` | `unchanged` | No measured default dimension changed. |

## Comparison axis: `mixed_change`

### E02 rooted ADB observer vs E05 Magisk root collector fixture

11 dimensions changed, 16 dimensions unchanged; 9 signals became available, 0 signals became unavailable.

Comparability: `limited`. Reasons: target_identity_matches, target_class_matches, state_identity_differs, experiment_differs, protocol_differs, observer_differs, observer_privilege_differs, observer_effective_uid_differs, report_schema_matches, environment_context_matches, measurement_differs.
Input schemas: base `6.0.0`, compare `6.0.0`; canonical comparison schema: `6.0.0`; migration mode: `temporary_in_memory`.

> **Comparison warning:** `mixed_state_and_observer_change_acknowledged`

| Dimension | Severity | Transition | Before | After | Interpretation |
|---|---|---|---|---|---|
| selected_process_visibility | medium | context_change (observed → observed) | `{'name': 'init', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:init:s0'}}, {'name': 'adbd', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:adbd:s0'}}, {'name': 'zygote', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'zygote64', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:zygote:s0'}}, {'name': 'system_server', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:system_server:s0'}}, {'name': 'magisk', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'magiskd', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}` | `{'name': 'init', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:init:s0'}}, {'name': 'adbd', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:adbd:s0'}}, {'name': 'zygote', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'zygote64', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:zygote:s0'}}, {'name': 'system_server', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:system_server:s0'}}, {'name': 'magisk', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'magiskd', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:magisk:s0'}}` | Selected process visibility or sanitized contexts changed. Inconclusive scoped evidence is distinct from observed absence. |
| root_shell_availability | medium | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| su_invocation_tested | low | collection_quality_change (not_collected → observed_absent) | `{"status": "not_collected", "value": null}` | `{"status": "observed_absent", "value": false}` | Trust-state dimension changed between reports. |
| root_management_artifact | medium | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| magisk_binary_visibility | medium | context_change (observed_absent → observed) | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| magisk_daemon_visibility | medium | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| magisk_process_visibility | medium | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| zygisk_visibility | medium | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | Trust-state dimension changed between reports. |
| magisk_version_name | info | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": "28.1"}` | Trust-state dimension changed between reports. |
| magisk_version_code | info | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": "28100"}` | Trust-state dimension changed between reports. |
| magisk_module_context | info | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": "androidtrustlab"}` | Trust-state dimension changed between reports. |

#### Signals became available

| Dimension | Status transition | Classification | Confidence impact | Observed values | Source evidence | Interpretation |
|---|---|---|---|---|---|---|
| root_shell_availability | not_collected → observed | collection_quality_change | increased | `{"after": true, "before": null}` | `{"after": ["legacy-sections/ROOT_PROBE"], "before": []}` | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| su_invocation_tested | not_collected → observed_absent | collection_quality_change | increased | `{"after": false, "before": null}` | `{"after": ["legacy-sections/ROOT_PROBE"], "before": []}` | Collection outcome changed from not_collected to observed_absent; this alone does not establish a target-state change. |
| root_management_artifact | not_collected → observed | collection_quality_change | increased | `{"after": true, "before": null}` | `{"after": ["legacy-sections/ROOT_PROBE"], "before": []}` | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| magisk_daemon_visibility | not_collected → observed | collection_quality_change | increased | `{"after": true, "before": null}` | `{"after": ["legacy-sections/PS"], "before": []}` | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| magisk_process_visibility | not_collected → observed | collection_quality_change | increased | `{"after": true, "before": null}` | `{"after": ["legacy-sections/PS"], "before": []}` | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| zygisk_visibility | not_collected → observed | collection_quality_change | increased | `{"after": true, "before": null}` | `{"after": ["legacy-sections/MAGISK"], "before": []}` | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| magisk_version_name | not_collected → observed | collection_quality_change | increased | `{"after": "28.1", "before": null}` | `{"after": ["legacy-sections/MAGISK"], "before": []}` | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| magisk_version_code | not_collected → observed | collection_quality_change | increased | `{"after": "28100", "before": null}` | `{"after": ["legacy-sections/MAGISK"], "before": []}` | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| magisk_module_context | not_collected → observed | collection_quality_change | increased | `{"after": "androidtrustlab", "before": null}` | `{"after": ["legacy-sections/MAGISK"], "before": []}` | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
