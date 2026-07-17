# Trust State Diffs

These diffs are generated from checked-in sample reports with `tools/generate_report.py`. They are useful for validating the analyzer pipeline, not for claiming hardware-backed trust behavior.

## Comparison axis: `same_target_state_change`

### E01 stock AVD ADB observer vs E02 rooted AVD ADB observer

1 dimensions changed, 27 dimensions unchanged; 0 signals became available, 0 signals became unavailable.

Comparability: `comparable`. Reasons: target_identity_matches, target_class_matches, state_identity_differs, experiment_differs, protocol_matches, observer_matches, observer_privilege_matches, observer_effective_uid_matches, report_schema_matches, environment_context_matches, measurement_differs.
Input schemas: base `6.0.0`, compare `6.0.0`; canonical comparison schema: `6.0.0`; migration mode: `temporary_in_memory`.

| Dimension | Materiality | Direction | Confidence | Transition | Before | After | Rationale | Interpretation |
|---|---|---|---|---|---|---|---|---|
| su binary visibility (`su_binary_visibility`) | moderate | indeterminate | moderate | state_change (observed_absent → observed) | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | materiality_from_dimension_policy, no_justified_direction_rule, confidence_from_explicit_factors | Trust-state dimension changed between reports. |

### E01 stock AVD vs E03 writable-system AVD

2 dimensions changed, 26 dimensions unchanged; 0 signals became available, 0 signals became unavailable.

Comparability: `comparable`. Reasons: target_identity_matches, target_class_matches, state_identity_differs, experiment_differs, protocol_matches, observer_matches, observer_privilege_matches, observer_effective_uid_matches, report_schema_matches, environment_context_matches, measurement_differs.
Input schemas: base `6.0.0`, compare `6.0.0`; canonical comparison schema: `6.0.0`; migration mode: `temporary_in_memory`.

| Dimension | Materiality | Direction | Confidence | Transition | Before | After | Rationale | Interpretation |
|---|---|---|---|---|---|---|---|---|
| Sensitive mount integrity (`mount_integrity`) | high | regression | moderate | state_change (observed_absent → observed) | `{"overlay_detected": {"status": "observed_absent", "value": false}, "writable_sensitive_mounts": {"status": "observed_absent", "value": []}}` | `{"overlay_detected": {"status": "observed", "value": true}, "writable_sensitive_mounts": {"status": "observed", "value": ["/system"]}}` | materiality_from_dimension_policy, ordered_dimension_rule_applied, confidence_from_explicit_factors | Sensitive mount state changed. Review raw mount evidence before making any platform-integrity conclusion. |
| Dynamic partition state (`dynamic_partition_state`) | low | indeterminate | moderate | state_change (observed → observed) | `{"record_indices": [0, 1, 2, 3, 4, 5], "sources": ["/dev/block/dm-redacted"], "state": "detected"}` | `{"record_indices": [1, 2, 3, 4, 5], "sources": ["/dev/block/dm-redacted"], "state": "detected"}` | materiality_from_dimension_policy, no_justified_direction_rule, confidence_from_explicit_factors | Dynamic-partition evidence changed. This records layout evidence, not an integrity verdict. |

## Comparison axis: `same_state_observer_change`

### E02 rooted AVD ADB observer vs E02 rooted AVD root observer

0 dimensions changed, 28 dimensions unchanged; 0 signals became available, 0 signals became unavailable.

Comparability: `comparable`. Reasons: target_identity_matches, target_class_matches, state_identity_matches, experiment_matches, protocol_differs, observer_differs, observer_privilege_differs, observer_effective_uid_differs, report_schema_matches, environment_context_matches, measurement_differs.
Input schemas: base `6.0.0`, compare `6.0.0`; canonical comparison schema: `6.0.0`; migration mode: `temporary_in_memory`.

> **Comparison warning:** `observer_context_changed_visibility_may_differ`

| Dimension | Materiality | Direction | Confidence | Transition | Before | After | Rationale | Interpretation |
|---|---|---|---|---|---|---|---|---|
| none | informational | indeterminate | low | unchanged | `unchanged` | `unchanged` | none | No measured default dimension changed. |

## Comparison axis: `mixed_change`

### E02 rooted ADB observer vs E05 Magisk root collector fixture

11 dimensions changed, 17 dimensions unchanged; 9 signals became available, 0 signals became unavailable.

Comparability: `limited`. Reasons: target_identity_matches, target_class_matches, state_identity_differs, experiment_differs, protocol_differs, observer_differs, observer_privilege_differs, observer_effective_uid_differs, report_schema_matches, environment_context_matches, measurement_differs.
Input schemas: base `6.0.0`, compare `6.0.0`; canonical comparison schema: `6.0.0`; migration mode: `temporary_in_memory`.

> **Comparison warning:** `mixed_state_and_observer_change_acknowledged`

| Dimension | Materiality | Direction | Confidence | Transition | Before | After | Rationale | Interpretation |
|---|---|---|---|---|---|---|---|---|
| Selected process visibility (`selected_process_visibility`) | moderate | context_change | moderate | context_change (observed → observed) | `{'name': 'init', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:init:s0'}}, {'name': 'adbd', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:adbd:s0'}}, {'name': 'zygote', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'zygote64', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:zygote:s0'}}, {'name': 'system_server', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:system_server:s0'}}, {'name': 'magisk', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'magiskd', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}` | `{'name': 'init', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:init:s0'}}, {'name': 'adbd', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:adbd:s0'}}, {'name': 'zygote', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'zygote64', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:zygote:s0'}}, {'name': 'system_server', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:system_server:s0'}}, {'name': 'magisk', 'visibility': {'status': 'not_collected', 'value': None}, 'context': {'status': 'not_collected', 'value': None}}, {'name': 'magiskd', 'visibility': {'status': 'observed', 'value': True}, 'context': {'status': 'observed', 'value': 'u:r:magisk:s0'}}` | materiality_from_dimension_policy, observer_or_target_context_changed, confidence_from_explicit_factors | Selected process visibility or sanitized contexts changed. Inconclusive scoped evidence is distinct from observed absence. |
| Root shell availability (`root_shell_availability`) | moderate | indeterminate | moderate | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Trust-state dimension changed between reports. |
| su invocation tested (`su_invocation_tested`) | low | indeterminate | moderate | collection_quality_change (not_collected → observed_absent) | `{"status": "not_collected", "value": null}` | `{"status": "observed_absent", "value": false}` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Trust-state dimension changed between reports. |
| Root-management artifact (`root_management_artifact`) | moderate | indeterminate | moderate | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Trust-state dimension changed between reports. |
| Magisk binary visibility (`magisk_binary_visibility`) | moderate | context_change | moderate | context_change (observed_absent → observed) | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | materiality_from_dimension_policy, observer_or_target_context_changed, confidence_from_explicit_factors | Trust-state dimension changed between reports. |
| Magisk daemon visibility (`magisk_daemon_visibility`) | moderate | indeterminate | moderate | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Trust-state dimension changed between reports. |
| Magisk process visibility (`magisk_process_visibility`) | moderate | indeterminate | moderate | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Trust-state dimension changed between reports. |
| Zygisk visibility (`zygisk_visibility`) | moderate | indeterminate | moderate | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": true}` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Trust-state dimension changed between reports. |
| Magisk version name (`magisk_version_name`) | informational | indeterminate | moderate | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": "28.1"}` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Trust-state dimension changed between reports. |
| Magisk version code (`magisk_version_code`) | informational | indeterminate | moderate | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": "28100"}` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Trust-state dimension changed between reports. |
| Magisk module context (`magisk_module_context`) | informational | indeterminate | moderate | collection_quality_change (not_collected → observed) | `{"status": "not_collected", "value": null}` | `{"status": "observed", "value": "androidtrustlab"}` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Trust-state dimension changed between reports. |

#### Signals became available

| Dimension | Materiality | Direction | Confidence | Status transition | Classification | Confidence impact | Observed values | Source evidence | Evidence paths | Rationale | Interpretation |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Root shell availability (`root_shell_availability`) | moderate | indeterminate | moderate | not_collected → observed | collection_quality_change | increased | `{"after": true, "before": null}` | `{"after": ["legacy-sections/ROOT_PROBE"], "before": []}` | `root_state.root_shell_available` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| su invocation tested (`su_invocation_tested`) | low | indeterminate | moderate | not_collected → observed_absent | collection_quality_change | increased | `{"after": false, "before": null}` | `{"after": ["legacy-sections/ROOT_PROBE"], "before": []}` | `root_state.su_invocation_tested` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Collection outcome changed from not_collected to observed_absent; this alone does not establish a target-state change. |
| Root-management artifact (`root_management_artifact`) | moderate | indeterminate | moderate | not_collected → observed | collection_quality_change | increased | `{"after": true, "before": null}` | `{"after": ["legacy-sections/ROOT_PROBE"], "before": []}` | `root_state.root_management_artifact_observed` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| Magisk daemon visibility (`magisk_daemon_visibility`) | moderate | indeterminate | moderate | not_collected → observed | collection_quality_change | increased | `{"after": true, "before": null}` | `{"after": ["legacy-sections/PS"], "before": []}` | `magisk_state.daemon_visibility` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| Magisk process visibility (`magisk_process_visibility`) | moderate | indeterminate | moderate | not_collected → observed | collection_quality_change | increased | `{"after": true, "before": null}` | `{"after": ["legacy-sections/PS"], "before": []}` | `magisk_state.process_visibility` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| Zygisk visibility (`zygisk_visibility`) | moderate | indeterminate | moderate | not_collected → observed | collection_quality_change | increased | `{"after": true, "before": null}` | `{"after": ["legacy-sections/MAGISK"], "before": []}` | `magisk_state.zygisk_visibility` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| Magisk version name (`magisk_version_name`) | informational | indeterminate | moderate | not_collected → observed | collection_quality_change | increased | `{"after": "28.1", "before": null}` | `{"after": ["legacy-sections/MAGISK"], "before": []}` | `magisk_state.version_name` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| Magisk version code (`magisk_version_code`) | informational | indeterminate | moderate | not_collected → observed | collection_quality_change | increased | `{"after": "28100", "before": null}` | `{"after": ["legacy-sections/MAGISK"], "before": []}` | `magisk_state.version_code` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
| Magisk module context (`magisk_module_context`) | informational | indeterminate | moderate | not_collected → observed | collection_quality_change | increased | `{"after": "androidtrustlab", "before": null}` | `{"after": ["legacy-sections/MAGISK"], "before": []}` | `magisk_state.module_context` | materiality_from_dimension_policy, collection_quality_is_not_target_direction, confidence_from_explicit_factors | Collection outcome changed from not_collected to observed; this alone does not establish a target-state change. |
