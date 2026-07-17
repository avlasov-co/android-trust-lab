# Trust Diff atldiff-bd940582560cc19eeb817a7d034b0ec7

1 dimensions changed, 27 dimensions unchanged; 0 signals became available, 0 signals became unavailable.

## Compatibility

- Input schemas: base `6.0.0`, compare `6.0.0`
- Canonical comparison schema: `6.0.0`
- Base migrations: none
- Compare migrations: none
- Warnings: none

## Comparison

- Axis: `incomparable`
- Comparability: `incomparable`
- Reasons: target_identity_missing, target_class_matches, state_identity_missing, experiment_differs, protocol_matches, observer_matches, observer_privilege_matches, observer_effective_uid_matches, report_schema_matches, environment_context_missing, measurement_differs

> **Warning:** Required comparison metadata is missing; inputs are incomparable.

| Dimension | Materiality | Direction | Confidence | Transition | Before | After | Rationale |
|---|---|---|---|---|---|---|---|
| su binary visibility (`su_binary_visibility`) | moderate | context_change | low | context_change (observed_absent → observed) | `{"status": "observed_absent", "value": false}` | `{"status": "observed", "value": true}` | materiality_from_dimension_policy, observer_or_target_context_changed, confidence_from_explicit_factors |

## Signals Became Available

None.

## Signals Became Unavailable

None.
