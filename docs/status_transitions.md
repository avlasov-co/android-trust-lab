# Status-Aware Diff Transitions

Introduced in diff `2.6.0` and retained by current diff `2.7.0`, status-aware comparison keeps evidence status separate from observed values. A literal observed string such as `unknown` therefore remains data and cannot collide with the `not_collected`, `inaccessible`, `command_error`, or `unsupported` outcomes.

Every changed dimension records its before and after status, transition classification, and confidence impact. Availability changes also produce structured entries in `new_signals` or `missing_signals` with observed values, source evidence references, and a status-specific interpretation.

| Transition | Classification | Signal direction |
|---|---|---|
| `not_collected` → `observed` | collection-quality change | new |
| `inaccessible` → `observed` | visibility change | new |
| `observed` → `inaccessible` | visibility change | missing, with inaccessible retained explicitly |
| `observed` → `observed_absent` | state change | neither |
| `command_error` → `observed` | collection-quality change | new |

Transitions under the `same_state_observer_change` comparison axis are classified as context changes. This prevents an observer boundary from masquerading as target mutation. `observed_absent` is successful negative evidence and is never treated as a collection failure.
