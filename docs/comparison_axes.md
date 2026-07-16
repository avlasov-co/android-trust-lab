# Comparison Axes and Comparability

Introduced in diff `2.5.0` and retained by current diff `2.6.0`, comparison-axis classification runs before interpreting target-state dimensions. Reports may carry the identity-bound `org.androidtrustlab.comparison-context` extension with a privacy-preserving target pseudonym, state ID, and environment context. Target class, experiment, collection protocol, observer, observer privilege, report schema, and measurement ID are bound from the report itself.

The classifier emits one axis:

| Axis | Meaning | Comparability |
|---|---|---|
| `same_target_state_change` | Same target and observer context; declared state changed | comparable |
| `same_state_observer_change` | Same target and state; observer, privilege, or protocol changed | comparable as a visibility-context comparison |
| `repeat_measurement` | Target, state, and observer context match | comparable |
| `different_target_context` | Target pseudonym, target class, or environment differs | limited |
| `mixed_change` | State and observer context both changed | limited and requires `--allow-mixed` |
| `incomparable` | Required target, state, observer, or environment metadata is missing | incomparable |

`comparison.reasons` records a deterministic match, difference, or missing-metadata reason for every classification field. `comparison.warnings` is rendered prominently in Markdown. Observer privilege and effective observer UID are visibility context and are excluded from the target-state dimension list.

The analyzer never derives a target pseudonym from a serial or other direct identifier. Collection manifests can supply a stable random pseudonym; otherwise the context remains `unknown`. Synthetic dataset fixtures use an explicit project-authored pseudonym that represents only the fixture target.
