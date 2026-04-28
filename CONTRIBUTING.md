# Contributing

Contributions must preserve the project scope: reproducible Android trust-state measurement.

## Accepted contribution types

- parser improvements
- schema improvements
- documentation improvements
- experiment templates
- analyzer tests
- read-only collectors
- better provenance capture
- clearer limitation reporting

## Rejected contribution types

Pull requests will be rejected if they add:

- Play Integrity bypass logic
- SafetyNet bypass logic
- root hiding
- Magisk hiding
- Zygisk hiding
- app-specific evasion
- banking app bypass behavior
- DRM bypass behavior
- malware persistence
- stealth services
- SELinux weakening
- unexplained write operations
- property spoofing for bypass purposes

## Collector rules

Collectors should be read-only unless a specific experiment explicitly justifies otherwise.

Every collected signal must map to a trust dimension. Avoid collecting unrelated command output that does not support the trust model.

## Experiment rules

Every experiment must include:

- experiment_id
- target_type
- target_config
- preconditions
- controlled_change
- expected_state
- collection_steps
- artifacts_produced
- actual_state
- diff_summary
- limitations
- status

All new report types must follow the JSON schema.
