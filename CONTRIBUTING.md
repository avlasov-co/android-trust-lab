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

## Schema-change checklist

Every report, diff, dataset-manifest, collection-manifest, or experiment-spec
change must include an ADR or an explicit compatibility note linked from the
pull request. Before review:

- identify the independently versioned schema family and proposed SemVer impact;
- update the machine-readable support and validation registries when support changes;
- state read, write, migration, diff, and deprecation effects;
- preserve all canonical evidence statuses without magic-string fallbacks;
- add manually authored positive, negative, compatibility, and migration fixtures;
- prove deterministic canonical JSON and path-independent identity where relevant;
- regenerate generator-owned samples only through the canonical generator;
- retain historical and captured evidence instead of rewriting it in place;
- update the ADR index, compatibility documentation, and release notes as applicable.

The governing policy is [ADR 0001](docs/adr/0001-schema-evolution-and-compatibility.md).

## Local pull-request checks

Install the analyzer development dependencies, then run the same fast gate used
by pull requests:

```bash
python -m pip install -e "analyzer[dev]"
bash scripts/check.sh
```

The gate checks deterministic formatting, linting, static types, branch-aware
tests, metadata and schemas, generated artifacts, structural packaging, shell syntax,
ShellCheck, and baseline-aware secret detection. Pre-commit uses the same Ruff
and repository-specific checks for shorter feedback while editing.
