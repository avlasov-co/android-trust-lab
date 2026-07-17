# Android Trust Lab

## For reviewers

Start here if you are evaluating the repository quickly:

- Work manifest: `docs/work_manifest.md`
- Reviewer quickstart: `docs/reviewer_quickstart.md`
- Evidence matrix: `docs/evidence_matrix.md`
- Reviewer packet: `docs/reviewer_packet.md`
- Canonical project metadata: `docs/project_metadata.md`
- Versioning policy: `docs/versioning.md`
- Artifact manifest: `results/artifact_manifest.json`
- Verifiable dataset contract: `docs/dataset_manifest_v2.md`
- One-command validation: `bash scripts/verify_release.sh`

Android Trust Lab is a reproducible research harness for measuring Android trust-state transitions across controlled system configurations.

The analyzer supports Python 3.11, 3.12, 3.13, and 3.14. Python 3.11 is the
minimum supported runtime.

Raw inputs cross a version-aware, observer-specific typed adapter boundary
before normalization. Adapter selection uses declared metadata, and legacy
sectioned text remains an explicit warned compatibility path. See
`docs/artifact_adapters.md` and the shared bounded-input policy in
`docs/parser_limits.md`.

It is not a root detector, bypass tool, root-hiding framework, Magisk hiding project, Play Integrity bypass project, SafetyNet bypass project, banking-app bypass project, or DuckDetector clone.

The project studies a narrower and cleaner question:

> How do Android trust-state signals change when an Android target moves between controlled states?

Example states include stock AVD, rooted AVD, writable-system AVD, safe modified-property experiments, an optional read-only Magisk privileged collector, and later physical-device validation.

## Why this exists

Android trust state is not a single boolean. It is distributed across bootloader state, Android Verified Boot, vbmeta, dm-verity, SELinux, mount layout, system properties, root visibility, Magisk visibility, process visibility, app-visible APIs, root-visible signals, and emulator-vs-physical-device differences.

Most casual tooling collapses this into a verdict. Android Trust Lab does not. It records observations, normalizes them into a schema, compares reports, and documents limitations.

## What the framework collects

Android Trust Lab supports several observer classes:

| Observer | Purpose | Example visibility |
|---|---|---|
| host | provenance | host OS, adb version, emulator/AVD metadata |
| adb_shell | shell-level target view | getprop, mounts, id, getenforce, selected process data |
| unprivileged_app | normal app view | Build values, limited filesystem/API state |
| root_collector | privileged read-only snapshot | boot props, mounts, SELinux, Magisk/process state |

The optional Magisk module is only a privileged collector. It does not change system behavior.

## Architecture

```text
host / adb / app / root collector
        ↓
collection manifest + integrity-bound raw artifacts
        ↓
typed artifact adapter + parser
        ↓
content-addressed trust-report v5 JSON
        ↓
diff engine
        ↓
trust-diff v2.2 JSON + markdown summary
```

## Implemented scope in this release

| Capability | Status |
|---|---|
| Python analyzer CLI for normalize / migrate / collection and dataset validation / diff / summarize | implemented |
| Strict portable collection-manifest v1 for every observer class | implemented |
| Typed, versioned artifact adapters for legacy / ADB / host / app / root inputs | implemented |
| Strict verifiable dataset-manifest v2 with deterministic freshness checks | implemented |
| Content-addressed report v5 and exact-input diff v2.2 identities | implemented |
| Structured SELinux/process evidence with scoped absence semantics | implemented |
| Raw text parsing, normalization, schema validation, and diff generation | implemented |
| Synthetic / AVD-limited sample reports and generated result diffs | implemented |
| Read-only Magisk root collector module | implemented |
| Deterministic Magisk structural packaging guardrails | implemented through `tools/package_magisk_module.py` |
| Android app, Gradle project, and instrumentation tests | not present |
| Unprivileged app probe | design only |
| APK manifest / permission analyzer | not present |
| Physical-device validation | not collected in this release |

For a reviewer-focused runbook, see `docs/reviewer_quickstart.md`. The identity
projection and volatile exclusions are specified in `docs/content_identity.md`.

## Reviewer smoke checks

From the repository root:

```bash
python -m pip install -e "analyzer[dev]"
pytest -q
python tools/generate_report.py --check
trustlab dataset verify datasets/manifest.json
python tools/package_magisk_module.py --check-only
for f in module/trustlab-magisk/*.sh module/trustlab-magisk/scripts/*.sh; do sh -n "$f"; done
```

These checks validate analyzer tests, generated sample artifacts, and the
Magisk collector's deterministic structural packaging contract. Packaging
validation does not prove shell-script runtime semantics.

## Basic virtual-target workflow

```bash
cd analyzer
python -m pip install -e ".[dev]"
cd ..

trustlab normalize   --input tests/fixtures/sample_raw_report.txt   --output /tmp/stock_report.json   --experiment-id E01_stock_avd   --observer adb_shell   --target-type avd

trustlab validate-report /tmp/stock_report.json

trustlab diff   --base datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json   --compare datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json   --output /tmp/root_diff.json

trustlab summarize /tmp/root_diff.json
```

## Example trust-state diff

```json
{
  "dimension": "su_binary_visibility",
  "before": {"status": "observed_absent", "value": false},
  "after": {"status": "observed", "value": true},
  "transition": {
    "before_status": "observed_absent",
    "after_status": "observed",
    "classification": "state_change",
    "confidence_impact": "unchanged"
  },
  "materiality": "moderate",
  "direction": "indeterminate",
  "confidence": {
    "level": "moderate",
    "factors": {
      "evidence_statuses": {"before": "observed_absent", "after": "observed"},
      "field_confidence": {"before": "not_available", "after": "not_available"},
      "corroborating_evidence_count": 1,
      "migration_count": 0,
      "comparability": "comparable",
      "comparability_warning_count": 0
    },
    "rationale": [
      "both_sides_successfully_observed",
      "field_confidence_unavailable",
      "corroborating_evidence_limited",
      "inputs_compared_without_migration",
      "comparison_fully_comparable"
    ]
  },
  "rationale": [
    "materiality_from_dimension_policy",
    "no_justified_direction_rule",
    "confidence_from_explicit_factors"
  ],
  "interpretation": "Root-related evidence changed between reports. This is an observation, not an app verdict or bypass claim.",
  "evidence_paths": [
    "root_state.su_binary_observed"
  ]
}
```

Materiality, direction, and confidence are separate per-dimension assessments. They are never aggregated into a universal trust score.

## Current limitations

This version validates the collection and analysis pipeline on virtual targets. Hardware-backed trust behavior requires physical-device validation.

Emulator data is useful for collector development, schema design, analyzer testing, normalization, diff generation, and CI-friendly samples. It cannot prove OEM bootloader behavior, Qualcomm/Xiaomi boot-chain behavior, TEE behavior, hardware attestation correctness, Widevine/DRM conclusions, vendor/HAL mismatch behavior, Goodix/FOD behavior, or Mi 9-specific conclusions.

## Safety scope

Use this project only on owned devices, test images, AVDs, lab systems, and explicitly authorized targets.

Do not use this repository to bypass security checks, hide root, evade app detection, weaken SELinux, spoof device identity, persist malware, bypass DRM, or attack remote systems.

## References

- Android Verified Boot: https://source.android.com/docs/security/features/verifiedboot/avb
- dm-verity: https://source.android.com/docs/security/features/verifiedboot/dm-verity
- Android SELinux: https://source.android.com/docs/security/features/selinux
- Magisk developer guide: https://topjohnwu.github.io/Magisk/guides.html
