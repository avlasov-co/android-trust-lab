# v0.2.0: Multi-observer trust evidence pipeline

This release candidate upgrades Android Trust Lab into a multi-observer trust-state measurement framework.

## Highlights

- App-probe artifact schema and normalization path.
- Observer-aware diff classification.
- Dimension-level confidence provenance.
- Manifest-driven sample and diff generation.
- Expanded Magisk collector safety guardrail tests.
- Regenerated evidence packet and reviewer docs.

## Validation performed locally

```text
bash scripts/verify_release.sh
12 tests passed
generated artifacts are up to date
Magisk module safety checks passed
Magisk shell syntax checks passed
release verification passed
```

## Safety scope

This remains defensive and measurement-focused. It does not implement bypass logic, root hiding, Play Integrity/SafetyNet evasion, DRM bypass, or production security certification. Physical-device validation remains unclaimed unless real device artifacts are collected separately.

## Artifact status

The full code archive and Magisk module archive were generated locally from the v0.2.0 working tree. They are provided outside GitHub because the available connector in this environment exposes file/commit operations but does not expose GitHub Releases or binary asset upload.
