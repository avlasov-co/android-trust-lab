# v0.2.0 Untagged Release Candidate: Multi-observer Trust Evidence Pipeline

## Status

This is an untagged release candidate, not a released version. Git history has
no `v0.2.0` tag, and no release date or published archive is claimed. This file
does not define the current package version; development continues as
`0.3.0.dev0`.

## Highlights

- Design-only app-probe metadata and normalization scaffolding.
- Observer-aware diff classification.
- Dimension-level confidence provenance.
- Manifest-driven sample and diff generation.
- Expanded Magisk collector safety guardrail tests.
- Regenerated evidence packet and reviewer docs.

## Historical validation note

An earlier draft recorded a local verification run, but the repository contains
no durable attestation for that run. Use `bash scripts/check.sh` on the current
commit for reproducible validation; do not treat the old draft count as release
evidence.

## Safety scope

This remains defensive and measurement-focused. It does not implement bypass logic, root hiding, Play Integrity/SafetyNet evasion, DRM bypass, or production security certification. Physical-device validation remains unclaimed unless real device artifacts are collected separately.

## Artifact status

No v0.2.0 code archive, Magisk module archive, tag, or published release asset is
tracked by this repository. Creating or publishing any such artifact is outside
this phase.
