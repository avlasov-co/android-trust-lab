# Reviewer Packet

## Read these first

1. `README.md`
2. `docs/work_manifest.md`
3. `docs/reviewer_quickstart.md`
4. `docs/evidence_matrix.md`
5. `results/trust_state_diffs.md`
6. `docs/dataset_manifest_v2.md`
7. `results/artifact_manifest.json`
8. `docs/android_testing.md`
9. `SECURITY.md`

## Fast validation

```bash
bash scripts/verify_release.sh
```

## What this repo demonstrates

- Defensive Android trust-state measurement framing.
- A reproducible Python analyzer workflow.
- Parser, normalizer, schema validation, diff generation, and CLI tooling.
- Synthetic / AVD-limited sample reports.
- A strict, integrity-bound dataset graph with deterministic freshness checks.
- Generated diffs, tables, and result summaries.
- A read-only Magisk collector module.
- Deterministic structural packaging guardrails for the Magisk module; these do
  not prove shell-script runtime semantics.
- A JDK 17 / API 37 Android scaffold with a checksum-locked Gradle distribution
  and Maven dependency graph; its typed probe, explicit review/export flow,
  strict merged-target-manifest checks, and seven-case managed-device suite. The
  target observer APK requests no permissions.
- Clear responsible-use boundaries.
- Explicit implemented-vs-design-only scope.

## What this repo does not claim

- Managed-device evidence is AVD-limited and does not replace physical-device
  validation.
- No physical-device validation in this release.
- No general post-build or arbitrary-APK manifest/permission analyzer; only the
  observer target's build-time merged-manifest contract is enforced.
- No Play Integrity, SafetyNet, DRM, Widevine, or app-specific bypass work.
- No root hiding, stealth, persistence, or evasion tooling.
- No production security certification.
