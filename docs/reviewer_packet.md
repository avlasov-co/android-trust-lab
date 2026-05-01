# Reviewer Packet

## Read these first

1. `README.md`
2. `docs/work_manifest.md`
3. `docs/reviewer_quickstart.md`
4. `docs/evidence_matrix.md`
5. `results/trust_state_diffs.md`
6. `results/artifact_manifest.json`
7. `SECURITY.md`

## Fast validation

```bash
bash scripts/verify_release.sh
```

## What this repo demonstrates

- Defensive Android trust-state measurement framing.
- A reproducible Python analyzer workflow.
- Parser, normalizer, schema validation, diff generation, and CLI tooling.
- Synthetic / AVD-limited sample reports.
- Generated diffs, tables, and result summaries.
- A read-only Magisk collector module.
- Packaging safety checks for the Magisk module.
- Clear responsible-use boundaries.
- Explicit implemented-vs-design-only scope.

## What this repo does not claim

- No Android app.
- No Gradle project.
- No instrumentation tests.
- No physical-device validation in this release.
- No APK manifest or permission analyzer.
- No Play Integrity, SafetyNet, DRM, Widevine, or app-specific bypass work.
- No root hiding, stealth, persistence, or evasion tooling.
- No production security certification.
