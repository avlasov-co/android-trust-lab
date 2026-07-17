# Evidence Matrix

| Reviewer signal | Repo evidence | Why it matters |
|---|---|---|
| Technical execution | `analyzer/`, `tools/generate_report.py`, `tests/` | Shows working code, not just documentation |
| Reproducibility | `scripts/verify_release.sh`, `tools/generate_report.py --check`, `tools/package_magisk_module.py --check-only` | Lets a reviewer verify core outputs locally |
| Defensive Android trust framing | `README.md`, `docs/work_manifest.md`, `docs/trust_model.md`, `docs/threat_model.md` | Keeps the project focused on measurement instead of app-bypass theater |
| Safety boundaries | `SECURITY.md`, `docs/work_manifest.md`, collector tests | Makes runtime boundaries reviewable without overstating packaging validation |
| Empirical discipline | `datasets/source.json`, `datasets/manifest.json`, `datasets/samples/`, `datasets/derived/diffs/`, `results/trust_state_diffs.md` | Separates source evidence from derived output and binds every artifact |
| Generated artifacts | `results/summary_table.md`, `results/trust_state_diffs.md`, `results/figures/trust_dimensions_matrix.md`, `results/figures/cross_observer_matrix.md` | Gives reviewers concrete artifacts to compare and regenerate |
| Cross-observer behavior | `experiments/E35_cross_observer.md`, `tests/fixtures/cross_observer_bundle/`, `tests/test_cross_observer_fixtures.py`, `docs/cross_observer_fixture.md` | Demonstrates one synthetic target state through app, ADB, and root observers with independent source hashes, visibility-safe diffs, and contradiction provenance |
| Schema discipline | versioned report and diff schemas through report 6.0 and diff 2.8, content identities, and migration/schema tests | Prevents report shape drift and unverifiable output formats |
| Maintainability | `tests/`, `.github/workflows/ci.yml`, `.github/workflows/android.yml`, `.github/workflows/docs.yml`, `CONTRIBUTING.md` | Shows the project can be changed without relying on vibes and caffeine fumes |
| Android contract testing | `app/observer/src/test/`, `app/observer/src/androidTest/`, `docs/android_testing.md`, `tests/test_app_export_contract.py` | Connects JVM, installed-app, merged-manifest, and Python normalization evidence |
| Honest limitations | `docs/work_manifest.md`, `docs/reviewer_quickstart.md`, `experiments/E99_physical_device_template.md` | Keeps AVD-managed testing separate from missing physical-device validation and general APK analysis |
| Public artifact value | `README.md`, `docs/reviewer_packet.md`, `docs/reviewer_quickstart.md`, `docs/evidence_matrix.md` | Lets a technical reviewer understand what to inspect first |
| Packaging discipline | `module/trustlab-magisk/`, `tools/package_magisk_module.py`, `tests/test_package_magisk_module.py` | Shows a closed payload, normalized ZIP metadata/modes, and exact-byte reproducibility |
| Reviewer speed | `docs/reviewer_packet.md`, `docs/work_manifest.md`, `scripts/verify_release.sh` | Compresses review into a short reading path plus one validation command |
