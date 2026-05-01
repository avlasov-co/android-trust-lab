# Evidence Matrix

| Reviewer signal | Repo evidence | Why it matters |
|---|---|---|
| Technical execution | `analyzer/`, `tools/generate_report.py`, `tests/` | Shows working code, not just documentation |
| Reproducibility | `scripts/verify_release.sh`, `tools/generate_report.py --check`, `tools/package_magisk_module.py --check-only` | Lets a reviewer verify core outputs locally |
| Defensive Android trust framing | `README.md`, `docs/work_manifest.md`, `docs/trust_model.md`, `docs/threat_model.md` | Keeps the project focused on measurement instead of app-bypass theater |
| Safety boundaries | `SECURITY.md`, `docs/work_manifest.md`, `tools/package_magisk_module.py` | Prevents the repo from reading like offensive tooling |
| Empirical discipline | `datasets/samples/`, `datasets/manifest.json`, `results/diffs/`, `results/trust_state_diffs.md` | Shows measured trust-state outputs from checked-in samples |
| Generated artifacts | `results/summary_table.md`, `results/trust_state_diffs.md`, `results/figures/trust_dimensions_matrix.md` | Gives reviewers concrete artifacts to compare and regenerate |
| Schema discipline | `collector/schema/trust_report.schema.json`, `collector/schema/trust_diff.schema.json`, `tests/test_schema_validation.py` | Prevents report shape drift and unverifiable output formats |
| Maintainability | `tests/`, `.github/workflows/ci.yml`, `.github/workflows/docs.yml`, `CONTRIBUTING.md` | Shows the project can be changed without relying on vibes and caffeine fumes |
| Honest limitations | `docs/work_manifest.md`, `docs/reviewer_quickstart.md`, `experiments/E99_physical_device_template.md` | Makes missing Android app, Gradle, instrumentation, and physical-device scope explicit |
| Public artifact value | `README.md`, `docs/reviewer_packet.md`, `docs/reviewer_quickstart.md`, `docs/evidence_matrix.md` | Lets a technical reviewer understand what to inspect first |
| Packaging discipline | `module/trustlab-magisk/`, `tools/package_magisk_module.py`, `tests/test_package_magisk_module.py` | Shows the Magisk collector is packaged with guardrails against mutation payloads |
| Reviewer speed | `docs/reviewer_packet.md`, `docs/work_manifest.md`, `scripts/verify_release.sh` | Compresses review into a short reading path plus one validation command |
