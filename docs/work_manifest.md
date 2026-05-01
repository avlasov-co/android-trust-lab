# Android Trust Lab Work Manifest

## Purpose

Android Trust Lab is a defensive research and engineering lab for measuring and comparing Android trust-state signals across controlled configurations.

The repository focuses on reproducible analyzer workflows, schema-validated reports, generated diffs/tables/results, and a read-only Magisk collector design. It is not a bypass toolkit, not an Android app suite, not a fake Gradle project, and not a production security certification system.

The core question is simple:

> When a controlled Android target changes state, what observable trust-state signals change, and which observer can see them?

Current checked-in evidence is synthetic / AVD-limited. Physical-device validation is explicitly out of scope for this release unless future reports are added with real device evidence.

## Implemented components

| Component | Status | Evidence | Verification command |
|---|---|---|---|
| Analyzer CLI | Implemented | `analyzer/trustlab/cli.py`, `analyzer/pyproject.toml` | `PYTHONPATH=analyzer trustlab --help` after editable install, or `PYTHONPATH=analyzer python -m trustlab.cli --help` |
| Parser / normalizer | Implemented | `analyzer/trustlab/parser.py`, `analyzer/trustlab/normalizer.py`, `tests/test_parser.py`, `tests/test_normalizer.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_parser.py tests/test_normalizer.py` |
| Diff engine | Implemented | `analyzer/trustlab/diff.py`, `tests/test_diff.py`, `results/diffs/` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_diff.py` |
| JSON schemas | Implemented | `collector/schema/trust_report.schema.json`, `collector/schema/trust_diff.schema.json`, `tests/test_schema_validation.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_schema_validation.py` |
| Sample reports | Implemented | `datasets/samples/`, `datasets/manifest.json` | `python tools/generate_report.py --check` |
| Generated diffs/tables | Implemented | `results/diffs/`, `results/summary_table.md`, `results/trust_state_diffs.md`, `results/figures/trust_dimensions_matrix.md` | `python tools/generate_report.py --check` |
| Magisk collector | Implemented | `module/trustlab-magisk/`, `docs/magisk_collector_design.md`, `module/trustlab-magisk/README.md` | `find module/trustlab-magisk -name "*.sh" -print -exec sh -n {} \;` |
| Magisk packaging helper | Implemented | `tools/package_magisk_module.py`, `tests/test_package_magisk_module.py` | `python tools/package_magisk_module.py --check-only` |
| Tests | Implemented | `tests/` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q` |
| CI checks | Implemented | `.github/workflows/ci.yml`, `.github/workflows/docs.yml` | GitHub Actions on push / PR |
| One-command release verification | Implemented | `scripts/verify_release.sh` | `bash scripts/verify_release.sh` |
| Android app | Not implemented | No app source tree, Kotlin/Java app code, or Android application manifest exists | Not applicable |
| Gradle project | Not implemented | No `build.gradle`, `settings.gradle`, or Gradle wrapper exists | Not applicable |
| Instrumentation tests | Not implemented | No Android instrumentation test source exists | Not applicable |
| Physical-device validation | Not performed | `experiments/E99_physical_device_template.md` is a template only | Not applicable |
| APK analyzer | Not implemented | No APK parser, AndroidManifest parser, or permission policy checker exists | Not applicable |
| Play Integrity / SafetyNet bypass | Not implemented and intentionally out of scope | `SECURITY.md`, this manifest | Not applicable |

## Implemented vs design-only

| Area | Status | Evidence / note |
|---|---|---|
| Python analyzer CLI | Implemented | CLI and package entry point exist in `analyzer/` |
| Raw report parsing | Implemented | Parser code and parser tests exist |
| Report normalization | Implemented | Normalizer code and sample reports exist |
| Schema validation | Implemented | JSON schemas and validation tests exist |
| Trust-state diffing | Implemented | Diff engine, generated diff JSON files, and markdown summaries exist |
| Generated artifact workflow | Implemented | `tools/generate_report.py --check` verifies checked-in derived outputs |
| Read-only Magisk collector | Implemented | Module files and shell collectors exist under `module/trustlab-magisk/` |
| Magisk package guardrails | Implemented | Packaging helper rejects common mutation payload locations |
| Release verification script | Implemented | `scripts/verify_release.sh` runs compile, tests, generated-output, package, and shell checks |
| AVD-limited sample workflow | Implemented | Sample directories are checked in under `datasets/samples/` |
| Unprivileged app probe | Design-only | `collector/android/app_probe_design.md` exists, but no app implementation exists |
| Privileged probe design notes | Partially implemented | Design notes exist and the Magisk collector implements a read-only root-observer path |
| Emulator workflow | Partially implemented | Experiment docs and sample artifacts exist; no fully automated emulator launch/run harness is included |
| Physical-device workflow | Design-only | Template exists, but no collected physical-device reports are checked in |
| Android app | Not implemented | No app project exists |
| Gradle build | Not implemented | No Gradle files exist |
| Instrumentation tests | Not implemented | No Android test harness exists |
| APK manifest / permission analysis | Not implemented | No APK analyzer exists |
| Production attestation / certification | Not applicable | The repo records measurements; it does not certify device security |
| Root hiding / bypass / evasion logic | Not applicable | Explicitly disallowed by safety policy |

## Safety boundaries

This repository is limited to defensive measurement and reproducible research.

Allowed scope:

- measuring Android trust-state signals in controlled environments;
- comparing observer-visible state across checked-in reports;
- validating reports against schemas;
- producing reproducible diffs, tables, and summaries;
- collecting read-only local device state only on owned or explicitly authorized lab targets;
- documenting limitations and uncertainty.

Disallowed scope:

- exploit development;
- Play Integrity, SafetyNet, DRM, or app-specific bypass work;
- root hiding or Magisk hiding;
- credential collection;
- stealth behavior;
- persistence mechanisms;
- mutation payloads or filesystem overlay payloads;
- privilege escalation;
- real user identifiers or secrets;
- production security certification claims.

The Magisk module is treated as a read-only collector. The packaging helper refuses common payload paths such as `system/`, `vendor/`, `product/`, `system_ext/`, `odm/`, `system.prop`, `META-INF`, and embedded zip files.

## Reproducibility commands

From the repository root:

```bash
bash scripts/verify_release.sh
```

The script runs the strongest checked-in release checks:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m compileall -q analyzer tools tests
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer python -m pytest -q
python tools/generate_report.py --check
python tools/package_magisk_module.py --check-only
find module/trustlab-magisk -name "*.sh" -print -exec sh -n {} \;
```

If the analyzer has not been installed, the script still sets `PYTHONPATH=analyzer` so local tests can run from source. If `pytest` or `jsonschema` are missing, install development dependencies first:

```bash
python -m pip install -e "analyzer[dev]"
```

## Validation status

Latest validation for this evidence packet:

| Check | Command | Status |
|---|---|---|
| Release verification | `bash scripts/verify_release.sh` | Not completed in this container: normal Python startup timed out before repo code executed |
| Python compile check | `python -S -m compileall -q analyzer tools tests` | Pass |
| Unit tests | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer python -m pytest -q` | Not completed in this container because Python site-package startup timed out |
| Generated report freshness | `python tools/generate_report.py --check` | Not completed in this container because normal Python startup timed out |
| Magisk package safety | `python -S tools/package_magisk_module.py --check-only` | Pass |
| Magisk shell syntax | `find module/trustlab-magisk -name "*.sh" -print -exec sh -n {} \;` | Pass |
| Artifact manifest JSON syntax | `jq empty results/artifact_manifest.json` | Pass |

Fallback validation was used only because of the container Python environment. In a normal local or CI environment with analyzer development dependencies installed, run `bash scripts/verify_release.sh` as the authoritative release check.

## Known limitations

- No Android app is implemented.
- No Gradle build is implemented.
- No Android instrumentation tests are implemented.
- No physical-device validation reports are checked in.
- No APK reverse engineering, AndroidManifest analysis, or permission parser is implemented.
- No production attestation, hardware-backed trust, TEE, OEM boot-chain, Widevine, DRM, or device-specific security conclusions are claimed.
- Current samples are synthetic / AVD-limited and intended for analyzer and collector workflow validation.
- The unprivileged app probe is design-only.
- The physical-device experiment file is a template, not completed evidence.

## Why this project matters

For a fellowship or residency-style review, this project shows:

- technical execution through working parser, normalizer, schema validation, diffing, CLI tooling, tests, and packaging checks;
- reproducibility through checked-in samples, generated reports, and a one-command verification script;
- defensive Android trust framing without bypass or evasion scope;
- empirical measurement discipline through structured reports and generated diffs instead of vague trust scoring;
- reviewer-verifiable artifacts that can be inspected and regenerated;
- honest scope control, including clear separation between implemented, design-only, and not implemented areas.
