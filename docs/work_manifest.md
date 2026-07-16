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
| Python support matrix | Implemented | `docs/python_support.md`, `.github/workflows/ci.yml`, `tools/check_python_support.py` | `python tools/check_python_support.py` |
| Repository quality controls | Implemented | `pyproject.toml`, `.pre-commit-config.yaml`, `.editorconfig`, `.gitattributes` | `bash scripts/check.sh` and `pre-commit run --all-files` |
| Independent CLI and adversarial tests | Implemented | `tests/test_installed_cli.py`, `tests/test_adversarial_inputs.py`, `tests/golden/` | `python -m pytest -q tests/test_installed_cli.py tests/test_adversarial_inputs.py` |
| CLI failure and write contract | Implemented | `docs/cli_contract.md`, `tests/test_cli_failures.py`, `tests/test_report_writer.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_cli_failures.py tests/test_report_writer.py` |
| Parser / normalizer | Implemented | `analyzer/trustlab/parser.py`, `analyzer/trustlab/normalizer.py`, `tests/test_parser.py`, `tests/test_normalizer.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_parser.py tests/test_normalizer.py` |
| Diff engine | Implemented | `analyzer/trustlab/diff.py`, `tests/test_diff.py`, `results/diffs/` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_diff.py` |
| JSON schemas and migration | Implemented | `collector/schema/trust_report_v1_0_0.schema.json`, `collector/schema/trust_report_v2_0_0.schema.json`, `analyzer/trustlab/migrations.py`, `tests/test_report_migration.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_schema_validation.py tests/test_report_migration.py` |
| Portable collection manifests | Implemented | `collector/schema/collection_manifest_v1_0_0.schema.json`, `analyzer/trustlab/collection_manifest.py`, `tests/test_collection_manifest.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_collection_manifest.py` |
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

The Magisk module is treated as a read-only collector. Its output is private by
default (`0700` run directories and `0600` artifacts under `/data/adb`), uses a
property allowlist, and omits the kernel command line. The packaging helper
enforces those controls and refuses common payload paths such as `system/`,
`vendor/`, `product/`, `system_ext/`, `odm/`, `system.prop`, `META-INF`, and
embedded zip files.

## Reproducibility commands

From the repository root:

```bash
bash scripts/verify_release.sh
```

The compatibility wrapper runs `scripts/check.sh`, the strongest checked-in
repository gate:

```bash
PYTHON_BIN=python3 bash scripts/check.sh
```

The command performs Python compilation, tests with branch coverage, canonical
metadata and version checks, explicit JSON Schema and artifact validation,
generated-output freshness checks, Magisk package safety checks, and shell
syntax checks. It sets `PYTHONPATH=analyzer` so local tests run from source. If
development dependencies are missing, install them first:

```bash
python -m pip install -e "analyzer[dev]"
```

## Validation status

Latest validation for this evidence packet:

| Check | Command | Status |
|---|---|---|
| Complete repository gate | `bash scripts/check.sh` in the activated development environment | Pass on 2026-07-16 |
| Ruff formatting and lint | Gate steps 2–3 | Pass; 46 Python files formatted and linted |
| Strict static typing | Gate step 4 | Pass for 26 analyzer and tool modules |
| Unit tests | Gate step 5 | 240 passed on Python 3.11, 3.12, 3.13, and 3.14 |
| Analyzer coverage | Gate step 5 | 93.97% statements (1201/1278); 83.33% branches (290/348); floors 85%/80% |
| Tools coverage | Gate step 5 | 87.69% statements (641/731); 74.84% branches (229/306); floors 70%/60% |
| Canonical metadata | Gate step 6 | Pass, including CFF 1.2 structure |
| Project version | Gate step 7 | Pass at `0.3.0.dev0` |
| Python support declarations | Gate step 8 | Pass for Python 3.11, 3.12, 3.13, and 3.14 |
| Schema and checked-in artifacts | Gate step 10 | 4 schemas, 7 reports, 5 diffs, and 1 collection manifest validated |
| Generated report freshness | Gate step 11 | Pass; generated artifacts are up to date |
| Magisk package safety | Gate step 12 | Pass |
| Shell syntax and ShellCheck | Gate steps 13–14 | Pass for 11 Magisk scripts and both repository Bash scripts |
| Secret detection | Gate step 15 | Pass against the checked-in baseline with network verification disabled |
| Pre-commit hygiene | `pre-commit run --all-files` | Pass for whitespace, EOF, JSON, YAML, Ruff, schemas, secrets, and ShellCheck |

Run `bash scripts/check.sh` or the compatible `bash scripts/verify_release.sh`
from an activated environment containing `analyzer[dev]`.

## Schema compatibility status

[ADR 0001](adr/0001-schema-evolution-and-compatibility.md) defines independent
schema versions, canonical evidence states, exact registry lookup, migration and
cross-version diff rules, canonical JSON identity, deprecation windows, and
sample-retention policy. The supported-version table and schema-resource
registry are machine-tested in `tests/test_compatibility_policy.py`. Report v1
is a read-only compatibility input, report v2 is the current validated writer
format, diff v1 remains current, and strict collection manifest v1 is readable
and writable. Experiment specs remain planned rather than falsely advertised as
supported.

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
