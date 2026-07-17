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
| Typed artifact adapters | Implemented | `analyzer/trustlab/artifacts.py`, `docs/artifact_adapters.md`, versioned adapter schemas, `tests/test_artifact_adapters.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_artifact_adapters.py` |
| Bounded parser and hostile-input policy | Implemented | `docs/parser_limits.md`, `analyzer/trustlab/parser.py`, `tests/test_parser_limits.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_parser_limits.py tests/test_adversarial_inputs.py` |
| Structured SELinux/process evidence | Implemented | `analyzer/trustlab/security_evidence.py`, `docs/report_schema_v5.md`, `tests/test_structured_security_evidence.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_security_evidence.py tests/test_structured_security_evidence.py` |
| Diff engine | Implemented | `analyzer/trustlab/diff.py`, `tests/test_diff.py`, `datasets/derived/diffs/` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_diff.py` |
| JSON schemas, identity, and migration | Implemented | report v1–v6 and diff v1–v2.8 schemas, `analyzer/trustlab/identity.py`, `analyzer/trustlab/migrations.py`, `tests/test_content_identity.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_schema_validation.py tests/test_content_identity.py tests/test_report_migration.py` |
| Portable collection manifests | Implemented | `collector/schema/collection_manifest_v1_0_0.schema.json`, `analyzer/trustlab/collection_manifest.py`, `tests/test_collection_manifest.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_collection_manifest.py` |
| Bounded host collector | Implemented | `analyzer/trustlab/host_collector.py`, `collector/host/collect_host_snapshot.md`, `tests/test_host_collector.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_host_collector.py` |
| Read-only ADB collector | Implemented | `analyzer/trustlab/adb_collector.py`, `collector/host/collect_adb_snapshot.md`, `tests/test_adb_collector.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_adb_collector.py` |
| Secure Magisk import | Implemented | `analyzer/trustlab/magisk_importer.py`, `docs/magisk_import_contract.md`, `tests/test_magisk_importer.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_magisk_importer.py` |
| Verifiable dataset manifest | Implemented | `datasets/source.json`, `datasets/manifest.json`, `docs/dataset_manifest_v2.md`, `analyzer/trustlab/dataset_manifest.py` | `trustlab dataset verify datasets/manifest.json` |
| Sample reports | Implemented | `datasets/samples/`, `datasets/manifest.json` | `python tools/generate_report.py --check` |
| Generated diffs/tables | Implemented | `datasets/derived/diffs/`, `results/summary_table.md`, `results/trust_state_diffs.md`, `results/figures/trust_dimensions_matrix.md`, `results/figures/cross_observer_matrix.md` | `python tools/generate_report.py --check` |
| Cross-observer fixture | Implemented | `experiments/E35_cross_observer.md`, `tests/fixtures/cross_observer_bundle/`, `docs/cross_observer_fixture.md`, `tests/test_cross_observer_fixtures.py` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q tests/test_cross_observer_fixtures.py` |
| Magisk collector | Implemented | `module/trustlab-magisk/`, `docs/magisk_collector_design.md`, `module/trustlab-magisk/README.md` | `find module/trustlab-magisk -name "*.sh" -print -exec sh -n {} \;` |
| Magisk packaging helper | Implemented | `tools/package_magisk_module.py`, `tests/test_package_magisk_module.py` | `python tools/package_magisk_module.py --check-only` |
| Tests | Implemented | `tests/` | `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer pytest -q` |
| CI checks | Implemented | `.github/workflows/ci.yml`, `.github/workflows/android.yml`, `.github/workflows/docs.yml` | Fast checks on push / PR; API 35 PR smoke; scheduled/manual API 27/30/35 matrix |
| One-command release verification | Implemented | `scripts/verify_release.sh` | `bash scripts/verify_release.sh` |
| Android app | Implemented | `app/observer/`; collection-free startup plus explicit foreground probe, review, redaction preview, and verified local export | `cd app && ./gradlew --dependency-verification strict :observer:assembleDebug :observer:testDebugUnitTest :observer:lint` |
| Gradle project | Implemented | Requires JDK 17 / API 37; checksum-locks Gradle 9.4.1 and Maven artifacts with dependency locks/verification | Same Android scaffold gate |
| Android test automation | Implemented | JVM, strict lint, debug/release merged manifests, seven installed-app cases, PR managed smoke, scheduled API matrix, and Kotlin-to-Python export bridge; see `docs/android_testing.md` | `cd app && ./gradlew --dependency-verification strict :observer:pixel2Api35DebugAndroidTest -Pandroid.testoptions.manageddevices.emulator.gpu=swiftshader_indirect` |
| Physical-device validation | Not performed | `experiments/E99_physical_device_template.md` is a template only | Not applicable |
| General post-build APK analyzer | Not implemented | The observer's merged target manifests have an exact build-time policy; no arbitrary-APK parser or reverse-engineering analyzer exists | Not applicable |
| Play Integrity / SafetyNet bypass | Not implemented and intentionally out of scope | `SECURITY.md`, this manifest | Not applicable |

## Implemented vs design-only

| Area | Status | Evidence / note |
|---|---|---|
| Python analyzer CLI | Implemented | CLI and package entry point exist in `analyzer/` |
| Raw report parsing | Implemented | Parser code and parser tests exist |
| Report normalization | Implemented | Normalizer code and sample reports exist |
| Schema validation | Implemented | JSON schemas and validation tests exist |
| Trust-state diffing | Implemented | Diff engine, generated diff JSON files, and markdown summaries exist |
| Generated artifact workflow | Implemented | `tools/generate_report.py --check` verifies dataset and separate cross-observer derived outputs |
| Read-only Magisk collector | Implemented | Module files and shell collectors exist under `module/trustlab-magisk/` |
| Magisk package guardrails | Implemented | Closed 15-file payload, bounded regular-file inventory, normalized ZIP modes/metadata, and two-build byte comparison |
| Release verification script | Implemented | `scripts/verify_release.sh` runs compile, tests, generated-output, package, and shell checks |
| AVD-limited sample workflow | Implemented | Sample directories are checked in under `datasets/samples/` |
| Unprivileged app probe | Implemented | Typed public-API collector and adapter, explicit foreground review flow, exact redaction preview, and verified temporary-document SAF publication |
| Privileged probe design notes | Partially implemented | Design notes exist and the Magisk collector implements a read-only root-observer path |
| Emulator workflow | Implemented for app contract tests | Gradle Managed Device API 35 PR smoke and scheduled/manual API 27/30/35 instrumentation matrix; experiment collection remains separately controlled |
| Physical-device workflow | Design-only | Template exists, but no collected physical-device reports are checked in |
| Android app | Implemented | One unprivileged `:observer` module; launch only renders scope and collection requires acknowledgement plus explicit Start |
| Gradle build | Implemented | Requires external JDK 17 / API 37; checksum-locks Gradle 9.4.1 and Maven artifacts with dependency locks/verification |
| Android test automation | Implemented | Seven AndroidJUnit4 installed-app cases plus managed-device CI and strict merged-manifest verification |
| General post-build APK analysis | Not implemented | Observer target manifests are checked during the build; arbitrary APKs are not parsed or analyzed |
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
generated-output freshness checks, deterministic Magisk structural packaging, and shell
syntax checks. It sets `PYTHONPATH=analyzer` so local tests run from source. If
development dependencies are missing, install them first:

```bash
python -m pip install -e "analyzer[dev]"
```

## Validation status

Latest validation for this evidence packet:

| Check | Command | Status |
|---|---|---|
| Complete repository gate | `bash scripts/check.sh` in the activated development environment | Pass on 2026-07-17 |
| Ruff formatting and lint | Gate steps 2–3 | Pass; 91 Python files formatted and linted |
| Strict static typing | Gate step 4 | Pass for 49 analyzer and tool modules |
| Unit tests | Gate step 5 | 1,040 passed on the development runtime; CI covers Python 3.11, 3.12, 3.13, and 3.14 |
| Analyzer coverage | Gate step 5 | 89.43% statements; 80.40% branches; floors 85%/80% |
| Tools coverage | Gate step 5 | 87.03% statements; 75.95% branches; floors 70%/60% |
| Canonical metadata | Gate step 6 | Pass, including CFF 1.2 structure |
| Project version | Gate step 7 | Pass at `0.3.0.dev0` |
| Python support declarations | Gate step 8 | Pass for Python 3.11, 3.12, 3.13, and 3.14 |
| Schema and checked-in artifacts | Gate step 10 | 24 schemas, 30 registry dimensions, 11 reports, 9 diffs, 4 collection manifests, 3 dataset manifests, and 1 dataset source validated |
| Generated report freshness | Gate step 11 | Pass; generated artifacts are up to date |
| Magisk structural packaging | Gate step 12 | Pass; exact payload, modes, metadata, and two-build byte identity |
| Shell syntax and ShellCheck | Gate steps 13–14 | Pass for 12 Magisk scripts and both repository Bash scripts |
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
through v5 are read-only compatibility inputs and report v6 is the current
validated writer. Diff v1 through v2.7 are read-only, and diff v2.8 is the
current writer. Strict
collection manifest v1 is readable and writable. Dataset manifest v1 remains
readable, strict dataset manifest v2
is the sole verified writer format, and dataset source v1 drives deterministic
generation. Experiment specs remain planned rather than falsely advertised as
supported.

## Known limitations

- Android export depends on a local DocumentsProvider advertising write, delete, and rename support; Android does not promise filesystem-style atomic rename across every third-party provider.
- Android managed-device evidence is AVD-limited; API 26 is the app minimum but the automated GMD matrix begins at the supported API 27 level.
- No physical-device validation reports are checked in.
- No general post-build APK reverse engineering or arbitrary-APK permission analyzer is implemented; the observer's own merged manifests are checked at build time.
- No production attestation, hardware-backed trust, TEE, OEM boot-chain, Widevine, DRM, or device-specific security conclusions are claimed.
- Current samples are synthetic / AVD-limited and intended for analyzer and collector workflow validation.
- The cross-observer bundle is project-authored synthetic evidence; it is not an AVD capture and does not represent physical OEM behavior.
- Dataset verification and repository generation require POSIX directory-descriptor safety primitives in this release.
- The physical-device experiment file is a template, not completed evidence.

## Why this project matters

For a fellowship or residency-style review, this project shows:

- technical execution through working parser, normalizer, schema validation, diffing, CLI tooling, tests, and packaging checks;
- reproducibility through checked-in samples, generated reports, and a one-command verification script;
- defensive Android trust framing without bypass or evasion scope;
- empirical measurement discipline through structured reports and generated diffs instead of vague trust scoring;
- reviewer-verifiable artifacts that can be inspected and regenerated;
- honest scope control, including clear separation between implemented, design-only, and not implemented areas.
