# Reviewer Quickstart

This guide separates checked-in behavior from design-only scope. The point is to make the repository easy to audit without guessing what exists.

## What is implemented in this release

| Area | Status | Evidence |
|---|---:|---|
| Python analyzer CLI | Implemented | `analyzer/trustlab/cli.py`, `analyzer/pyproject.toml` |
| Raw artifact parser | Implemented | `analyzer/trustlab/parser.py`, `tests/test_parser.py` |
| Trust report normalization | Implemented | `analyzer/trustlab/normalizer.py`, `tests/test_normalizer.py` |
| Trust diff generation | Implemented | `analyzer/trustlab/diff.py`, `tests/test_diff.py` |
| JSON schemas | Implemented | `collector/schema/trust_report.schema.json`, `collector/schema/trust_diff.schema.json` |
| Synthetic / AVD-limited samples | Implemented | `datasets/samples/`, `datasets/manifest.json` |
| Generated result tables and diffs | Implemented | `results/`, `tools/generate_report.py` |
| Read-only Magisk root collector | Implemented | `module/trustlab-magisk/`, `docs/magisk_collector_design.md` |
| Magisk module packaging safety check | Implemented | `tools/package_magisk_module.py`, `tests/test_package_magisk_module.py` |
| Android app / Gradle project | Not present | No `build.gradle`, `settings.gradle`, `AndroidManifest.xml`, Kotlin, or Java app source is included |
| Unprivileged app probe | Design only | `collector/android/app_probe_design.md` |
| APK manifest or permission analyzer | Not present | No APK parser, manifest parser, or permission-policy checker is included |
| Physical-device validation | Not collected | `experiments/E99_physical_device_template.md` |

## Minimal local verification

From the repository root:

```bash
bash scripts/verify_release.sh
```

That script runs the checked-in release checks:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m compileall -q analyzer tools tests
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer python -m pytest -q
python tools/generate_report.py --check
python tools/package_magisk_module.py --check-only
find module/trustlab-magisk -name "*.sh" -print -exec sh -n {} \;
```

If `pytest` or `jsonschema` are missing, install development dependencies first:

```bash
python -m pip install -e "analyzer[dev]"
```

Expected high-level result:

```text
18+ tests passed
generated artifacts are up to date
Magisk module safety checks passed
Magisk shell syntax checks pass
```

The exact test count may increase as the repo grows. The important part is that tests pass, generated artifacts are not stale, and the module packaging safety check refuses mutation payloads.

## Minimal analyzer demo

Normalize a checked-in raw artifact:

```bash
trustlab normalize \
  --input datasets/samples/stock_avd/raw_sample.txt \
  --output /tmp/atl_stock_report.json \
  --experiment-id E01_stock_avd \
  --observer adb_shell \
  --target-type avd \
  --collection-method adb_shell_snapshot \
  --collection-timestamp 2026-04-25T15:06:21Z \
  --raw-artifact-ref datasets/samples/stock_avd/raw_sample.txt

trustlab validate-report /tmp/atl_stock_report.json
```

Compare stock and rooted AVD sample reports:

```bash
trustlab diff \
  --base datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json \
  --compare datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json \
  --output /tmp/atl_stock_vs_rooted.json

trustlab summarize /tmp/atl_stock_vs_rooted.json
```

Expected interpretation: the diff should report changed trust-state dimensions from checked-in sample evidence. It is not a root-detection verdict, app-bypass result, or hardware-backed physical-device claim.

## Minimal Magisk collector packaging demo

Validate safety constraints and build the module archive:

```bash
python tools/package_magisk_module.py --output /tmp/androidtrustlab-magisk.zip
```

The packaging helper refuses common mutation payload locations such as `system/`, `vendor/`, `product/`, `system.prop`, `META-INF/`, and embedded zip files. That guardrail keeps the module framed as a read-only collector instead of a system modification bundle.

## What not to claim

Do not claim this release contains:

- an Android app
- a Gradle build
- instrumentation tests
- APK manifest or permission analysis
- Play Integrity, SafetyNet, Widevine, or DRM conclusions
- app-specific detection or evasion results
- physical-device boot-chain validation
- TEE or hardware attestation validation

The current release is a reproducible analyzer and collector lab with synthetic / AVD-limited samples. That is already useful.
