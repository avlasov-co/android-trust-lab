# Engineering Baseline

## Audited state

The Phase 1 engineering baseline was established on 2026-07-16 from commit
`d669712735334d6ea3d1f053e233c2713823d496` (`main`). The initial worktree had
no textual, untracked, or file-mode differences. Git and the filesystem agreed
on every executable bit: the release verifier, generator and packaging tools,
and all eleven Magisk shell scripts were executable; tracked data and documents
were not.

The audited history has tags `0.1.0` and `v0.1.1`. The following commit adds
v0.2.0 release-candidate notes but is not tagged. Phase 1 treats that version
state as a known metadata defect until Step 03 resolves it truthfully.

## Repository structure

| Path | Role |
|---|---|
| `analyzer/` | Python package and `trustlab` CLI |
| `collector/` | Collector designs, normalization rules, and JSON Schemas |
| `datasets/` | Synthetic raw fixtures and normalized sample reports |
| `experiments/` | Controlled experiment records and templates |
| `module/trustlab-magisk/` | Read-only privileged collector module |
| `results/` | Generated diffs, tables, and research views |
| `tests/` | Parser, normalizer, diff, schema, CLI, and package tests |
| `tools/` | Deterministic artifact generator and validation/package helpers |
| `scripts/` | Unified local verification entry point and compatibility wrapper |
| `.github/workflows/` | Hosted repository and documentation checks |

There is no Android application, Gradle project, instrumentation test suite, or
50-step roadmap file in this checkout. The unprivileged app probe is design-only.

## Supported development commands

Create an isolated environment and install the declared development dependencies:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e "analyzer[dev]"
```

Run the complete local gate from the repository root:

```bash
bash scripts/check.sh
```

`bash scripts/verify_release.sh` is a compatibility wrapper for the same gate.
Set `PYTHON_BIN=/path/to/python` when a specific interpreter is required. The
check compiles Python sources, runs tests with branch coverage, validates the
Draft 2020-12 schemas and all checked-in reports/diffs, checks generated-file
freshness, validates Magisk package safety, and checks shell syntax.

Focused commands are:

```bash
PYTHONPATH=analyzer python3 -m pytest -q
PYTHONPATH=analyzer python3 -m coverage run --branch --source=analyzer/trustlab -m pytest -q
python3 -m coverage report -m
PYTHONPATH=analyzer python3 tools/check_schemas.py
PYTHONPATH=analyzer python3 tools/generate_report.py --check
python3 tools/package_magisk_module.py --check-only
```

## Tests and coverage

The pre-change audit collected 21 tests and passed all 21. Its branch-aware
coverage result was 66% overall (373 statements, 118 missed, 104 branches, and
20 partial branches).

After adding the valid-path CLI smoke and schema-document regression test, the
unified Step 01 gate collects and passes 23 tests. The exact coverage result is
85% overall (373 statements, 37 missed, 104 branches, and 25 partial branches).
This is an observed baseline, not a Phase 1 coverage threshold.

## Generated-artifact workflow

`tools/generate_report.py` is the canonical generator for five normalized
sample reports, `datasets/manifest.json`, four result diffs, the sample diff
fixture, and three Markdown result views. Use `--check` in verification and CI;
run without `--check` only after intentionally changing a generator input.
Review every regenerated file before committing it.

`results/artifact_manifest.json` is not currently produced or freshness-checked
by that generator. Its stale validation/version fields are a named provenance
defect for the versioning work rather than evidence of a completed check.

## Evidence classifications

- **Synthetic evidence** is manually authored or deterministically generated to
  exercise the pipeline. Every checked-in sample is currently synthetic.
- **AVD-limited evidence** models or comes from an Android Virtual Device and
  cannot support physical boot-chain, TEE, hardware-attestation, OEM, or DRM
  claims. An AVD-shaped synthetic fixture is not thereby a captured artifact.
- **Captured evidence** is output directly acquired from an owned or explicitly
  authorized target with provenance. It must say whether that target was an AVD
  or physical device. No captured AVD or physical-device dataset is checked in
  at this baseline.

Raw logs and portable artifacts must exclude or redact serial numbers, account
names, host paths, command lines, network addresses, and device metadata that
can identify a person or environment.

## Named baseline defects

1. **Canonical metadata drift (Step 02):** active citation and schema identifiers
   use a retired repository slug.
2. **Version drift (Step 03):** package, citation, Magisk module, release notes,
   and artifact metadata disagree; v0.2.0 has no Git tag.
3. **Repository-relative schema loading (Phase 2 Step 06):** installed analyzer
   validation depends on finding `collector/schema` in a source checkout.
4. **Fail-open dependency fallback (Phase 2 Step 07):** validation falls back to
   checking only top-level required keys when `jsonschema` is unavailable.
5. **App observer mapping (Step 04):** `unprivileged_app` normalizes to an invalid
   privilege value instead of `app_sandbox`.
6. **Validation/write ordering (Step 05):** normalize and diff write requested
   outputs before validation; diff does not validate its inputs.
7. **CLI failure contract (Step 05):** expected malformed-input and filesystem
   errors currently escape as tracebacks without stable project exit codes.

## Subsequent resolution notes

Phase 2 Step 06 resolves baseline defect 3: schemas are packaged as canonical
`importlib.resources`, wheel and sdist contents are tested, and compatibility
copies cannot drift without failing verification.

Phase 2 Step 07 resolves baseline defect 4: `jsonschema` is a mandatory runtime
dependency, Draft 2020-12 schemas are meta-validated, formats are enforced, and
all validation failures are reported deterministically.

Phase 2 Step 08 establishes Python 3.11 as the minimum and tests the complete
3.11, 3.12, 3.13, and 3.14 support matrix in CI. A consistency checker binds
package metadata, classifiers, documentation, and the workflow matrix.

These defects are recorded here rather than encoded as expected Step 01
behavior. The Step 01 product path remains unchanged apart from a valid CLI
smoke test.
