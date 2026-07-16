# Versioning Policy

## Development version

The Python analyzer package is currently `0.3.0.dev0`. The sole Python source is
`analyzer/trustlab/_version.py`; `trustlab.__version__` re-exports it and
setuptools reads it dynamically for wheel and source-distribution metadata.

Human-facing metadata that cannot or conventionally does not use the exact PEP
440 spelling may use the equivalent `0.3.0-dev0`. The consistency checker parses
all project-version surfaces with `packaging.version.Version` instead of
comparing raw strings.

The Magisk `versionCode` uses `major * 10000 + minor * 100 + patch`, ignoring the
development suffix. Thus `0.3.0.dev0` has version code `300`. The code remains
monotonic relative to the earlier checked-in value.

## Independent schema versions

Project/package versioning does not govern data-contract compatibility. These
versions remain independent and must not be synchronized mechanically:

| Contract | Current version source | Current value |
|---|---|---|
| Trust report schema | `normalizer.py` and report schema | `1.0.0` |
| Trust diff schema | `diff.py` and diff schema | `1.0.0` |
| Dataset manifest | report generator | `1.0.0` |
| Collection manifest | Magisk collector writer | `collection-manifest-0.1` |

Future schema compatibility policy belongs in its own architecture decision and
must not be inferred from an analyzer package release.

## Release history

Git tags are the authority for completed repository releases. The repository has
tags `0.1.0` and `v0.1.1`. `RELEASE_NOTES_v0.2.0.md` is explicitly an untagged
release candidate: no tag, date, archive, or published release is invented.

Run `python tools/check_version_consistency.py` (or `bash scripts/check.sh`) after
changing any version surface. Run `python tools/generate_report.py` to update the
generated artifact manifest; never edit that derived manifest by hand.
