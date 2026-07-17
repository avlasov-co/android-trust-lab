# Deterministic Magisk Module Packaging

Use the checked-in helper from the repository root:

```bash
python tools/package_magisk_module.py --check-only
python tools/package_magisk_module.py --output dist/androidtrustlab-magisk.zip
```

`--check-only` still performs two complete temporary builds and compares their
exact bytes. A normal build publishes only after the same comparison succeeds
and prints the final SHA-256 digest.

## Canonical archive contract

The payload is a closed allowlist: `README.md`, `module.prop`, `skip_mount`, the
four root entrypoint scripts, and the eight scripts beneath `scripts/`. No other
directory or file is accepted. Entries are sorted by canonical POSIX relative
path. Every script is archived as a Unix regular file with mode `0755`; the
three non-scripts use `0644`. Checkout modes and source mtimes are ignored.

The timestamp is UTC `SOURCE_DATE_EPOCH`, rounded down to ZIP's two-second
precision. It must resolve to 1980–2107. When the variable is absent, the
canonical ZIP-safe default is `315532800` (`1980-01-01T00:00:00Z`). Entries use
explicit `ZIP_STORED` compression metadata, empty comments and extra fields,
and Unix creator metadata. Storing this small payload avoids compressor-version
byte drift.

The inventory rejects symlinks, FIFOs, sockets, devices, other special files,
absolute or traversing names, backslashes, drive/UNC paths, duplicate normalized
paths, unexpected payloads, embedded archives, excessive paths/counts, files
over 2 MiB, and total payloads over 4 MiB. Safe bounded reads recheck file
identity so a swapped symlink or changed file fails the build.

Package-time validation also requires the exact `module.prop` fields, the
`#!/system/bin/sh` shebang, successful host `sh -n` parsing for every script,
and an empty regular `skip_mount` file.

## Scope of the guardrails

These deterministic structural packaging guardrails prove payload membership,
paths, filesystem types, size limits, normalized ZIP metadata and modes,
metadata shape, shebangs, host-shell parseability, and selected static boundary
markers. They do not prove shell-script runtime semantics, producer identity,
device behavior, or that an installed module is behaviorally safe. Runtime
behavior remains subject to source review and the dedicated collector tests.

There is intentionally no generic `zip -r` fallback: it would not preserve the
canonical modes, timestamps, metadata, inventory validation, or two-build
comparison.
