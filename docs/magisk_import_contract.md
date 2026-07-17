# Magisk Import Contract

`trustlab import magisk --input PATH --output DIR` verifies and normalizes one
complete, already-local Magisk collection. The importer never invokes ADB,
`su`, Magisk, or any target command. Transfer from an owned or explicitly
authorized target is a separate operation.

## Accepted input

`PATH` names either an unpacked collection directory or that directory's exact
`collector_manifest.json`. Archives are not extracted. A ZIP, tar file, renamed
archive, or any other regular file is rejected before parsing.

The unpacked directory is a closed bundle. It may contain only:

- the root `collector_manifest.json`; and
- the regular files bound by observed manifest artifact entries.

The importer rejects undeclared files or directories, missing entries,
symlinks, hard links, special files, aliased files, path traversal, absolute or
nonportable paths, case-insensitive path collisions, duplicate logical names or
paths, excessive depth or entry counts, and more than 128 MiB of declared
artifact bytes. Each source file is opened beneath a held no-follow directory
descriptor, read once into an immutable bounded snapshot, and checked against
its declared byte size and SHA-256 digest. A changing file is an interrupted
import, not partial evidence.

## Required producer contract

The validated collection manifest must declare:

- collection-manifest schema `1.0.0`;
- collector `trustlab-magisk` with the root observer, Android platform, and
  on-device transport required by the shared schema;
- `completion_status: complete`;
- applied `atl_portable_v1` redaction with all three removal declarations true;
- one schema-valid status record for every declared probe;
- a semantic collector version in `collector.version`; and
- the independently required module version in
  `tool_versions.trustlab_magisk`.

The collector and module versions must match exactly. Major versions 0 and 1
belong to the current compatibility family, and the selected Magisk adapter
further limits accepted implementations to its explicit version registry
(`0.3.0`, `0.3.0-dev0`, and `1.0.0`). Unknown versions fail closed; an unknown
major is reported as an unsupported version.

Historical or diagnostic partial manifests remain readable through
`trustlab normalize --manifest ...`. They are never accepted by the default
import workflow. The pre-Step-29 module output is partial by design, so the
runtime hardening step must produce a complete manifest before its output can
pass this importer.

## Publication

The content address is `sha256-<digest>`, where `digest` is SHA-256 over ATL
Canonical JSON v1 serialization of the validated manifest. Because every
observed artifact is size/hash-bound by that manifest, the address covers the
verified collection without including its absolute source location.

The importer publishes this private tree beneath `DIR`:

```text
sha256-<64 lowercase hex>/
  collector_manifest.json
  <declared relative evidence paths>
  trust_report.json
```

Directories are mode `0700` and files are mode `0600` where POSIX modes apply.
A private lock serializes imports. Evidence and the validated normalized report
are written into a random same-filesystem staging directory, and the complete
tree is renamed into place only after every check passes. Existing content
addresses are never overwritten. Input and output trees may not overlap, and
no absolute source path is written into portable output.

Hashes establish internal integrity and deterministic identity; they do not
authenticate who produced a collection or prove hardware-backed device trust.
