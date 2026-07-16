# Privileged Probe Design

## Purpose

Capture a privileged trust-state snapshot.

## Collects

- boot properties
- mounts
- SELinux
- Magisk state
- process state
- allowlisted boot-state evidence (the kernel command line is excluded)
- filesystem contexts

## Must not

- modify props
- patch SELinux
- mount overlays
- hide root
- spoof identity
- weaken policy

## Portable output

Privileged collectors emit the same strict
`collector/schema/collection_manifest_v1_0_0.schema.json` contract as every
other observer. The manifest uses a pseudonymous target and relative paths and
integrity-binds observed artifacts; partial or inaccessible probes must not be
reported as empty successes.

Validated `root_collector` manifest metadata selects the Magisk typed adapter
for its exact bound raw report. Inline capture imports may instead use
`artifact_collection_manifest_v1_0_0.schema.json` with `artifact_kind` set to
`magisk_collection_manifest`.
