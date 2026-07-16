# Overview

Android Trust Lab is a reproducible research framework for measuring Android trust-state transitions across controlled configurations.

## Goal

The goal is to observe how trust-related signals change when a target moves between known states: stock AVD, rooted AVD, writable-system AVD, modified safe-property experiment, optional privileged collector, and future physical-device validation.

## Research question

How do Android trust-state signals change across controlled system transitions, and how does the observer privilege level affect what can be seen?

## Core statement

Android trust state is distributed across boot, kernel, SELinux, mounts, properties, userspace, and app-visible APIs.

## Architecture summary

Collectors describe raw artifacts with strict portable collection manifests.
The analyzer verifies the relative path, size, and SHA-256 binding, parses the
raw evidence, normalizes it into strict report schema v2, and compares compatible
reports into `trust_diff.schema.json`. Frozen v1 reports remain readable and have
an explicit v1-to-v2 migration; legacy raw files can still be normalized
directly.

## Expected outputs

- normalized JSON reports
- trust-state diffs
- experiment matrix
- dataset samples
- results tables
- methodology documentation
- limitations documentation
- paper-style writeup

## Maturity level

MVP research harness. The virtual-target pipeline is implemented first. Physical-device conclusions are not claimed until physical artifacts exist.
