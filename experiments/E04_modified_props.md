# E04 Modified Properties

## Purpose

Test whether the analyzer detects property inconsistencies.

## Target

Controlled virtual target or synthetic raw artifact.

## Preconditions

- Baseline report exists.
- Property modifications are safe and local.

## Controlled change

Use synthetic/local properties or clearly safe test values.

## Expected signals

- property consistency dimension may change
- raw properties include changed keys
- analyzer flags inconsistency without making a bypass verdict

## Collection procedure

1. Prepare safe property test case.
2. Collect or generate raw artifact.
3. Normalize report.
4. Diff against baseline.

## Artifacts produced

Planned for a later release.

## Actual result

No sample artifact is included in v0.1.0.

## Diff summary

Not generated in v0.1.0.

## Limitations

This experiment is intentionally deferred to avoid introducing property-spoofing examples before the measurement scope is fully constrained.

## Status

Planned. Not included in the v0.1.0 sample dataset.
