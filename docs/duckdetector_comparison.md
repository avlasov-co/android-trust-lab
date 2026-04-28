# DuckDetector Comparison

## What DuckDetector does

DuckDetector is a detector application focused on device-side inspection and evidence of suspicious state such as root-related tampering, runtime hooking, mount manipulation, attestation trust, and virtualized execution environments.

## What Android Trust Lab does

Android Trust Lab is a research harness for controlled trust-state transitions. It produces normalized reports, diffs those reports, stores experiment samples, and documents methodology and limitations.

## Core distinction

DuckDetector answers:

> What evidence of tampering exists on this device?

Android Trust Lab answers:

> How do trust-state signals change across controlled system transitions?

## Overlap

Both projects may observe root, mounts, properties, Magisk-related signals, or virtualized environments.

## Differences

| Area | DuckDetector | Android Trust Lab |
|---|---|---|
| Primary form | detector application | research harness |
| Main output | cards/verdict-like evidence | normalized reports and diffs |
| Focus | current device suspicious state | controlled state transitions |
| Dataset | not the main artifact | explicit experiment samples |
| Methodology | detector logic | reproducible experiment docs |
| Goal | inspection | measurement |

## Why both can coexist

A detector is useful for local inspection. A transition harness is useful for studying how signals change between known states. These are distinct use cases and should be evaluated separately.

## Why this project is not a detector app

Android Trust Lab does not issue app-facing bypass advice, does not optimize for hiding, and does not reduce trust state to a single pass/fail verdict.
