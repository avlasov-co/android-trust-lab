# Android Trust Lab: Measuring Android Trust-State Transitions Across Controlled System Configurations

## Abstract

Android trust state is often treated as a single device verdict, but practical trust evidence is distributed across boot properties, verified boot metadata, SELinux state, mount layout, root visibility, process visibility, app-visible APIs, and observer privilege boundaries. Android Trust Lab is a reproducible research harness that collects, normalizes, validates, and compares trust-state reports across controlled Android target configurations.

## Introduction

This project studies how trust-state signals change when a target moves between controlled states such as stock AVD, rooted AVD, writable-system AVD, safe modified-property experiments, optional privileged collection, and future physical-device validation.

## Background

Android platform integrity involves multiple layers, including boot verification, dm-verity, SELinux policy enforcement, mount configuration, system properties, process state, and app-visible APIs. No single observer sees all layers equally.

## Methodology

Experiments define a target, preconditions, controlled change, expected state, collection procedure, artifacts, actual state, diff summary, limitations, and status. Reports are normalized into JSON Schema and compared with a schema-defined diff format.

## System Design

The system has four observer categories: host, adb shell, unprivileged app, and root collector. Each observer has different visibility. The analyzer preserves this distinction instead of flattening evidence into one verdict.

## Experiments

Initial experiments target AVD-based configurations:

- E01 stock AVD
- E02 rooted AVD
- E03 writable-system AVD
- E04 safe property modification
- E05 Magisk collector
- E99 future physical-device template

## Results

The v0.1.0 sample dataset includes four generated comparisons:

- stock AVD adb observer to rooted AVD adb observer
- rooted AVD adb observer to rooted AVD root observer
- stock AVD adb observer to writable-system AVD adb observer
- rooted AVD adb observer to Magisk root collector

The generated diffs show that the analyzer separates target-state changes from observer-privilege changes. In the stock-to-rooted adb comparison, the changed trust dimension is `root_presence`. In the rooted adb-to-root observer comparison, the changed dimension is `observer_privilege`, preserving the distinction between target mutation and visibility boundary.

The writable-system comparison records mount-integrity changes, including overlay-backed or writable sensitive mount evidence. The Magisk comparison records privileged collector visibility without treating Magisk presence as a bypass, hiding mechanism, or application verdict.

All v0.1.0 results are synthetic or AVD-limited. They validate the collection, normalization, diffing, and reporting pipeline. They do not claim hardware-backed boot-chain behavior, TEE behavior, OEM bootloader behavior, or physical-device attestation correctness.

## Limitations

AVD experiments validate the collection and analysis pipeline but cannot prove OEM bootloader behavior, Qualcomm/Xiaomi boot-chain behavior, TEE correctness, Widevine/DRM conclusions, vendor/HAL mismatch behavior, Goodix/FOD behavior, or Mi 9-specific conclusions.

## Relation to Existing Tools

DuckDetector is a detector-style Android inspection app. Android Trust Lab is a transition-measurement harness. Both may observe similar signals, but they answer different questions.

## Safety Scope

This repository rejects bypass, hiding, evasion, persistence, SELinux weakening, DRM bypass, and app-specific attack logic.

## Future Work

- physical-device validation
- app probe implementation
- richer provenance capture
- report visualization
- Cuttlefish experiments
- longitudinal trust-state datasets

## References

- Android Verified Boot: https://source.android.com/docs/security/features/verifiedboot/avb
- dm-verity: https://source.android.com/docs/security/features/verifiedboot/dm-verity
- Android SELinux: https://source.android.com/docs/security/features/selinux
- Magisk developer guide: https://topjohnwu.github.io/Magisk/guides.html
