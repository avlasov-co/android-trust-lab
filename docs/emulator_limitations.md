# Emulator Limitations

This document is intentionally blunt because fake confidence is how bad research gets dressed up and sent outside.

## Valid on emulator

Emulator and AVD experiments are valid for:

- collector development
- schema design
- analyzer testing
- report normalization
- diff generation
- controlled virtual experiments
- CI-friendly samples

## Not valid on emulator

Emulator and AVD experiments are not valid for proving:

- real OEM bootloader behavior
- Xiaomi/Qualcomm boot chain behavior
- hardware-backed AVB conclusions
- TEE behavior
- hardware attestation correctness
- Widevine/DRM conclusions
- vendor/HAL mismatch validation
- Goodix/FOD validation
- Mi 9-specific conclusions

## Required interpretation

This version validates the collection and analysis pipeline on virtual targets. Hardware-backed trust behavior requires physical-device validation.
