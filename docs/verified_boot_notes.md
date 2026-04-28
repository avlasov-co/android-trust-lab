# Verified Boot Notes

## Verified Boot chain

Android Verified Boot is intended to verify the integrity of boot and protected partitions before and during system startup. Android's modern AVB implementation uses vbmeta metadata and cryptographic verification of partition contents.

## AVB

AVB is Android Verified Boot 2.0. It provides tooling and metadata for verifying Android partitions.

## vbmeta

`vbmeta` stores verification metadata. Devices may use a top-level vbmeta image and chained descriptors for other partitions.

## dm-verity

`dm-verity` verifies block-device contents using a hash tree. In trust-state measurement, verity mode can affect whether protected partitions are expected to remain read-only and verified.

## Bootloader lock state

Bootloader lock state affects whether verified boot conclusions can be trusted. A locked bootloader and a verified boot state are materially different from an unlocked or unknown state.

## Verified boot states

Common property-level signals include values such as `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`, and `ro.boot.vbmeta.device_state`. Their presence and meaning vary by target and target class.

## Rollback indexes

Rollback indexes protect against loading older vulnerable images. This project notes their relevance but does not attempt hardware-backed rollback validation in the emulator MVP.

## Emulator evidence is limited

AVD data can test collection and parsing, but it cannot prove real OEM boot-chain behavior, TEE-backed attestation behavior, or hardware-backed verified boot correctness.

## References

- https://source.android.com/docs/security/features/verifiedboot/avb
- https://source.android.com/docs/security/features/verifiedboot/dm-verity
- https://android.googlesource.com/platform/external/avb/+/master/README.md
