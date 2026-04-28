# Property Normalization

## Property groups

- boot: `ro.boot.*`
- build: `ro.build.*`
- product: `ro.product.*`
- crypto: `ro.crypto.*`
- adb/security: `ro.debuggable`, `ro.secure`, `ro.adb.secure`
- runtime: `sys.boot_completed`

## Missing values

Expected missing values are normalized as `unknown`.

## Unknown handling

Unknown is not failure. Unknown means the observer did not produce reliable evidence.

## Confidence rules

- emulator hardware-backed trust dimensions: low confidence
- direct property values from target: medium confidence
- physical-device values with bootloader/attestation provenance: high confidence, if later implemented

## Inconsistent properties

Inconsistency is recorded as an observation, not a bypass verdict.
