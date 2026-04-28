# Magisk Collector Sample

This directory contains a synthetic root-side sample for `E05_magisk_collector`.

Files:

- `raw_sample.txt`: raw sectioned artifact shaped like output from the read-only Magisk collector.
- `collector_manifest_sample.json`: on-device manifest pointer. This is not a normalized trust report.
- `E05_magisk_collector__observer-root__sample.json`: normalized report generated from `raw_sample.txt`.

This sample validates analyzer behavior and report shape. It does not claim physical-device AVB, TEE, attestation, or OEM boot-chain behavior.
