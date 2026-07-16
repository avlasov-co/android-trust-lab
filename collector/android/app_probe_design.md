# App Probe Design

The unprivileged app probe is optional.

## Purpose

Capture what a normal Android app can see.

## Measures

- Android API-visible Build values
- limited filesystem visibility
- package/environment info
- emulator indicators visible to app
- SELinux context if accessible

## Must not

- make root-detection verdicts
- bypass checks
- provide app-specific evasion logic
- attempt stealth

## Portable output

The future app implementation must emit strict
`collector/schema/app_probe_v1_0_0.schema.json` JSON with artifact kind
`app_probe_json` and observer type `unprivileged_app`. Unsupported APIs, access
denials, command errors, timeouts, and skipped probes remain separate outcomes.
The artifact contains no package credentials, account data, device serial, or
absolute path. If a later collector publishes portable bundle provenance, it
must additionally use `collection_manifest_v1_0_0.schema.json`; the contracts
serve different purposes and must agree on observer and event metadata.
