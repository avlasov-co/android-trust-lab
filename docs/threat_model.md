# Threat Model

This threat model is for measurement integrity, not attack.

## What is measured

The project measures Android trust-state signals across controlled experiment states.

## Supported observer IDs

- `host`
- `adb_shell`
- `unprivileged_app`
- `root_collector`

Boot/kernel-level evidence is a signal source when available. It is not a
standalone observer ID in the current report schema or analyzer registry.

## Observer access

| Observer | Can access | Cannot prove |
|---|---|---|
| `host` | adb version, emulator metadata, artifact provenance | internal target state by itself |
| `adb_shell` | shell-visible props, mounts, SELinux mode, uid/gid | app-only view or hardware attestation correctness |
| `unprivileged_app` | sandbox-visible Build/API/environment values | root-only state |
| `root_collector` | privileged props, mounts, process/context state | hardware-backed boot guarantees by itself |

## Inconsistency sources

- property spoofing or divergence
- mount namespace differences
- incomplete or fallback mount sources that omit topology
- system-as-root and stacked mounts misread as legacy `/system` layouts
- SELinux context visibility differences
- emulator behavior
- vendor-specific behavior
- incomplete permissions
- timing during boot
- observer-induced state changes

## Assets

- trust-state accuracy
- measurement reproducibility
- experiment integrity
- report provenance

## Out of scope

- bypassing app checks
- stealth
- malware persistence
- remote exploitation
- DRM bypass
- Play Integrity or SafetyNet bypass
