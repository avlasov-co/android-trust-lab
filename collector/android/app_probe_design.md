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
