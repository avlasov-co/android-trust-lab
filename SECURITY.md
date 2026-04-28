# Security Policy

Android Trust Lab is a controlled-lab research project for trust-state measurement.

## Supported use

Supported use is limited to:

- owned devices
- local Android Virtual Devices
- lab images
- explicitly authorized research targets
- reproducible security measurement
- read-only collection unless a documented experiment explicitly requires otherwise

## Not supported

This project does not support and will not accept requests, issues, pull requests, examples, or documentation for:

- Play Integrity bypass
- SafetyNet bypass
- root hiding
- Magisk hiding
- Zygisk hiding
- banking app bypass
- app-specific evasion logic
- DRM or Widevine bypass
- malware persistence
- stealth services
- remote exploitation
- SELinux weakening
- property spoofing for access to protected apps
- remount helpers for bypass purposes
- overlay patching for evasion

## Responsible disclosure

If you find a vulnerability in this repository, report it privately to the maintainer instead of publishing working exploit details in an issue.

Include:

- affected component
- reproduction steps
- expected impact
- safe proof of concept, if necessary
- suggested remediation

Do not include bypass playbooks or app-specific evasion recipes.
