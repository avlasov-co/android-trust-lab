# Privileged Probe Design

## Purpose

Capture a privileged trust-state snapshot.

## Collects

- boot properties
- mounts
- SELinux
- Magisk state
- process state
- kernel command line
- filesystem contexts

## Must not

- modify props
- patch SELinux
- mount overlays
- hide root
- spoof identity
- weaken policy
