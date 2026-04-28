# Mount Normalization

Mounts are converted into structured state.

## Classes

- read-only
- read-write
- overlay
- tmpfs
- bind mount
- sensitive writable mount
- unknown

## Sensitive paths

- `/system`
- `/vendor`
- `/product`
- `/system_ext`
- `/odm`
- `/apex`

A sensitive writable mount is recorded in `writable_sensitive_mounts`.
