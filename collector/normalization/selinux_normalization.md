# SELinux Normalization

SELinux mode is normalized to:

- enforcing
- permissive
- disabled
- unknown
- inaccessible

`getenforce` output is preferred when available. Process or filesystem contexts are additional evidence, not replacements for mode.
