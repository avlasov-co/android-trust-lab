# SELinux Normalization

SELinux evidence is normalized as separate observations for policy mode, the
observer's current context, denial-collection status, and source observer.
Policy mode values are:

- enforcing
- permissive
- disabled
- unavailable with an explicit status (`not_collected`, `inaccessible`,
  `command_error`, or `unsupported`)

`getenforce` output is the policy-mode source. `id -Z` or an equivalent
collector/app probe is the current-context source. Filesystem label rows are not
current-process evidence and are ignored. Portable contexts retain only the
Android process domain and sensitivity level (for example `u:r:shell:s0`);
per-app MLS/MCS categories are removed.

Denial evidence is not inferred from policy mode. The report records whether a
denial source was collected, inaccessible, unsupported, failed, or not
collected. An empty or missing denial source is never presented as proof that no
denial occurred. All observations retain relative source references when actual
evidence was parsed.
