# Parser limits and malformed-input policy

Android Trust Lab treats collector artifacts as untrusted input. The parser
uses one bounded, deterministic policy for direct legacy text, typed JSON
artifacts, and raw payloads bound by portable collection manifests. These
limits protect analysis availability; they do not make any trust claim about
the target.

## Resource envelope

| Resource | Limit | Result when exceeded |
|---|---:|---|
| Exact input bytes | 8 MiB | Reject before parsing |
| One decoded source line | 256 KiB of UTF-8 | Reject with the line number |
| Section headers | 64 occurrences | Reject |
| Section name | 64 normalized characters | Reject with the header line |
| Lines in one section | 4,096 | Reject |
| Typed JSON container depth | 32 levels, including the root | Reject |
| Typed JSON nodes | 100,000 values, containers, and object member names | Reject |
| Retained parser warnings | 256 | Retain a terminal warning that more were omitted |

File inputs are read as a stable, regular-file, no-follow snapshot. A file
larger than the byte envelope is rejected before it is accumulated. Already
in-memory inputs are checked before section or JSON syntax work. The parser
does not silently truncate bytes, lines, sections, values, or JSON data.

## Text and decoding policy

Input must be strict UTF-8. A decode failure reports the failing byte offset;
an invalid in-memory Unicode scalar reports its character offset. NUL and
Unicode control characters other than tab and line separators are rejected
with line and column context.

LF is canonical. CRLF and bare CR are accepted for historical collector
compatibility, normalized while parsing, and recorded as an explicit warning.
The exact source-byte digest still binds the original line endings.

## Legacy section recovery

Legacy sectioned text cannot express per-command exit status, so its status is
explicitly marked as inferred. Recovery is limited and deterministic:

- repeated section headers are retained in capture order and concatenated;
- section names are ASCII and case-insensitive; malformed header-like lines are
  rejected so their following content cannot bleed into a trusted section;
- simultaneous historical aliases such as `GETPROP`/`PROPS` use the first
  populated canonical alias and emit a duplicate-or-conflict precedence
  warning;
- repeated property and boot-state keys use the last occurrence;
- a repeated key is diagnosed as duplicate or conflicting without copying its
  value into the warning;
- malformed property or boot-state entries are ignored with an aggregate
  warning, while independently valid entries remain usable;
- the literal string `unknown` remains an observed value and is never confused
  with parser uncertainty;
- shell and command failure text is never accepted as path evidence;
- an unrecognized section is not interpreted as evidence. Its bounded name,
  occurrence count, normalized byte size, and SHA-256 digest are retained in
  `org.androidtrustlab.adapter.unrecognized_sections`; the exact raw artifact
  reference remains the authoritative byte binding.

Malformed successful output is diagnosed and cannot manufacture evidence of
absence. Inaccessible, failed, timed-out, unsupported, and uncollected typed
captures retain their command-result status and never contribute stdout to
evidence fragments. A genuinely successful empty capture remains distinct
from every failure state. Where an old section has recognizable permission,
timeout, or command-error text, the legacy adapter records an explicitly
inferred `inaccessible`, `timeout`, or `command_error` command result instead
of calling the command successful. Historical Magisk and `su` negative
sentinels remain the narrowly documented observed-absence compatibility case.

## Typed JSON policy

Typed artifacts first pass the same byte, line, character, and warning limits,
then strict JSON decoding. Duplicate object members, non-standard constants,
decoder recursion, excessive nesting, excessive node count, schema violations,
and incoherent command outcomes fail closed. Artifact schemas additionally
bound capture counts and capture text fields.

The checked-in adversarial contract is exercised by
`tests/test_parser_limits.py`, `tests/test_adversarial_inputs.py`, and
`tests/test_artifact_adapters.py`.
