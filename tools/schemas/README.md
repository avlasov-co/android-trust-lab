# Validation Schemas

`cff-1.2.0.schema.json` is the CFF 1.2.0 JSON Schema identified by its `$id`,
`https://citation-file-format.github.io/1.2.0/schema.json`. It is vendored so
metadata validation remains deterministic and offline. The copy was sourced
from `citation-file-format/cff-converter-python` 2.0.0, whose independent
`cffconvert --validate` result is also used when auditing metadata changes.

Update this file only when the repository deliberately adopts a new CFF schema
version, and verify the source and `$id` during review.
