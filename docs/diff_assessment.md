# Diff Materiality, Direction, and Confidence

Current diff schema `2.7.0` separates three questions that vulnerability-style severity previously conflated:

- `materiality` describes how important a dimension is to interpreting the experiment: `informational`, `low`, `moderate`, or `high`.
- `direction` describes a justified transition: `improvement`, `regression`, `context_change`, `visibility_change`, or `indeterminate`.
- `confidence` describes support for that one comparison from evidence status, field confidence, corroboration, migration history, and comparability warnings.

Direction is emitted only for registered ordered semantics such as enforced versus disabled SELinux state, locked versus unlocked verified-boot evidence, or absent versus present writable-sensitive-mount evidence. Reversing such a comparison inverts improvement and regression. Root or Magisk visibility has no universal direction and remains indeterminate. Observer or target-context changes remain context changes, and inaccessible evidence remains a visibility change.

Confidence is a factorized assessment, not target trust. Its machine-readable factors retain both evidence statuses, any field confidence, corroborating evidence count, migration count, comparability, and warning count. Canonical rationale codes make each reduction reviewable.

Android Trust Lab does not add, average, or otherwise aggregate dimension assessments into a universal trust score. Materiality is not vulnerability severity, and confidence is not device integrity.
