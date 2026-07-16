# Report Schema v2

Report schema `2.0.0` is the current writer contract. Its canonical packaged
resource is `trust_report_v2_0_0.schema.json`; frozen `1.0.0` remains a read-only
input at `trust_report_v1_0_0.schema.json`. Both resources ship in wheels and
source distributions and are resolved locally by the exact compatibility
registry—never by a network or `latest` lookup.

## Strict shape

V2 uses Draft 2020-12 definitions for report and experiment IDs, timestamps,
SemVer, target and observer metadata, evidence status, confidence, mount
observations, command results, provenance, migrations, and limitations. Every
object is closed with `additionalProperties: false` except the explicit
`extensions` map. Extension keys must use reverse-DNS spelling and values must be
canonical-JSON-safe objects: floats are forbidden, integer values use the
interoperable range, and arrays and object fan-out are bounded.

Previously loose property, process, emulator, and mount structures are now
declared field by field. Mount `integrity_summary` is a required object containing
only `overlay_detected` and `writable_sensitive_mounts`. Arrays have item and size
constraints, identifiers and versions have patterns, and timestamps use the
project's strict RFC 3339 format checker.

## Evidence envelopes

Collected values use `{status, value, reason}` envelopes. The six statuses are
`observed`, `observed_absent`, `inaccessible`, `not_collected`, `command_error`,
and `unsupported`. An observed value has a `null` reason. Affirmative absence has
an empty/false value and a non-empty reason. Every other non-observation has a
`null` value and a non-empty reason. This prevents a literal `unknown` string from
silently collapsing absence, access denial, skipped collection, command failure,
and unsupported capability.

Raw property maps may still contain the literal text `unknown` when that exact
text was observed; the containing envelope records that the map itself was
observed. Confidence is independently constrained to `low`, `medium`, `high`, or
`unassessed`.

## V1 migration

`migrate_report_v1_to_v2` and `trustlab migrate-report` implement the sole
registered v1-to-v2 path:

1. require declared source version `1.0.0`;
2. validate the source against the frozen v1 schema;
3. deterministically map every known field into the strict v2 shape;
4. retain ambiguous `unknown`/missing values as `not_collected` with a reason
   instead of inventing a stronger state;
5. preserve the complete original report as deterministic JSON text plus its
   SHA-256 digest under the namespaced `org.androidtrustlab.migration` extension;
6. record source version, target version, migration ID, and normalizer version;
7. validate the complete migrated result against v2 before returning or writing.

Migration does not read the clock, network, environment, or filesystem identity,
and it never mutates or replaces the source. Re-running it over the same v1 JSON
produces byte-equivalent canonical JSON. Cross-version diffing invokes this exact
path and refuses unsupported inputs.
Diff provenance records each original report ID and schema version, the common
comparison version, and the exact migration chain applied to each input.

Fresh normalization uses the presence of raw command sections—including empty
sections—to distinguish a successful probe that found nothing from a probe that
was never recorded. A v1 negative or empty value without equivalent provenance
remains `not_collected`; migration never promotes it to affirmative absence or
access denial.

Generator-owned synthetic reports were deliberately regenerated as v2 from
their checked-in raw inputs. `tests/fixtures/report_v1_historical.json` remains
an immutable historical input, with independently hashed expectations under
`tests/golden/`.
