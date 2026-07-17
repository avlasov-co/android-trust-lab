# Trust Dimension Registry Design

Step 25 moves trust-dimension metadata into one validated, versioned registry
without changing the current report or diff wire formats.

## Interface and file layout

- `analyzer/trustlab/registry/trust_dimensions_v1_0_0.json` is the canonical
  ordered registry data.
- `analyzer/trustlab/schemas/trust_dimension_registry_v1_0_0.schema.json` is
  the packaged canonical JSON Schema. An identical compatibility copy lives at
  `collector/schema/trust_dimension_registry_v1_0_0.schema.json`.
- `analyzer/trustlab/dimension_registry.py` loads and validates the registry at
  import/build time and exposes immutable typed definitions, ID lookup, default
  and contextual sequences, extraction, and comparison.
- `analyzer/trustlab/dimension_rendering.py` owns the named renderer lookup,
  registry-derived matrix ordering, report-value rendering, and generated
  registry-document rendering.
- `analyzer/trustlab/registry/__init__.py` marks the packaged data namespace.
- `docs/trust_dimension_registry.md` is generated from the registry and checked
  for freshness with the other canonical artifacts.

The public Python contract exposes `TrustDimension`,
`TRUST_DIMENSION_DEFINITIONS`, `TRUST_DIMENSIONS_BY_ID`, `DEFAULT_DIMENSIONS`,
`CONTEXTUAL_DIMENSION_DEFINITIONS`, `dimension_definition()`,
`extract_dimension()`, and `dimensions_equal()`. The consumer-side rendering
contract exposes `MATRIX_DIMENSIONS`, `render_dimension()`, and
`registry_markdown()` from `dimension_rendering.py`.

## Schema contract

Every registry entry has a stable dimension ID, title, description,
interpretation, category, supported report versions, extractor ID, comparator
ID, expected evidence statuses, fixed materiality policy, direction-rule ID,
factorized confidence policy, evidence paths, renderer hints, contextual flag,
and default-enable flag. The JSON Schema closes every object and allowlists all
function and policy IDs; registry data cannot contain executable expressions.

Semantic validation additionally requires unique IDs and evidence paths,
current report-version support, one evidence path for each enabled measured
dimension, no evidence path for a disabled contextual dimension, canonical
status sets, contiguous unique matrix order, and complete references to every
public extractor and comparator ID. Renderer IDs are closed by the schema and
must all resolve when the consumer-side renderer lookup is imported. Registry
array order is the canonical deterministic diff and documentation order.

## Comparator lookup contract

Registry entries select functions through exact string IDs in immutable Python
lookup maps. `nested_path_v1`, `app_probe_extension_v1`, and
`contextual_unavailable_v1` are the only extractors.
`app_probe_extension_v1` reads only the validated
`org.androidtrustlab.app-probe` extension and otherwise returns the canonical
not-collected sentinel. `canonical_equality_v1` compares status/value evidence while
excluding evidence-reference noise; `contextual_unavailable_v1` accepts only
the canonical not-collected contextual sentinel. No `eval`, import path, query
language, lambda, or registry-supplied expression is permitted.

Direction and rendering policies follow the same closed-ID pattern. A missing
or unknown identifier fails closed during core or consumer initialization.

## Compatibility behavior

The registry was introduced against report `6.0.0` and diff `2.7.0` without a
wire-schema bump. Current diff `2.8.0` consumes the same registry contract while
allowing its registered hyphenated extension evidence path. The first 27
measured dimensions preserve their existing paths, order, materiality,
direction, confidence, and interpretation. Step 32 activates
`app_visible_state` as the twenty-eighth measured dimension only when a
validated typed app-probe extension exists. `physical_device_state` and
`root_visible_state` remain documented contextual dimensions with no fabricated
path and are not diffed until direct report payloads exist.

Historical diff versions remain readable. Their legacy observer-only dimension
metadata and frozen severity spellings stay in compatibility validation code;
they are not promoted into the current registry. Current diff validation must
reject any undocumented current dimension.

## Ownership boundaries

Writer A owns only registry data, its JSON Schema and compatibility copy,
packaging needed for those resources, registry loading/semantic validation,
safe typed extractor/comparator lookup, and registry-specific tests.

Writer B owns only registry-backed renderers, matrix/summary consumers,
generated dimension documentation, generator changes, and consumer-specific
tests and fixtures. Writer B must consume Writer A's committed interface without
altering its schema or comparator semantics.

The root agent owns this contract, diff-engine integration, direction and
confidence compatibility, historical validation, metadata and repository gate
wiring, integration conflict resolution, the single canonical regeneration,
reviewer findings, and the final Step 25 commit.
