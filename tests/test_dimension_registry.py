from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from trustlab.dimension_registry import (
    CANONICAL_EVIDENCE_STATUSES,
    COMPARATOR_LOOKUP,
    CONTEXTUAL_DIMENSION_DEFINITIONS,
    DEFAULT_DIMENSIONS,
    EXTRACTOR_LOOKUP,
    TRUST_DIMENSION_DEFINITIONS,
    TRUST_DIMENSIONS_BY_ID,
    TrustDimensionRegistryError,
    comparison_value,
    dimension_definition,
    dimensions_equal,
    extract_dimension,
    validate_registry_document,
)
from trustlab.trust_dimensions import materiality_for_dimension
from trustlab.validators import load_schema

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "analyzer/trustlab/registry/trust_dimensions_v1_0_0.json"
SCHEMA_NAME = "trust_dimension_registry_v1_0_0.schema.json"

EXPECTED_ORDER = (
    "bootloader_lock_state",
    "verified_boot_state",
    "vbmeta_state",
    "verity_mode",
    "selinux_mode",
    "selinux_current_context",
    "selinux_denial_collection",
    "selected_process_visibility",
    "mount_integrity",
    "system_mount_resolution",
    "dynamic_partition_state",
    "apex_mount_set",
    "root_shell_availability",
    "su_binary_visibility",
    "su_invocation_tested",
    "su_invocation_result",
    "root_management_artifact",
    "magisk_binary_visibility",
    "magisk_daemon_visibility",
    "magisk_process_visibility",
    "zygisk_visibility",
    "magisk_version_name",
    "magisk_version_code",
    "magisk_module_context",
    "magisk_command_status",
    "property_consistency",
    "emulator_state",
    "app_visible_state",
    "physical_device_state",
    "root_visible_state",
)


def registry_document() -> dict[str, object]:
    value = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def sample_report() -> dict[str, object]:
    value = json.loads(
        (ROOT / "tests/fixtures/sample_normalized_report.json").read_text(
            encoding="utf-8"
        )
    )
    assert isinstance(value, dict)
    return value


def test_registry_is_schema_valid_and_has_exact_canonical_order():
    definitions = validate_registry_document(registry_document())

    assert definitions == TRUST_DIMENSION_DEFINITIONS
    assert tuple(definition.id for definition in definitions) == EXPECTED_ORDER
    assert (
        tuple(definition.id for definition in DEFAULT_DIMENSIONS) == EXPECTED_ORDER[:28]
    )
    assert (
        tuple(definition.id for definition in CONTEXTUAL_DIMENSION_DEFINITIONS)
        == EXPECTED_ORDER[28:]
    )
    assert tuple(TRUST_DIMENSIONS_BY_ID) == EXPECTED_ORDER


def test_registry_schema_closes_objects_and_allowlists_executable_policy_ids():
    schema = load_schema(SCHEMA_NAME)
    assert schema["additionalProperties"] is False
    for definition in schema["$defs"].values():
        if isinstance(definition, dict) and definition.get("type") == "object":
            assert definition["additionalProperties"] is False

    properties = schema["$defs"]["dimension"]["properties"]
    assert properties["extractor_id"]["enum"] == [
        "nested_path_v1",
        "app_probe_extension_v1",
        "contextual_unavailable_v1",
    ]
    assert properties["comparator_id"]["enum"] == [
        "canonical_equality_v1",
        "contextual_unavailable_v1",
    ]
    assert "expression" not in properties
    assert "import_path" not in properties


def test_registry_definitions_and_lookup_tables_are_immutable():
    with pytest.raises(FrozenInstanceError):
        TRUST_DIMENSION_DEFINITIONS[0].title = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        TRUST_DIMENSIONS_BY_ID["new"] = TRUST_DIMENSION_DEFINITIONS[0]  # type: ignore[index]
    with pytest.raises(TypeError):
        EXTRACTOR_LOOKUP["new"] = EXTRACTOR_LOOKUP["nested_path_v1"]  # type: ignore[index]
    with pytest.raises(TypeError):
        COMPARATOR_LOOKUP["new"] = COMPARATOR_LOOKUP["canonical_equality_v1"]  # type: ignore[index]


def test_all_safe_extractors_and_comparators_are_referenced():
    assert {
        definition.extractor_id for definition in TRUST_DIMENSION_DEFINITIONS
    } == set(EXTRACTOR_LOOKUP)
    assert {
        definition.comparator_id for definition in TRUST_DIMENSION_DEFINITIONS
    } == set(COMPARATOR_LOOKUP)


def test_every_measured_dimension_extracts_its_unique_report_path():
    report = sample_report()
    paths = [definition.evidence_paths[0] for definition in DEFAULT_DIMENSIONS]
    assert len(paths) == len(set(paths)) == 28

    for definition in DEFAULT_DIMENSIONS:
        if definition.id == "app_visible_state":
            assert extract_dimension(report, definition) == {
                "status": "not_collected",
                "value": None,
                "reason": "direct supporting payload is not available",
                "evidence_refs": [],
            }
            continue
        current: object = report
        for part in definition.evidence_paths[0].split("."):
            assert isinstance(current, dict)
            assert part in current
            current = current[part]
        assert extract_dimension(report, definition) == current
        assert dimensions_equal(definition, current, deepcopy(current))


def test_canonical_comparator_ignores_reason_and_evidence_reference_noise():
    dimension = dimension_definition("root_shell_availability")
    before = {
        "status": "observed",
        "value": True,
        "reason": "before wording",
        "evidence_refs": ["artifact:before"],
    }
    after = {
        "status": "observed",
        "value": True,
        "reason": "after wording",
        "evidence_refs": ["artifact:after"],
    }

    assert dimensions_equal(dimension, before, after)
    after["value"] = False
    assert not dimensions_equal(dimension, before, after)


def test_canonical_comparator_recursively_excludes_nested_evidence_references():
    before = {
        "status": "observed",
        "value": {
            "probes": [
                {
                    "probe_id": "example",
                    "status": "observed",
                    "value": True,
                    "reason": None,
                    "evidence_refs": ["captures/before.txt"],
                }
            ]
        },
        "reason": None,
        "evidence_refs": ["captures/outer-before.txt"],
    }
    after = deepcopy(before)
    after["value"]["probes"][0]["evidence_refs"] = ["captures/after.txt"]
    after["evidence_refs"] = ["captures/outer-after.txt"]

    assert comparison_value(before) == {
        "status": "observed",
        "value": {
            "probes": [{"probe_id": "example", "status": "observed", "value": True}]
        },
    }
    assert dimensions_equal("app_visible_state", before, after)


def test_contextual_dimensions_return_and_require_canonical_sentinel():
    report = sample_report()
    for definition in CONTEXTUAL_DIMENSION_DEFINITIONS:
        sentinel = extract_dimension(report, definition)
        assert sentinel == {
            "status": "not_collected",
            "value": None,
            "reason": "direct supporting payload is not available",
            "evidence_refs": [],
        }
        assert dimensions_equal(definition, sentinel, deepcopy(sentinel))
        altered = deepcopy(sentinel)
        altered["reason"] = "different"
        with pytest.raises(TrustDimensionRegistryError, match="canonical"):
            dimensions_equal(definition, sentinel, altered)


def test_missing_nested_report_path_preserves_unknown_compatibility_value():
    assert extract_dimension({}, "bootloader_lock_state") == "unknown"


def test_unknown_or_noncanonical_dimension_fails_closed():
    with pytest.raises(TrustDimensionRegistryError, match="unknown trust dimension"):
        dimension_definition("not_registered")
    altered = deepcopy(dimension_definition("bootloader_lock_state"))
    object.__setattr__(altered, "title", "altered")
    with pytest.raises(TrustDimensionRegistryError, match="not the canonical"):
        dimension_definition(altered)


def test_registry_supports_only_current_report_version_and_canonical_statuses():
    for definition in DEFAULT_DIMENSIONS:
        assert definition.supported_report_versions == ("6.0.0",)
        assert definition.expected_statuses == CANONICAL_EVIDENCE_STATUSES
    for definition in CONTEXTUAL_DIMENSION_DEFINITIONS:
        assert definition.supported_report_versions == ("6.0.0",)
        assert definition.expected_statuses == ("not_collected",)


def test_materiality_compatibility_keeps_legacy_observer_dimensions_outside_registry():
    assert "observer_uid_root" not in TRUST_DIMENSIONS_BY_ID
    assert "observer_privilege" not in TRUST_DIMENSIONS_BY_ID
    assert materiality_for_dimension("observer_uid_root") == "moderate"
    assert materiality_for_dimension("observer_privilege") == "informational"
    assert materiality_for_dimension("unknown_historical_dimension") == "low"


def test_matrix_order_is_unique_contiguous_and_preserves_current_dimensions():
    matrix = sorted(
        (
            definition.renderer_hints.matrix_order,
            definition.id,
        )
        for definition in TRUST_DIMENSION_DEFINITIONS
        if definition.renderer_hints.matrix_order is not None
    )
    assert matrix == [
        (1, "bootloader_lock_state"),
        (2, "verified_boot_state"),
        (3, "vbmeta_state"),
        (4, "verity_mode"),
        (5, "selinux_mode"),
        (6, "mount_integrity"),
        (7, "root_shell_availability"),
        (8, "magisk_binary_visibility"),
        (9, "property_consistency"),
    ]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda document: document["dimensions"][1].update(
                id=document["dimensions"][0]["id"]
            ),
            "IDs must be unique",
        ),
        (
            lambda document: document["dimensions"][1].update(
                evidence_paths=document["dimensions"][0]["evidence_paths"]
            ),
            "evidence paths must be unique",
        ),
        (
            lambda document: document["dimensions"][0].update(
                supported_report_versions=["5.0.0"]
            ),
            "must support only current report version",
        ),
        (
            lambda document: document["dimensions"][28].update(
                evidence_paths=["target.observer_type"]
            ),
            "cannot fabricate an evidence path",
        ),
        (
            lambda document: document["dimensions"][1]["renderer_hints"].update(
                matrix_order=1
            ),
            "matrix renderer order must be unique",
        ),
    ],
)
def test_registry_semantic_validation_rejects_contract_drift(mutate, message):
    document = registry_document()
    mutate(document)
    with pytest.raises(TrustDimensionRegistryError, match=message):
        validate_registry_document(document)


@pytest.mark.parametrize(
    "field",
    ["extractor_id", "comparator_id"],
)
def test_registry_schema_rejects_arbitrary_behavior_identifiers(field):
    document = registry_document()
    document["dimensions"][0][field] = "module.function"
    with pytest.raises(TrustDimensionRegistryError, match="schema validation"):
        validate_registry_document(document)


def test_registry_schema_rejects_undeclared_executable_expression():
    document = registry_document()
    document["dimensions"][0]["expression"] = "__import__('os').system('id')"
    with pytest.raises(TrustDimensionRegistryError, match="schema validation"):
        validate_registry_document(document)
