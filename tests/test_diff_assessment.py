from __future__ import annotations

import copy
from pathlib import Path

import pytest

from trustlab.canonical_json import framed_content_digest
from trustlab.comparison import attach_comparison_context
from trustlab.diff import make_diff
from trustlab.exceptions import SchemaValidationError
from trustlab.report_writer import load_json
from trustlab.validators import validate_diff

ROOT = Path(__file__).resolve().parents[1]
STOCK = ROOT / "datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json"
ROOTED_ADB = (
    ROOT / "datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json"
)
MAGISK_ROOT = (
    ROOT
    / "datasets/samples/magisk_collector/E05_magisk_collector__observer-root__sample.json"
)
WRITABLE = (
    ROOT
    / "datasets/samples/writable_system_avd/E03_writable_system_avd__observer-adb__sample.json"
)


def changed(diff: dict, dimension: str) -> dict:
    return next(
        item for item in diff["changed_dimensions"] if item["dimension"] == dimension
    )


def rehash_diff(document: dict) -> None:
    projection = {
        key: value
        for key, value in document.items()
        if key not in {"diff_id", "content_digest"}
    }
    digest = framed_content_digest(
        family="diff", schema_version=document["schema_version"], value=projection
    )
    document["content_digest"] = digest
    document["diff_id"] = f"atldiff-{digest[:32]}"


def test_current_diff_separates_materiality_direction_and_confidence():
    diff = make_diff(load_json(STOCK), load_json(ROOTED_ADB))
    signal = changed(diff, "su_binary_visibility")

    assert diff["schema_version"] == "2.7.0"
    assert "severity" not in signal
    assert signal["materiality"] == "moderate"
    assert signal["direction"] == "indeterminate"
    assert signal["confidence"]["level"] == "moderate"
    assert signal["confidence"]["factors"] == {
        "evidence_statuses": {
            "before": "observed_absent",
            "after": "observed",
        },
        "field_confidence": {
            "before": "not_available",
            "after": "not_available",
        },
        "corroborating_evidence_count": 1,
        "migration_count": 0,
        "comparability": "comparable",
        "comparability_warning_count": 0,
    }
    assert signal["evidence_paths"] == ["root_state.su_binary_observed"]
    assert signal["rationale"] == [
        "materiality_from_dimension_policy",
        "no_justified_direction_rule",
        "confidence_from_explicit_factors",
    ]
    assert "score" not in repr(diff).lower()
    validate_diff(diff)


def test_ordered_direction_inverts_for_reversed_mount_comparison():
    stock = load_json(STOCK)
    writable = load_json(WRITABLE)

    forward = changed(make_diff(stock, writable), "mount_integrity")
    reverse = changed(make_diff(writable, stock), "mount_integrity")

    assert forward["materiality"] == reverse["materiality"] == "high"
    assert forward["direction"] == "regression"
    assert reverse["direction"] == "improvement"
    assert forward["confidence"]["level"] == reverse["confidence"]["level"]
    assert (
        forward["rationale"][1]
        == reverse["rationale"][1]
        == ("ordered_dimension_rule_applied")
    )


def test_indeterminate_direction_does_not_invert_without_a_rule():
    stock = load_json(STOCK)
    rooted = load_json(ROOTED_ADB)

    assert (
        changed(make_diff(stock, rooted), "su_binary_visibility")["direction"]
        == "indeterminate"
    )
    assert (
        changed(make_diff(rooted, stock), "su_binary_visibility")["direction"]
        == "indeterminate"
    )


def test_mixed_observer_comparison_uses_context_not_regression():
    diff = make_diff(load_json(ROOTED_ADB), load_json(MAGISK_ROOT), allow_mixed=True)

    process = changed(diff, "selected_process_visibility")
    magisk = changed(diff, "magisk_binary_visibility")
    assert process["direction"] == "context_change"
    assert magisk["direction"] == "context_change"
    assert process["confidence"]["factors"]["comparability"] == "limited"
    assert process["confidence"]["factors"]["comparability_warning_count"] == 1
    assert "comparison_warning_reduces_confidence" in process["confidence"]["rationale"]
    assert not {item["direction"] for item in diff["changed_dimensions"]} & {
        "improvement",
        "regression",
    }


def test_verified_boot_direction_uses_field_confidence_and_corroboration():
    base = load_json(STOCK)
    compare = copy.deepcopy(base)
    compare["verified_boot"]["flash_locked"]["value"] = "0"
    compare = attach_comparison_context(
        compare,
        target_pseudonym="target-synthetic-avd",
        state_id="state-unlocked-fixture",
        environment_context="synthetic",
    )

    forward = changed(make_diff(base, compare), "bootloader_lock_state")
    reverse = changed(make_diff(compare, base), "bootloader_lock_state")

    assert forward["direction"] == "regression"
    assert reverse["direction"] == "improvement"
    assert forward["confidence"]["level"] == "low"
    assert forward["confidence"]["factors"]["field_confidence"] == {
        "before": "low",
        "after": "low",
    }
    assert forward["confidence"]["factors"]["corroborating_evidence_count"] == 4
    assert "field_confidence_applied" in forward["confidence"]["rationale"]


def test_migrations_and_incomparability_reduce_confidence():
    historical = load_json(ROOT / "tests/fixtures/report_v1_historical.json")
    current = load_json(STOCK)

    diff = make_diff(historical, current)
    assessment = diff["changed_dimensions"][0]["confidence"]

    assert assessment["level"] == "low"
    assert assessment["factors"]["migration_count"] == 5
    assert assessment["factors"]["comparability"] == "incomparable"
    assert "input_migration_reduces_confidence" in assessment["rationale"]
    assert "comparison_incomparable" in assessment["rationale"]


def test_visibility_transition_is_not_assigned_target_direction():
    base = load_json(STOCK)
    compare = copy.deepcopy(base)
    compare["magisk_state"]["module_context"] = {
        "status": "observed",
        "value": "androidtrustlab",
        "reason": None,
        "evidence_refs": ["legacy-sections/MAGISK"],
    }
    base["magisk_state"]["module_context"] = {
        "status": "inaccessible",
        "value": None,
        "reason": "fixture visibility boundary",
        "evidence_refs": [],
    }
    base = attach_comparison_context(
        base,
        target_pseudonym="target-synthetic-avd",
        state_id="state-visibility-fixture",
        environment_context="synthetic",
    )
    compare = attach_comparison_context(
        compare,
        target_pseudonym="target-synthetic-avd",
        state_id="state-visibility-fixture",
        environment_context="synthetic",
    )

    diff = make_diff(base, compare)
    assessment = changed(diff, "magisk_module_context")

    assert assessment["direction"] == "visibility_change"
    assert assessment["materiality"] == "informational"
    assert diff["new_signals"][0]["direction"] == "visibility_change"
    assert diff["new_signals"][0]["confidence"] == assessment["confidence"]
    assert diff["new_signals"][0]["evidence_paths"] == assessment["evidence_paths"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("materiality", "low", "materiality"),
        ("direction", "improvement", "direction"),
    ],
)
def test_validation_rejects_forged_assessment(field, value, message):
    diff = make_diff(load_json(STOCK), load_json(ROOTED_ADB))
    diff["changed_dimensions"][0][field] = value
    rehash_diff(diff)

    with pytest.raises(SchemaValidationError, match=message):
        validate_diff(diff)


def test_validation_rejects_forged_confidence_factors():
    diff = make_diff(load_json(STOCK), load_json(ROOTED_ADB))
    diff["changed_dimensions"][0]["confidence"]["factors"][
        "corroborating_evidence_count"
    ] = 99
    rehash_diff(diff)

    with pytest.raises(SchemaValidationError, match="confidence"):
        validate_diff(diff)
