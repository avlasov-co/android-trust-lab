from __future__ import annotations

import copy
import itertools
from pathlib import Path

import pytest

from trustlab.canonical_json import framed_content_digest
from trustlab.comparison import attach_comparison_context
from trustlab.diff import make_diff
from trustlab.exceptions import SchemaValidationError
from trustlab.identity import finalize_report_identity
from trustlab.report_writer import load_json
from trustlab.transitions import (
    classify_status_transition,
    confidence_impact,
    evidence_status,
    signal_direction,
    transition_interpretation,
)
from trustlab.validators import validate_diff

ROOT = Path(__file__).resolve().parents[1]
STATUSES = (
    "observed",
    "observed_absent",
    "inaccessible",
    "not_collected",
    "command_error",
    "unsupported",
)
EXPECTED_CLASSES = (
    (
        "state_change",
        "state_change",
        "visibility_change",
        "collection_quality_change",
        "collection_quality_change",
        "collection_quality_change",
    ),
    (
        "state_change",
        "state_change",
        "visibility_change",
        "collection_quality_change",
        "collection_quality_change",
        "collection_quality_change",
    ),
    (
        "visibility_change",
        "visibility_change",
        "visibility_change",
        "visibility_change",
        "visibility_change",
        "visibility_change",
    ),
    (
        "collection_quality_change",
        "collection_quality_change",
        "visibility_change",
        "collection_quality_change",
        "collection_quality_change",
        "collection_quality_change",
    ),
    (
        "collection_quality_change",
        "collection_quality_change",
        "visibility_change",
        "collection_quality_change",
        "collection_quality_change",
        "collection_quality_change",
    ),
    (
        "collection_quality_change",
        "collection_quality_change",
        "visibility_change",
        "collection_quality_change",
        "collection_quality_change",
        "collection_quality_change",
    ),
)


def evidence(status: str, *, value: str | None = None, ref: str) -> dict:
    if status == "observed":
        return {
            "status": status,
            "value": value or "androidtrustlab",
            "reason": None,
            "evidence_refs": [ref],
        }
    return {
        "status": status,
        "value": None,
        "reason": "fixture evidence outcome",
        "evidence_refs": [] if status != "observed_absent" else [ref],
    }


def report_with_module_context(
    status: str,
    *,
    value: str | None = None,
    ref: str = "legacy-sections/MAGISK",
) -> dict:
    report = load_json(ROOT / "tests/fixtures/sample_normalized_report.json")
    report = attach_comparison_context(
        copy.deepcopy(report),
        target_pseudonym="target-status-transition-fixture",
        state_id="state-status-transition-fixture",
        environment_context="synthetic",
    )
    report["magisk_state"]["module_context"] = evidence(status, value=value, ref=ref)
    return finalize_report_identity(report)


def rehash_diff(document: dict) -> None:
    projection = {
        key: value
        for key, value in document.items()
        if key not in {"diff_id", "content_digest"}
    }
    digest = framed_content_digest(
        family="diff",
        schema_version=document["schema_version"],
        value=projection,
    )
    document["content_digest"] = digest
    document["diff_id"] = f"atldiff-{digest[:32]}"


@pytest.mark.parametrize(
    ("before_index", "after_index"), list(itertools.product(range(6), repeat=2))
)
def test_complete_status_transition_matrix(before_index, after_index):
    before = STATUSES[before_index]
    after = STATUSES[after_index]

    assert (
        classify_status_transition(
            before,
            after,
            comparison_axis="same_target_state_change",
        )
        == EXPECTED_CLASSES[before_index][after_index]
    )


def test_observer_axis_classifies_every_status_pair_as_context_change():
    for before, after in itertools.product(STATUSES, repeat=2):
        assert (
            classify_status_transition(
                before,
                after,
                comparison_axis="same_state_observer_change",
            )
            == "context_change"
        )


@pytest.mark.parametrize(
    "axis", ["different_target_context", "mixed_change", "incomparable"]
)
def test_confounded_observed_transitions_are_context_changes(axis):
    assert (
        classify_status_transition(
            "observed",
            "observed_absent",
            comparison_axis=axis,
        )
        == "context_change"
    )


def test_aggregate_status_and_transition_helpers_cover_non_observed_outcomes():
    assert evidence_status({"derived": "value"}) == "observed"
    assert (
        evidence_status([{"status": "command_error"}, {"status": "unsupported"}])
        == "command_error"
    )
    assert (
        evidence_status([{"status": "unsupported"}, {"status": "not_collected"}])
        == "unsupported"
    )
    assert confidence_impact("not_collected", "not_collected") == "unchanged"
    assert confidence_impact("command_error", "unsupported") == "indeterminate"
    assert signal_direction("observed_absent", "observed") is None
    assert "observer context" in transition_interpretation(
        "observed", "observed_absent", "context_change"
    )
    assert "explicit observations" in transition_interpretation(
        "observed", "observed_absent", "state_change"
    )


@pytest.mark.parametrize(
    (
        "before_status",
        "after_status",
        "signal_list",
        "transition_class",
        "impact",
    ),
    [
        (
            "not_collected",
            "observed",
            "new_signals",
            "collection_quality_change",
            "increased",
        ),
        ("inaccessible", "observed", "new_signals", "visibility_change", "increased"),
        (
            "observed",
            "inaccessible",
            "missing_signals",
            "visibility_change",
            "decreased",
        ),
        ("observed", "observed_absent", None, "state_change", "unchanged"),
        (
            "command_error",
            "observed",
            "new_signals",
            "collection_quality_change",
            "increased",
        ),
    ],
)
def test_required_status_transitions_are_structured(
    before_status,
    after_status,
    signal_list,
    transition_class,
    impact,
):
    diff = make_diff(
        report_with_module_context(before_status),
        report_with_module_context(after_status),
    )
    change = next(
        item
        for item in diff["changed_dimensions"]
        if item["dimension"] == "magisk_module_context"
    )

    assert change["transition"] == {
        "before_status": before_status,
        "after_status": after_status,
        "classification": transition_class,
        "confidence_impact": impact,
    }
    if signal_list is None:
        assert diff["new_signals"] == diff["missing_signals"] == []
    else:
        signal = diff[signal_list][0]
        assert signal["dimension"] == "magisk_module_context"
        assert signal["before_status"] == before_status
        assert signal["after_status"] == after_status
        assert signal["classification"] == transition_class
        assert signal["confidence_impact"] == impact
        if transition_class == "visibility_change":
            assert (
                "inaccessible is distinct from observed absence"
                in signal["interpretation"]
            )
        else:
            assert signal["interpretation"]
        other = "missing_signals" if signal_list == "new_signals" else "new_signals"
        assert diff[other] == []
    validate_diff(diff)


def test_literal_observed_unknown_does_not_collide_with_status_sentinel():
    diff = make_diff(
        report_with_module_context("not_collected"),
        report_with_module_context("observed", value="unknown"),
    )

    signal = diff["new_signals"][0]
    assert signal["after_status"] == "observed"
    assert signal["observed_values"]["after"] == "unknown"
    assert signal["observed_values"]["before"] is None
    validate_diff(diff)


@pytest.mark.parametrize(
    ("unavailable", "available"),
    list(
        itertools.product(
            ("inaccessible", "not_collected", "command_error", "unsupported"),
            ("observed", "observed_absent"),
        )
    ),
)
def test_new_and_missing_signal_inversion(unavailable, available):
    unavailable_report = report_with_module_context(
        unavailable, ref="legacy-sections/ROOT_PROBE"
    )
    available_report = report_with_module_context(
        available, ref="legacy-sections/MAGISK"
    )

    forward = make_diff(unavailable_report, available_report)
    reverse = make_diff(available_report, unavailable_report)
    new_signal = forward["new_signals"][0]
    missing_signal = reverse["missing_signals"][0]

    assert signal_direction(unavailable, available) == "new"
    assert signal_direction(available, unavailable) == "missing"
    assert new_signal["before_status"] == missing_signal["after_status"]
    assert new_signal["after_status"] == missing_signal["before_status"]
    assert (
        new_signal["observed_values"]["before"]
        == missing_signal["observed_values"]["after"]
    )
    assert (
        new_signal["observed_values"]["after"]
        == missing_signal["observed_values"]["before"]
    )
    assert confidence_impact(unavailable, available) == "increased"
    assert confidence_impact(available, unavailable) == "decreased"


def test_summary_includes_structured_signal_counts_and_sources():
    diff = make_diff(
        report_with_module_context("command_error"),
        report_with_module_context("observed"),
    )

    assert diff["summary"].endswith(
        "1 signals became available, 0 signals became unavailable."
    )
    assert diff["new_signals"][0]["source_evidence"] == {
        "before": [],
        "after": ["legacy-sections/MAGISK"],
    }


def test_validation_rejects_forged_transition_classification():
    diff = make_diff(
        report_with_module_context("inaccessible"),
        report_with_module_context("observed"),
    )
    diff["changed_dimensions"][0]["transition"]["classification"] = "state_change"
    diff["new_signals"][0]["classification"] = "state_change"
    rehash_diff(diff)

    with pytest.raises(SchemaValidationError, match="transition is not canonical"):
        validate_diff(diff)


def test_validation_rejects_inaccessible_evidence_forged_as_new():
    diff = make_diff(
        report_with_module_context("not_collected"),
        report_with_module_context("observed"),
    )
    diff["new_signals"][0]["after_status"] = "inaccessible"
    rehash_diff(diff)

    with pytest.raises(SchemaValidationError, match="structured signal transition"):
        validate_diff(diff)
