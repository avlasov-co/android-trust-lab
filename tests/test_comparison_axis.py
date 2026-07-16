from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from trustlab.cli import EXIT_USAGE_ERROR, main
from trustlab.comparison import attach_comparison_context
from trustlab.diff import make_diff
from trustlab.exceptions import ComparisonAcknowledgementError, SchemaValidationError
from trustlab.normalizer import normalize_raw_file
from trustlab.report_writer import diff_to_markdown

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "tests/fixtures/sample_raw_report.txt"


def contextual_report(
    *,
    observer: str = "adb_shell",
    method: str = "adb_shell_snapshot",
    experiment: str = "E01_stock_avd",
    target_type: str = "avd",
    target_pseudonym: str = "target-comparison-fixture",
    state_id: str = "state-stock",
    environment: str = "synthetic",
    timestamp: str = "2026-07-16T10:00:00Z",
):
    report = normalize_raw_file(
        RAW,
        observer_type=observer,
        collection_method=method,
        experiment_id=experiment,
        target_type=target_type,
        collection_timestamp=timestamp,
    )
    return attach_comparison_context(
        report,
        target_pseudonym=target_pseudonym,
        state_id=state_id,
        environment_context=environment,
    )


def test_same_target_state_change_axis():
    base = contextual_report()
    compare = contextual_report(
        experiment="E02_rooted_avd",
        state_id="state-rooted",
        timestamp="2026-07-16T10:01:00Z",
    )

    diff = make_diff(base, compare)

    assert diff["comparison"]["axis"] == "same_target_state_change"
    assert diff["comparison"]["comparability"] == "comparable"
    assert diff["comparison"]["visibility_context_changed"] is False
    assert "state_identity_differs" in diff["comparison"]["reasons"]


@pytest.mark.parametrize(
    ("observer", "method"),
    [
        ("unprivileged_app", "app_snapshot"),
        ("root_collector", "synthetic_root_collector_snapshot"),
    ],
)
def test_same_state_observer_change_axis_covers_app_adb_and_adb_root(observer, method):
    base = contextual_report()
    compare = contextual_report(
        observer=observer,
        method=method,
        timestamp="2026-07-16T10:01:00Z",
    )

    diff = make_diff(base, compare)

    assert diff["comparison"]["axis"] == "same_state_observer_change"
    assert diff["comparison"]["visibility_context_changed"] is True
    assert diff["comparison"]["warnings"] == [
        "observer_context_changed_visibility_may_differ"
    ]
    dimensions = {item["dimension"] for item in diff["changed_dimensions"]}
    assert "observer_privilege" not in dimensions
    assert "observer_uid_root" not in dimensions


def test_repeat_measurement_axis_uses_distinct_measurement_ids():
    base = contextual_report()
    compare = contextual_report(timestamp="2026-07-16T10:01:00Z")

    diff = make_diff(base, compare)

    assert diff["comparison"]["axis"] == "repeat_measurement"
    assert "measurement_differs" in diff["comparison"]["reasons"]


@pytest.mark.parametrize(
    "change",
    [
        {"target_pseudonym": "target-unrelated-fixture"},
        {"target_type": "physical"},
        {"environment": "physical_captured"},
    ],
)
def test_different_target_context_axis(change):
    base = contextual_report()
    compare = contextual_report(timestamp="2026-07-16T10:01:00Z", **change)

    diff = make_diff(base, compare)

    assert diff["comparison"]["axis"] == "different_target_context"
    assert diff["comparison"]["comparability"] == "limited"
    assert diff["comparison"]["warnings"] == [
        "different_target_context_limits_attribution"
    ]


def test_missing_context_is_incomparable_without_guessing():
    base = normalize_raw_file(
        RAW,
        collection_timestamp="2026-07-16T10:00:00Z",
    )
    compare = copy.deepcopy(base)

    diff = make_diff(base, compare)

    assert diff["comparison"]["axis"] == "incomparable"
    assert diff["comparison"]["comparability"] == "incomparable"
    assert "target_identity_missing" in diff["comparison"]["reasons"]
    assert "state_identity_missing" in diff["comparison"]["reasons"]


def test_mixed_change_requires_explicit_acknowledgement():
    base = contextual_report()
    compare = contextual_report(
        observer="root_collector",
        method="synthetic_root_collector_snapshot",
        experiment="E02_rooted_avd",
        state_id="state-rooted",
        timestamp="2026-07-16T10:01:00Z",
    )

    with pytest.raises(ComparisonAcknowledgementError, match="--allow-mixed"):
        make_diff(base, compare)

    diff = make_diff(base, compare, allow_mixed=True)
    assert diff["comparison"]["axis"] == "mixed_change"
    assert diff["comparison"]["acknowledgement"] == "allow_mixed"
    assert diff["comparison"]["warnings"] == [
        "mixed_state_and_observer_change_acknowledged"
    ]
    markdown = diff_to_markdown(diff)
    assert "> **Warning:** Target state and observer context both changed" in markdown


def test_comparison_context_is_bound_into_report_identity():
    report = contextual_report()
    tampered = copy.deepcopy(report)
    tampered["extensions"]["org.androidtrustlab.comparison-context"]["state_id"] = (
        "state-tampered"
    )

    with pytest.raises(SchemaValidationError, match="content digest"):
        make_diff(tampered, report)


def test_cli_allow_mixed_controls_output_and_preserves_destination(tmp_path, capsys):
    base = contextual_report()
    compare = contextual_report(
        observer="root_collector",
        method="synthetic_root_collector_snapshot",
        experiment="E02_rooted_avd",
        state_id="state-rooted",
        timestamp="2026-07-16T10:01:00Z",
    )
    base_path = tmp_path / "base.json"
    compare_path = tmp_path / "compare.json"
    output_path = tmp_path / "diff.json"
    base_path.write_text(json.dumps(base), encoding="utf-8")
    compare_path.write_text(json.dumps(compare), encoding="utf-8")
    output_path.write_text("sentinel\n", encoding="utf-8")

    code = main(
        [
            "diff",
            "--base",
            str(base_path),
            "--compare",
            str(compare_path),
            "--output",
            str(output_path),
        ]
    )
    assert code == EXIT_USAGE_ERROR
    assert "--allow-mixed" in capsys.readouterr().err
    assert output_path.read_text(encoding="utf-8") == "sentinel\n"

    code = main(
        [
            "diff",
            "--base",
            str(base_path),
            "--compare",
            str(compare_path),
            "--output",
            str(output_path),
            "--allow-mixed",
        ]
    )
    assert code == 0
    diff = json.loads(output_path.read_text(encoding="utf-8"))
    assert diff["comparison"]["axis"] == "mixed_change"
    assert diff["comparison"]["warnings"] == [
        "mixed_state_and_observer_change_acknowledged"
    ]
