import copy
import sys
from pathlib import Path
from typing import Any, cast

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyzer"))

from trustlab.canonical_json import framed_content_digest
from trustlab.diff import make_diff
from trustlab.exceptions import SchemaValidationError, UnsupportedSchemaVersionError
from trustlab.identity import finalize_report_identity
from trustlab.migrations import migrate_report_to_current, migrate_report_v1_to_v2
from trustlab.report_writer import diff_to_markdown, load_json
from trustlab.validators import validate_diff

ROOT = Path(__file__).resolve().parents[1]


def load_report(relative: str):
    return load_json(ROOT / relative)


def rehash_diff(document):
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
    return document


def test_diff_root_change_without_observer_change():
    base = load_report(
        "datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json"
    )
    compare = load_report(
        "datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json"
    )
    diff = make_diff(base, compare)
    dimensions = {item["dimension"] for item in diff["changed_dimensions"]}
    assert "su_binary_visibility" in dimensions
    assert "observer_privilege" not in dimensions


def test_diff_observer_change_is_separate_from_target_mutation():
    base = load_report(
        "datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json"
    )
    compare = load_report(
        "datasets/samples/rooted_avd/E02_rooted_avd__observer-root__sample.json"
    )
    diff = make_diff(base, compare)
    dimensions = {item["dimension"] for item in diff["changed_dimensions"]}
    assert diff["comparison"]["axis"] == "same_state_observer_change"
    assert diff["comparison"]["visibility_context_changed"] is True
    assert "observer_privilege" not in dimensions
    assert "observer_uid_root" not in dimensions
    assert "su_binary_visibility" not in dimensions


def test_diff_keeps_su_invocation_tested_separate_from_result():
    base = load_report(
        "datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json"
    )
    compare = load_report(
        "datasets/samples/magisk_collector/E05_magisk_collector__observer-root__sample.json"
    )

    diff = make_diff(base, compare, allow_mixed=True)
    dimensions = {item["dimension"] for item in diff["changed_dimensions"]}

    assert "su_invocation_tested" in dimensions
    assert "su_invocation_result" not in dimensions


def test_diff_does_not_emit_fake_visibility_or_physical_dimensions():
    base = load_report(
        "datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json"
    )
    compare = load_report(
        "datasets/samples/rooted_avd/E02_rooted_avd__observer-root__sample.json"
    )
    diff = make_diff(base, compare, allow_mixed=True)
    dimensions = {item["dimension"] for item in diff["changed_dimensions"]}
    assert "app_visible_state" not in dimensions
    assert "root_visible_state" not in dimensions
    assert "physical_device_state" not in dimensions
    assert "bootloader_lock_state" in diff["unchanged_dimensions"]


def test_writable_system_diff_detects_mount_integrity():
    base = load_report(
        "datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json"
    )
    compare = load_report(
        "datasets/samples/writable_system_avd/E03_writable_system_avd__observer-adb__sample.json"
    )
    diff = make_diff(base, compare)
    dimensions = {item["dimension"] for item in diff["changed_dimensions"]}
    assert "mount_integrity" in dimensions


def test_diff_id_is_deterministic():
    base = load_report(
        "datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json"
    )
    compare = load_report(
        "datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json"
    )
    assert make_diff(base, compare)["diff_id"] == make_diff(base, compare)["diff_id"]


def test_diff_id_changes_for_portable_property_transition():
    base = load_report("tests/fixtures/sample_normalized_report.json")
    compare = copy.deepcopy(base)
    compare["properties"]["security"]["value"]["ro.secure"] = "0"
    compare = finalize_report_identity(compare)

    assert make_diff(base, compare)["diff_id"] != make_diff(base, base)["diff_id"]


def test_cross_version_diff_uses_explicit_migration_chain():
    v1 = load_report("tests/fixtures/report_v1_historical.json")
    v2 = migrate_report_v1_to_v2(v1)

    diff = make_diff(v1, v2)
    assert diff["changed_dimensions"] == []
    assert len(diff["unchanged_dimensions"]) == 28
    current = migrate_report_to_current(v2)
    provenance = diff["provenance"]
    compatibility = diff["compatibility"]
    assert compatibility["input_schema_versions"] == {
        "base": "1.0.0",
        "compare": "2.0.0",
    }
    assert compatibility["canonical_comparison_schema_version"] == "6.0.0"
    assert compatibility["migration_mode"] == "temporary_in_memory"
    assert compatibility["warnings"] == [
        "base_input_migrated_temporarily_in_memory",
        "compare_input_migrated_temporarily_in_memory",
    ]
    assert [item["migration_id"] for item in compatibility["migrations"]["base"]] == [
        "report-v1-to-v2",
        "report-v2-to-v3",
        "report-v3-to-v4",
        "report-v4-to-v5",
        "report-v5-to-v6",
    ]
    assert provenance["common_report_schema_version"] == "6.0.0"
    assert provenance["base"]["original_schema_version"] == "1.0.0"
    assert provenance["compare"]["original_schema_version"] == "2.0.0"
    assert (
        provenance["base"]["original_document_digest"]
        != provenance["compare"]["original_document_digest"]
    )
    assert provenance["base"]["original_content_digest"] is None
    assert provenance["compare"]["original_content_digest"] is None
    assert (
        provenance["base"]["common_report"]
        == provenance["compare"]["common_report"]
        == {
            "report_id": current["report_id"],
            "content_digest": current["content_digest"],
            "schema_version": "6.0.0",
        }
    )
    assert [
        migration["migration_id"]
        for migration in provenance["base"]["applied_migrations"]
    ] == [
        "report-v1-to-v2",
        "report-v2-to-v3",
        "report-v3-to-v4",
        "report-v4-to-v5",
        "report-v5-to-v6",
    ]
    assert [
        migration["migration_id"]
        for migration in provenance["compare"]["applied_migrations"]
    ] == [
        "report-v2-to-v3",
        "report-v3-to-v4",
        "report-v4-to-v5",
        "report-v5-to-v6",
    ]
    validate_diff(diff)


def test_v2_inputs_record_temporary_canonical_migration():
    v1 = load_report("tests/fixtures/report_v1_historical.json")
    v2 = migrate_report_v1_to_v2(v1)

    diff = make_diff(v2, v2)

    assert diff["compatibility"]["input_schema_versions"] == {
        "base": "2.0.0",
        "compare": "2.0.0",
    }
    assert len(diff["compatibility"]["migrations"]["base"]) == 4
    assert len(diff["compatibility"]["migrations"]["compare"]) == 4
    assert diff["compatibility"]["warnings"] == [
        "base_input_migrated_temporarily_in_memory",
        "compare_input_migrated_temporarily_in_memory",
    ]
    validate_diff(diff)


def test_current_inputs_record_no_migration_warning():
    current = load_report("tests/fixtures/sample_normalized_report.json")

    diff = make_diff(current, current)

    assert diff["compatibility"] == {
        "input_schema_versions": {"base": "6.0.0", "compare": "6.0.0"},
        "migrations": {"base": [], "compare": []},
        "warnings": [],
        "canonical_comparison_schema_version": "6.0.0",
        "migration_mode": "temporary_in_memory",
    }


@pytest.mark.parametrize("version", [None, "v6", "6", "06.0.0", "6.0"])
def test_diff_rejects_malformed_report_versions(version):
    current = load_report("tests/fixtures/sample_normalized_report.json")
    malformed = copy.deepcopy(current)
    malformed["schema_version"] = version

    with pytest.raises(SchemaValidationError, match="semantic version"):
        make_diff(malformed, current)


def test_diff_rejects_unsupported_report_version_before_comparison():
    current = load_report("tests/fixtures/sample_normalized_report.json")
    unsupported = copy.deepcopy(current)
    unsupported["schema_version"] = "7.0.0"

    with pytest.raises(UnsupportedSchemaVersionError, match="unsupported"):
        make_diff(unsupported, current)


def test_diff_rejects_malformed_document_and_tampered_identity():
    current = load_report("tests/fixtures/sample_normalized_report.json")
    malformed = {"schema_version": "6.0.0"}
    tampered = copy.deepcopy(current)
    tampered["target"]["android_version"]["value"] = "15"

    with pytest.raises(SchemaValidationError, match="schema validation failed"):
        make_diff(malformed, current)
    with pytest.raises(SchemaValidationError, match="content digest"):
        make_diff(tampered, current)
    with pytest.raises(SchemaValidationError, match="JSON object"):
        make_diff(cast(Any, []), current)


def test_diff_validation_rejects_rehashed_unregistered_migration_chain():
    v1 = load_report("tests/fixtures/report_v1_historical.json")
    current = load_report("tests/fixtures/sample_normalized_report.json")
    forged = make_diff(v1, current)
    forged["provenance"]["base"]["applied_migrations"][0]["migration_id"] = (
        "forged-migration"
    )
    rehash_diff(forged)

    with pytest.raises(SchemaValidationError, match="registered migration chain"):
        validate_diff(forged)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("input_version", "input version"),
        ("migrations", "registered migration path"),
        ("warnings", "warnings"),
    ],
)
def test_diff_validation_binds_compatibility_to_provenance(field, message):
    v1 = load_report("tests/fixtures/report_v1_historical.json")
    current = load_report("tests/fixtures/sample_normalized_report.json")
    forged = make_diff(v1, current)
    if field == "input_version":
        forged["compatibility"]["input_schema_versions"]["base"] = "2.0.0"
    elif field == "migrations":
        forged["compatibility"]["migrations"]["base"] = []
    else:
        forged["compatibility"]["warnings"] = []
    rehash_diff(forged)

    with pytest.raises(SchemaValidationError, match=message):
        validate_diff(forged)


def test_diff_and_markdown_reject_sensitive_values():
    base = load_report(
        "datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json"
    )
    compare = load_report(
        "datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json"
    )
    forged = make_diff(base, compare)
    forged["changed_dimensions"][0]["before"] = "ghp_DIFF_PRIVATEVALUE12345678"
    rehash_diff(forged)

    with pytest.raises(SchemaValidationError, match="privacy"):
        validate_diff(forged)
    with pytest.raises(SchemaValidationError, match="privacy"):
        diff_to_markdown(forged)


def test_diff_rejects_account_name_in_magisk_version_dimension():
    base = load_report(
        "datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json"
    )
    compare = load_report(
        "datasets/samples/magisk_collector/E05_magisk_collector__observer-root__sample.json"
    )
    forged = make_diff(base, compare, allow_mixed=True)
    version = next(
        item
        for item in forged["changed_dimensions"]
        if item["dimension"] == "magisk_version_name"
    )
    version["before"] = {"status": "observed", "value": "alice"}
    rehash_diff(forged)

    with pytest.raises(SchemaValidationError, match="dimension"):
        validate_diff(forged)
    with pytest.raises(SchemaValidationError, match="dimension"):
        diff_to_markdown(forged)


def test_diff_rejects_account_name_in_migration_provenance():
    base = load_report("tests/fixtures/report_v1_historical.json")
    compare = load_report("tests/fixtures/sample_normalized_report.json")
    forged = make_diff(base, compare)
    forged["provenance"]["base"]["applied_migrations"][0]["implementation"]["name"] = (
        "alice"
    )
    rehash_diff(forged)

    with pytest.raises(SchemaValidationError, match="provenance"):
        validate_diff(forged)
    with pytest.raises(SchemaValidationError, match="provenance"):
        diff_to_markdown(forged)


@pytest.mark.parametrize("field", ["original_report_id", "original_content_digest"])
def test_diff_validation_rejects_rehashed_forged_original_current_identity(field):
    current = load_report("tests/fixtures/sample_normalized_report.json")
    forged = make_diff(current, current)
    forged["provenance"]["base"][field] = "0" * 64
    rehash_diff(forged)

    with pytest.raises(SchemaValidationError, match="original current report identity"):
        validate_diff(forged)
