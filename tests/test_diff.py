import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyzer"))

from trustlab.canonical_json import framed_content_digest
from trustlab.diff import make_diff
from trustlab.exceptions import SchemaValidationError
from trustlab.identity import finalize_report_identity
from trustlab.migrations import migrate_report_to_current, migrate_report_v1_to_v2
from trustlab.report_writer import load_json
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
    assert "root_presence" in dimensions
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
    assert "observer_privilege" in dimensions
    assert "root_presence" not in dimensions


def test_diff_does_not_emit_fake_visibility_or_physical_dimensions():
    base = load_report(
        "datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json"
    )
    compare = load_report(
        "datasets/samples/rooted_avd/E02_rooted_avd__observer-root__sample.json"
    )
    diff = make_diff(base, compare)
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


def test_diff_id_preserves_prior_utf8_canonicalization():
    base = load_report("tests/fixtures/sample_normalized_report.json")
    compare = copy.deepcopy(base)
    compare["properties"]["security"]["value"]["ro.secure"] = "sécurisé"
    compare = finalize_report_identity(compare)

    assert make_diff(base, compare)["diff_id"] != make_diff(base, base)["diff_id"]


def test_cross_version_diff_uses_explicit_migration_chain():
    v1 = load_report("tests/fixtures/report_v1_historical.json")
    v2 = migrate_report_v1_to_v2(v1)

    diff = make_diff(v1, v2)
    assert diff["changed_dimensions"] == []
    assert len(diff["unchanged_dimensions"]) == 14
    current = migrate_report_to_current(v2)
    provenance = diff["provenance"]
    assert provenance["common_report_schema_version"] == "4.0.0"
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
            "schema_version": "4.0.0",
        }
    )
    assert [
        migration["migration_id"]
        for migration in provenance["base"]["applied_migrations"]
    ] == ["report-v1-to-v2", "report-v2-to-v3", "report-v3-to-v4"]
    assert [
        migration["migration_id"]
        for migration in provenance["compare"]["applied_migrations"]
    ] == ["report-v2-to-v3", "report-v3-to-v4"]
    validate_diff(diff)


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


@pytest.mark.parametrize("field", ["original_report_id", "original_content_digest"])
def test_diff_validation_rejects_rehashed_forged_original_v4_identity(field):
    current = load_report("tests/fixtures/sample_normalized_report.json")
    forged = make_diff(current, current)
    forged["provenance"]["base"][field] = "0" * 64
    rehash_diff(forged)

    with pytest.raises(SchemaValidationError, match="original current report identity"):
        validate_diff(forged)
