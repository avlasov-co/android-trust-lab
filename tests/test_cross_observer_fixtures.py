from __future__ import annotations

import hashlib
import json
import shutil
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from trustlab.canonical_json import framed_content_digest
from trustlab.collection_manifest import CollectionManifest
from trustlab.dataset_manifest import stable_pretty_json_bytes
from trustlab.dimension_registry import (
    TRUST_DIMENSIONS_BY_ID,
    comparison_value,
    extract_dimension,
)
from trustlab.exceptions import SchemaValidationError
from trustlab.validators import validate_diff, validate_report

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from cross_observer_fixture import (  # noqa: E402
    CROSS_OBSERVER_MATRIX_RELATIVE,
    CROSS_OBSERVER_RELATIVE,
    build_cross_observer_artifacts,
)


@pytest.fixture(scope="module")
def cross_observer():
    return build_cross_observer_artifacts(ROOT)


def _rehash_diff(document: dict) -> None:
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


def test_linked_bundle_normalizes_three_observers_and_all_pairs(cross_observer):
    assert cross_observer.contract["experimental_protocol_id"] == (
        "atl_cross_observer_v1"
    )
    assert list(cross_observer.reports_by_observer) == ["app", "adb", "root"]
    assert list(cross_observer.diffs_by_pair) == [
        "app-vs-adb",
        "app-vs-root",
        "adb-vs-root",
    ]
    assert len(cross_observer.outputs) == 7

    contexts = []
    raw_hashes = set()
    for report in cross_observer.reports_by_observer.values():
        validate_report(report)
        contexts.append(report["extensions"]["org.androidtrustlab.comparison-context"])
        raw_hashes.add(report["raw_artifacts"][0]["sha256"])
        assert report["raw_artifacts"][0]["collection_id"] == "collection-redacted"
    assert {context["target_pseudonym"] for context in contexts} == {
        "target-3535353535353535"
    }
    assert {context["state_id"] for context in contexts} == {
        "state-e35-cross-observer-rooted-avd"
    }
    assert {context["experiment_id"] for context in contexts} == {"E35_cross_observer"}
    assert {context["protocol"] for context in contexts} == {"app", "adb", "root"}
    assert len(raw_hashes) == 3

    for diff in cross_observer.diffs_by_pair.values():
        validate_diff(diff)
        assert diff["schema_version"] == "2.8.0"
        assert diff["comparison"]["axis"] == "same_state_observer_change"
        assert not {item["direction"] for item in diff["changed_dimensions"]} & {
            "improvement",
            "regression",
        }


@pytest.mark.parametrize("pair_id", ["app-vs-adb", "app-vs-root"])
def test_app_inaccessible_context_becomes_context_change(cross_observer, pair_id):
    diff = cross_observer.diffs_by_pair[pair_id]
    change = next(
        item
        for item in diff["changed_dimensions"]
        if item["dimension"] == "selinux_current_context"
    )

    assert change["transition"] == {
        "before_status": "inaccessible",
        "after_status": "observed",
        "classification": "context_change",
        "confidence_impact": "increased",
    }
    assert change["direction"] == "context_change"
    assert change["confidence"]["level"] == "moderate"
    signal = next(
        item
        for item in diff["new_signals"]
        if item["dimension"] == "selinux_current_context"
    )
    assert signal["before_status"] == "inaccessible"
    assert signal["classification"] == signal["direction"] == "context_change"


def test_shared_observations_remain_consistent(cross_observer):
    reports = cross_observer.reports_by_observer
    emulator = TRUST_DIMENSIONS_BY_ID["emulator_state"]
    assert {
        extract_dimension(report, emulator)["value"] for report in reports.values()
    } == {True}

    adb_root = [reports[observer] for observer in ("adb", "root")]
    for dimension_id in (
        "verified_boot_state",
        "mount_integrity",
        "su_binary_visibility",
    ):
        definition = TRUST_DIMENSIONS_BY_ID[dimension_id]
        assert comparison_value(
            extract_dimension(adb_root[0], definition)
        ) == comparison_value(extract_dimension(adb_root[1], definition))


def test_contradiction_retains_confidence_and_source_chain(cross_observer):
    reports = cross_observer.reports_by_observer
    diff = cross_observer.diffs_by_pair["adb-vs-root"]
    change = next(
        item
        for item in diff["changed_dimensions"]
        if item["dimension"] == "selinux_mode"
    )

    assert change["before"] == {"status": "observed", "value": "enforcing"}
    assert change["after"] == {"status": "observed", "value": "permissive"}
    assert change["direction"] == "context_change"
    assert change["confidence"]["level"] == "moderate"
    assert change["confidence"]["factors"] == {
        "evidence_statuses": {"before": "observed", "after": "observed"},
        "field_confidence": {
            "before": "not_available",
            "after": "not_available",
        },
        "corroborating_evidence_count": 1,
        "migration_count": 0,
        "comparability": "comparable",
        "comparability_warning_count": 1,
    }
    for side, observer_id in (("base", "adb"), ("compare", "root")):
        report = reports[observer_id]
        assert diff[f"{side}_report"] == {
            "report_id": report["report_id"],
            "content_digest": report["content_digest"],
            "schema_version": report["schema_version"],
        }
        assert diff["provenance"][side]["common_report"] == diff[f"{side}_report"]
        selinux = report["selinux"]["policy_mode"]
        assert selinux["evidence_refs"] == ["legacy-sections/GETENFORCE"]

    observers = {
        entry["observer_id"]: entry for entry in cross_observer.contract["observers"]
    }
    assert (
        reports["adb"]["raw_artifacts"][0]["sha256"] == observers["adb"]["raw_sha256"]
    )
    assert (
        reports["root"]["raw_artifacts"][0]["sha256"] == observers["root"]["raw_sha256"]
    )


def test_app_visible_diff_path_is_valid_in_new_diff_contract(cross_observer):
    diff = cross_observer.diffs_by_pair["app-vs-adb"]
    change = next(
        item
        for item in diff["changed_dimensions"]
        if item["dimension"] == "app_visible_state"
    )

    assert change["evidence_paths"] == ["extensions.org.androidtrustlab.app-probe"]
    assert change["direction"] == "context_change"
    probes = change["before"]["value"]["probes"]
    assert [probe["probe_id"] for probe in probes] == [
        "build_version",
        "app_identity",
        "install_source",
        "selinux_self_context",
        "file_system_shell",
        "file_system_su",
        "file_system_xbin_su",
        "file_vendor_bin_su",
        "file_sbin_su",
        "proc_self_status",
        "proc_self_mountinfo",
        "emulator_indicators",
    ]
    assert all(
        "reason" not in probe and "evidence_refs" not in probe for probe in probes
    )
    signal = next(
        item
        for item in diff["missing_signals"]
        if item["dimension"] == "app_visible_state"
    )
    assert signal["source_evidence"]["before"] == sorted(
        f"captures/{probe['probe_id']}.txt" for probe in probes
    )
    validate_diff(diff)


def test_collection_manifests_bind_exact_independent_sources(cross_observer):
    bundle = ROOT / CROSS_OBSERVER_RELATIVE
    observed_hashes = set()
    collection_ids = set()
    for entry in cross_observer.contract["observers"]:
        raw = (bundle / entry["raw_path"]).read_bytes()
        manifest_payload = (bundle / entry["manifest_path"]).read_bytes()
        manifest = CollectionManifest.from_dict(json.loads(manifest_payload))
        raw_entry = next(
            artifact
            for artifact in manifest.artifacts
            if artifact.logical_name == "raw_report"
        )
        digest = hashlib.sha256(raw).hexdigest()
        assert digest == entry["raw_sha256"] == raw_entry.sha256
        assert len(raw) == raw_entry.byte_size
        assert hashlib.sha256(manifest_payload).hexdigest() == entry["manifest_sha256"]
        observed_hashes.add(digest)
        collection_ids.add(manifest.collection_id)
    assert len(observed_hashes) == 3
    assert len(collection_ids) == 3


def test_malformed_nested_app_status_fails_closed(cross_observer):
    malformed = deepcopy(cross_observer.diffs_by_pair["app-vs-adb"])
    app_change = next(
        item
        for item in malformed["changed_dimensions"]
        if item["dimension"] == "app_visible_state"
    )
    app_change["before"]["value"]["probes"][0]["status"] = []
    _rehash_diff(malformed)

    with pytest.raises(
        SchemaValidationError, match="diff dimension value contradicts its status"
    ):
        validate_diff(malformed)


def test_cross_observer_generated_outputs_are_fresh(cross_observer):
    for path, expected in cross_observer.outputs.items():
        assert path.read_bytes() == expected
    matrix = (ROOT / CROSS_OBSERVER_MATRIX_RELATIVE).read_text(encoding="utf-8")
    assert "does not represent physical OEM behavior" in matrix
    assert "same_state_observer_change" in matrix


@pytest.mark.parametrize(
    "tamper",
    [
        "raw",
        "expectation",
        "expectation_removed",
        "manifest_hash",
        "extra_generated",
    ],
)
def test_cross_observer_contract_fails_closed_on_tampering(tmp_path, tamper):
    source = ROOT / CROSS_OBSERVER_RELATIVE
    destination = tmp_path / CROSS_OBSERVER_RELATIVE
    destination.parent.mkdir(parents=True)
    shutil.copytree(source, destination)

    if tamper == "extra_generated":
        shutil.copy2(
            destination / "generated/reports/app_report.json",
            destination / "generated/reports/obsolete_report.json",
        )
    elif tamper == "raw":
        path = destination / "adb/adb_snapshot.txt"
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        path = destination / "expectations.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        if tamper == "expectation":
            document["expectations"]["visibility_transitions"][0]["direction"] = (
                "regression"
            )
        elif tamper == "expectation_removed":
            document["expectations"]["visibility_transitions"].pop()
        else:
            document["observers"][0]["manifest_sha256"] = "0" * 64
        path.write_bytes(stable_pretty_json_bytes(document))

    with pytest.raises(SchemaValidationError, match="cross-observer fixture contract"):
        build_cross_observer_artifacts(tmp_path)
