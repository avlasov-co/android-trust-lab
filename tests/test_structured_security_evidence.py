from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from trustlab.diff import make_diff
from trustlab.exceptions import SchemaValidationError
from trustlab.identity import finalize_report_identity
from trustlab.normalizer import normalize_raw_file
from trustlab.report_writer import report_to_markdown
from trustlab.security_evidence import SELECTED_PROCESS_NAMES
from trustlab.validators import validate_diff, validate_report


def capture(
    name: str,
    *,
    status: str = "observed",
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = 0,
    source_ref: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "exit_code": exit_code,
        "timed_out": False,
        "stdout": stdout,
        "stderr": stderr,
        "source_ref": source_ref or f"captures/{name}.txt",
    }


def normalize_manifest(
    tmp_path: Path,
    captures: list[dict[str, Any]],
    *,
    artifact_kind: str = "adb_collection_manifest",
    observer_type: str = "adb_shell",
    suffix: str = "sample",
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    document = {
        "artifact_kind": artifact_kind,
        "schema_version": "1.0.0",
        "collector_version": "0.3.0",
        "observer": {
            "observer_type": observer_type,
            "collection_method": "synthetic_security_fixture",
        },
        "collection": {
            "experiment_id": "E19_structured_security",
            "target_type": "avd",
            "timestamp": "2026-07-16T19:00:00Z",
        },
        "captures": captures,
        "warnings": warnings or [],
    }
    path = tmp_path / f"{suffix}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return normalize_raw_file(
        path,
        raw_artifact_ref=f"tests/generated/{suffix}.json",
        raw_artifact_id=f"security-fixture-{suffix}",
        redaction_state="redacted",
    )


def selected(report: dict[str, Any], name: str) -> dict[str, Any]:
    return next(
        item
        for item in report["process_state"]["selected_processes"]
        if item["name"] == name
    )


def full_security_report(tmp_path: Path, *, suffix: str = "full") -> dict[str, Any]:
    return normalize_manifest(
        tmp_path,
        [
            capture("getenforce", stdout="Enforcing\n"),
            capture(
                "selinux_context",
                stdout="u:r:untrusted_app:s0:c987654,c999999\n",
            ),
            capture(
                "selinux_denials",
                stdout="one sanitized denial-collection marker\n",
            ),
            capture(
                "processes",
                stdout=(
                    "LABEL USER PID NAME\n"
                    "u:r:init:s0 root 1 init\n"
                    "u:r:zygote:s0:c987654,c999999 u0_a987 7654321 zygote64\n"
                    "u:r:shell:s0 shell 8765432 private-command-marker\n"
                ),
                stderr="private-stderr-marker",
            ),
        ],
        suffix=suffix,
    )


def test_complete_table_retains_contexts_and_can_prove_exact_absence(
    tmp_path: Path,
) -> None:
    report = full_security_report(tmp_path)

    assert report["schema_version"] == "6.0.0"
    assert report["selinux"]["policy_mode"] == {
        "status": "observed",
        "value": "enforcing",
        "reason": None,
        "evidence_refs": ["captures/getenforce.txt"],
    }
    assert report["selinux"]["current_context"]["value"] == ("u:r:untrusted_app:s0")
    assert report["selinux"]["denial_collection"]["status"] == "observed"
    assert report["process_state"]["scope"] == "complete"
    assert report["process_state"]["completeness"] == "complete"
    assert selected(report, "init")["visibility"]["status"] == "observed"
    assert selected(report, "zygote64")["context"]["value"] == "u:r:zygote:s0"
    assert selected(report, "adbd")["visibility"]["status"] == "observed_absent"
    assert [item["name"] for item in report["process_state"]["selected_processes"]] == [
        *SELECTED_PROCESS_NAMES
    ]
    validate_report(report)


def test_portable_report_discards_pids_users_categories_arguments_and_stderr(
    tmp_path: Path,
) -> None:
    serialized = json.dumps(full_security_report(tmp_path), sort_keys=True)

    for private_marker in (
        "u0_a987",
        "7654321",
        "8765432",
        "c987654",
        "c999999",
        "private-command-marker",
        "private-stderr-marker",
    ):
        assert private_marker not in serialized


def test_portable_report_withholds_arbitrary_manifest_warnings(tmp_path: Path) -> None:
    report = normalize_manifest(
        tmp_path,
        [],
        suffix="warning-redaction",
        warnings=["PRIVATE_CMDLINE_PID_424242 user=u0_a123 /system/bin/sh --secret"],
    )

    adapter = report["extensions"]["org.androidtrustlab.adapter"]
    assert adapter["warnings"] == ["adapter warning 001 withheld"]
    assert "PRIVATE_CMDLINE_PID_424242" not in json.dumps(report)


@pytest.mark.parametrize(
    ("capture_name", "stdout", "expected_limitation"),
    [
        (
            "ps_selected",
            "u:r:init:s0 init\n",
            "selected_filter_not_exhaustive",
        ),
        (
            "processes",
            "LABEL USER PID NAME\nu:r:init:s0 root 1 init\nu:r:adbd:s0 shell\n",
            "partial_process_table",
        ),
        (
            "processes",
            "USER PID NAME\nroot 1 init\nroot 2 magis+\n",
            "partial_process_table",
        ),
    ],
)
def test_filtered_or_partial_capture_never_proves_nonexistence(
    tmp_path: Path,
    capture_name: str,
    stdout: str,
    expected_limitation: str,
) -> None:
    report = normalize_manifest(
        tmp_path,
        [capture(capture_name, stdout=stdout)],
        suffix=f"{capture_name}-limited",
    )

    assert selected(report, "init")["visibility"]["status"] == "observed"
    assert selected(report, "adbd")["visibility"]["status"] == "not_collected"
    assert all(
        item["visibility"]["status"] != "observed_absent"
        for item in report["process_state"]["selected_processes"]
    )
    assert expected_limitation in report["process_state"]["limitations"]
    validate_report(report)


def test_legacy_unsupported_ps_layout_retains_structured_parser_outcome(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "legacy-unsupported-ps.txt"
    raw.write_text(
        "=== PS ===\nUSER PID ARGS\nroot 424242 /system/bin/init --private-argument\n",
        encoding="utf-8",
    )

    report = normalize_raw_file(
        raw,
        raw_artifact_ref="tests/generated/legacy-unsupported-ps.txt",
        redaction_state="redacted",
    )
    processes = report["process_state"]

    assert processes["capture_status"] == "observed"
    assert processes["source_format"] == "unknown"
    assert processes["completeness"] == "unsupported"
    assert "unsupported_ps_format" in processes["limitations"]
    assert all(
        item["visibility"]["status"] == "not_collected"
        for item in processes["selected_processes"]
    )
    serialized = json.dumps(report)
    assert "424242" not in serialized
    assert "private-argument" not in serialized
    validate_report(report)


@pytest.mark.parametrize(
    ("capture_status", "exit_code", "expected_status"),
    [
        ("not_collected", None, "not_collected"),
        ("inaccessible", 1, "inaccessible"),
        ("command_error", 2, "command_error"),
        ("unsupported", None, "unsupported"),
    ],
)
def test_process_command_status_is_preserved_without_private_diagnostics(
    tmp_path: Path,
    capture_status: str,
    exit_code: int | None,
    expected_status: str,
) -> None:
    report = normalize_manifest(
        tmp_path,
        [
            capture(
                "processes",
                status=capture_status,
                exit_code=exit_code,
                stderr="private-diagnostic-marker",
            )
        ],
        suffix=f"status-{capture_status}",
    )

    process_state = report["process_state"]
    assert process_state["capture_status"] == expected_status
    assert process_state["completeness"] == "unknown"
    assert all(
        item["visibility"]["status"] == expected_status
        for item in process_state["selected_processes"]
    )
    assert "private-diagnostic-marker" not in json.dumps(report)
    validate_report(report)


def test_app_sandbox_process_list_is_explicitly_nonexhaustive(tmp_path: Path) -> None:
    report = normalize_manifest(
        tmp_path,
        [capture("processes", stdout="USER PID NAME\nu0_a123 88 init\n")],
        artifact_kind="app_probe_json",
        observer_type="unprivileged_app",
        suffix="app-sandbox",
    )

    assert report["process_state"]["scope"] == "app_sandbox"
    assert "app_sandbox_visibility" in report["process_state"]["limitations"]
    assert selected(report, "adbd")["visibility"]["status"] == "not_collected"
    validate_report(report)


def test_diff_distinguishes_observed_absence_from_invisibility_without_refs(
    tmp_path: Path,
) -> None:
    absent = full_security_report(tmp_path, suffix="absent")
    invisible = normalize_manifest(
        tmp_path,
        [
            capture(
                "processes",
                status="inaccessible",
                exit_code=1,
                stderr="private-diff-marker",
            )
        ],
        suffix="invisible",
    )

    diff = make_diff(absent, invisible)
    change = next(
        item
        for item in diff["changed_dimensions"]
        if item["dimension"] == "selected_process_visibility"
    )
    assert change["before"][1]["visibility"]["status"] == "observed_absent"
    assert change["after"][1]["visibility"]["status"] == "inaccessible"
    assert "evidence_refs" not in json.dumps(change)
    assert "private-diff-marker" not in json.dumps(diff)
    validate_diff(diff)


def test_semantics_reject_absence_claim_from_filtered_capture(tmp_path: Path) -> None:
    report = normalize_manifest(
        tmp_path,
        [capture("ps_selected", stdout="u:r:init:s0 init\n")],
        suffix="forged-filter",
    )
    forged = copy.deepcopy(report)
    missing = selected(forged, "adbd")
    missing["visibility"] = {
        "status": "observed_absent",
        "value": False,
        "reason": "forged filtered absence",
    }
    missing["context"] = {
        "status": "observed_absent",
        "value": None,
        "reason": "forged filtered absence",
    }
    forged = finalize_report_identity(forged)

    with pytest.raises(SchemaValidationError, match="process absence"):
        validate_report(forged)


def test_semantics_reject_missing_process_scope_limitation(tmp_path: Path) -> None:
    report = normalize_manifest(
        tmp_path,
        [capture("ps_selected", stdout="u:r:init:s0 init\n")],
        suffix="forged-limitations",
    )
    forged = copy.deepcopy(report)
    forged["process_state"]["limitations"] = ["observer_scoped_visibility"]
    forged = finalize_report_identity(forged)

    with pytest.raises(SchemaValidationError, match="limitations"):
        validate_report(forged)


@pytest.mark.parametrize(
    ("capture_name", "source_ref"),
    [
        ("ps_selected", None),
        ("processes", "captures/PS"),
    ],
)
def test_filtered_capture_cannot_be_forged_as_exhaustive(
    tmp_path: Path, capture_name: str, source_ref: str | None
) -> None:
    report = normalize_manifest(
        tmp_path,
        [
            capture(
                capture_name,
                stdout="u:r:init:s0 init\n",
                source_ref=source_ref,
            )
        ],
        suffix=f"forged-filter-scope-{capture_name}",
    )
    forged = copy.deepcopy(report)
    processes = forged["process_state"]
    processes["scope"] = "complete"
    processes["source_format"] = "toolbox"
    processes["limitations"] = ["observer_scoped_visibility"]
    for item in processes["selected_processes"]:
        if item["visibility"]["status"] == "observed":
            continue
        item["visibility"] = {
            "status": "observed_absent",
            "value": False,
            "reason": "forged exhaustive absence",
        }
        item["context"] = {
            "status": "observed_absent",
            "value": None,
            "reason": "forged exhaustive absence",
        }
    forged = finalize_report_identity(forged)

    with pytest.raises(SchemaValidationError, match="filtered process capture"):
        validate_report(forged)


def test_root_level_ps_source_name_does_not_imply_filtered_scope(
    tmp_path: Path,
) -> None:
    report = normalize_manifest(
        tmp_path,
        [
            capture(
                "processes",
                stdout="USER PID NAME\nroot 1 init\n",
                source_ref="PS",
            )
        ],
        suffix="root-level-ps-source",
    )

    assert report["process_state"]["scope"] == "complete"
    assert selected(report, "adbd")["visibility"]["status"] == "observed_absent"
    validate_report(report)


def test_semantics_reject_process_status_that_disagrees_with_capture(
    tmp_path: Path,
) -> None:
    report = normalize_manifest(
        tmp_path,
        [capture("ps_selected", stdout="u:r:init:s0 init\n")],
        suffix="forged-status",
    )
    forged = copy.deepcopy(report)
    process_state = forged["process_state"]
    process_state["capture_status"] = "inaccessible"
    process_state["completeness"] = "unknown"
    process_state["evidence_refs"] = []
    for item in process_state["selected_processes"]:
        item["visibility"] = {
            "status": "inaccessible",
            "value": None,
            "reason": "forged inaccessible capture",
        }
        item["context"] = {
            "status": "inaccessible",
            "value": None,
            "reason": "forged inaccessible capture",
        }
        item["evidence_refs"] = []
    forged = finalize_report_identity(forged)

    with pytest.raises(SchemaValidationError, match="command provenance"):
        validate_report(forged)


def test_semantics_reject_app_scope_forged_as_exhaustive(tmp_path: Path) -> None:
    report = normalize_manifest(
        tmp_path,
        [capture("processes", stdout="USER PID NAME\nu0_a123 88 init\n")],
        artifact_kind="app_probe_json",
        observer_type="unprivileged_app",
        suffix="forged-app-scope",
    )
    forged = copy.deepcopy(report)
    process_state = forged["process_state"]
    process_state["scope"] = "complete"
    process_state["limitations"] = ["observer_scoped_visibility"]
    for item in process_state["selected_processes"]:
        if item["visibility"]["status"] == "observed":
            continue
        item["visibility"] = {
            "status": "observed_absent",
            "value": False,
            "reason": "forged exhaustive app absence",
        }
        item["context"] = {
            "status": "observed_absent",
            "value": None,
            "reason": "forged exhaustive app absence",
        }
    forged = finalize_report_identity(forged)

    with pytest.raises(SchemaValidationError, match="observer boundary"):
        validate_report(forged)


def test_complete_absence_claim_requires_identity_bound_capture_reference(
    tmp_path: Path,
) -> None:
    report = full_security_report(tmp_path, suffix="missing-process-ref")
    forged = copy.deepcopy(report)
    forged["process_state"]["evidence_refs"] = []
    forged = finalize_report_identity(forged)

    with pytest.raises(SchemaValidationError, match="source evidence reference"):
        validate_report(forged)


@pytest.mark.parametrize("forgery", ["capture", "row"])
def test_process_references_must_bind_the_semantic_adapter_capture(
    tmp_path: Path, forgery: str
) -> None:
    report = full_security_report(tmp_path, suffix=f"forged-process-ref-{forgery}")
    forged = copy.deepcopy(report)
    if forgery == "capture":
        forged["process_state"]["evidence_refs"] = ["captures/getenforce.txt"]
    else:
        selected(forged, "init")["evidence_refs"] = ["captures/getenforce.txt"]
    forged = finalize_report_identity(forged)

    with pytest.raises(SchemaValidationError, match="semantic adapter capture"):
        validate_report(forged)


def test_selinux_reference_must_bind_the_semantic_adapter_capture(
    tmp_path: Path,
) -> None:
    report = full_security_report(tmp_path, suffix="forged-selinux-ref")
    forged = copy.deepcopy(report)
    forged["selinux"]["policy_mode"]["evidence_refs"] = ["captures/processes.txt"]
    forged = finalize_report_identity(forged)

    with pytest.raises(SchemaValidationError, match="semantic adapter capture"):
        validate_report(forged)


@pytest.mark.parametrize("capture_name", ["processes", "getenforce"])
def test_observation_requires_its_semantic_adapter_capture(
    tmp_path: Path, capture_name: str
) -> None:
    report = full_security_report(tmp_path, suffix=f"deleted-{capture_name}")
    forged = copy.deepcopy(report)
    adapter = forged["extensions"]["org.androidtrustlab.adapter"]
    adapter["captures"] = [
        capture for capture in adapter["captures"] if capture["name"] != capture_name
    ]
    forged = finalize_report_identity(forged)

    with pytest.raises(SchemaValidationError, match="semantic adapter capture"):
        validate_report(forged)


def test_direct_observed_selinux_evidence_requires_source_reference(
    tmp_path: Path,
) -> None:
    report = full_security_report(tmp_path, suffix="missing-context-ref")
    forged = copy.deepcopy(report)
    forged["selinux"]["current_context"]["evidence_refs"] = []
    forged = finalize_report_identity(forged)

    with pytest.raises(SchemaValidationError, match="current_context"):
        validate_report(forged)


def test_capture_level_reference_removes_caller_controlled_path(tmp_path: Path) -> None:
    report = normalize_manifest(
        tmp_path,
        [
            capture(
                "processes",
                stdout="USER PID NAME\nroot 1 init\n",
                source_ref="captures/process#Lraw.txt",
            )
        ],
        suffix="literal-hash-l-path",
    )

    assert report["process_state"]["evidence_refs"] == ["captures/processes.txt"]
    assert selected(report, "init")["evidence_refs"] == ["captures/processes.txt"]
    assert "process#Lraw" not in str(report)
    validate_report(report)


def test_empty_context_and_denial_capture_keep_distinct_collection_semantics(
    tmp_path: Path,
) -> None:
    report = normalize_manifest(
        tmp_path,
        [
            capture(
                "selinux_context",
                status="empty",
                exit_code=0,
            ),
            capture(
                "selinux_denials",
                status="empty",
                exit_code=0,
            ),
        ],
        suffix="empty-selinux",
    )

    assert report["selinux"]["current_context"]["status"] == "observed_absent"
    assert report["selinux"]["denial_collection"] == {
        "status": "observed",
        "reason": None,
        "evidence_refs": ["captures/selinux_denials.txt"],
    }
    validate_report(report)


def test_selinux_command_outcomes_remain_separate_and_sanitized(tmp_path: Path) -> None:
    report = normalize_manifest(
        tmp_path,
        [
            capture(
                "getenforce",
                status="inaccessible",
                exit_code=1,
                stderr="private-mode-error",
            ),
            capture(
                "selinux_context",
                status="unsupported",
                exit_code=None,
                stderr="private-context-error",
            ),
            capture(
                "selinux_denials",
                status="command_error",
                exit_code=2,
                stderr="private-denial-error",
            ),
        ],
        suffix="selinux-statuses",
    )

    assert report["selinux"]["policy_mode"]["status"] == "inaccessible"
    assert report["selinux"]["current_context"]["status"] == "unsupported"
    assert report["selinux"]["denial_collection"]["status"] == "command_error"
    serialized = json.dumps(report)
    assert "private-mode-error" not in serialized
    assert "private-context-error" not in serialized
    assert "private-denial-error" not in serialized
    validate_report(report)


def test_report_summary_retains_structured_statuses_without_source_details(
    tmp_path: Path,
) -> None:
    report = full_security_report(tmp_path, suffix="summary")

    markdown = report_to_markdown(report)

    assert "SELinux current context: `u:r:untrusted_app:s0`" in markdown
    assert "SELinux denial collection: `observed`" in markdown
    assert (
        "Process capture: `observed` (scope `complete`, completeness `complete`)"
        in (markdown)
    )
    assert "init=observed/u:r:init:s0" in markdown
    assert "adbd=observed_absent/observed_absent" in markdown
    assert "Observer effective UID is root: `not_collected`" in markdown
    assert "su binary visible: `not_collected`" in markdown
    assert "su invocation tested: `not_collected`" in markdown
    assert "Magisk binary visible: `not_collected`" in markdown
    assert "Verified-boot confidence:" in markdown
    assert "evidence_refs" not in markdown
    assert "7654321" not in markdown
