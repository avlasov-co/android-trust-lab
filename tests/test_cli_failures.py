from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import traceback
from pathlib import Path

import pytest

from trustlab import cli, normalizer, report_writer
from trustlab.exceptions import (
    CollectionError,
    NormalizationError,
    OutputWriteError,
    SchemaValidationError,
)

ROOT = Path(__file__).resolve().parents[1]
RAW_FIXTURE = ROOT / "tests/fixtures/sample_raw_report.txt"
REPORT_FIXTURE = ROOT / "tests/fixtures/sample_normalized_report.json"


def valid_report():
    return json.loads(REPORT_FIXTURE.read_text(encoding="utf-8"))


def write_document(path, data):
    path.write_text(json.dumps(data) + "\n", encoding="utf-8")


def assert_clean_error(capsys, code, expected_text):
    captured = capsys.readouterr()
    assert code > 0
    assert captured.out == ""
    assert expected_text in captured.err
    assert "Traceback" not in captured.err
    return captured


def test_normalize_validation_failure_preserves_existing_destination(
    tmp_path, monkeypatch, capsys
):
    invalid = valid_report()
    invalid["observer"]["privilege_level"] = "invalid"
    monkeypatch.setattr(cli, "normalize_raw_file", lambda *args, **kwargs: invalid)
    destination = tmp_path / "report.json"
    destination.write_bytes(b"sentinel\n")

    code = cli.main(
        ["normalize", "--input", str(RAW_FIXTURE), "--output", str(destination)]
    )

    assert_clean_error(capsys, code, "schema validation failed")
    assert code == cli.EXIT_SCHEMA_VALIDATION
    assert destination.read_bytes() == b"sentinel\n"
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_invalid_normalized_model_creates_no_destination_parent(
    tmp_path, monkeypatch, capsys
):
    invalid = valid_report()
    invalid.pop("target")
    monkeypatch.setattr(cli, "normalize_raw_file", lambda *args, **kwargs: invalid)
    destination = tmp_path / "new-parent" / "report.json"

    code = cli.main(
        ["normalize", "--input", str(RAW_FIXTURE), "--output", str(destination)]
    )

    assert_clean_error(capsys, code, "schema validation failed")
    assert code == cli.EXIT_SCHEMA_VALIDATION
    assert not destination.parent.exists()


def test_no_validate_still_enforces_portable_privacy_gate(
    tmp_path, monkeypatch, capsys
):
    unsafe = valid_report()
    unsafe["target"]["model"]["value"] = "alice@example.com"
    monkeypatch.setattr(cli, "normalize_raw_file", lambda *args, **kwargs: unsafe)
    destination = tmp_path / "report.json"

    code = cli.main(
        [
            "normalize",
            "--input",
            str(RAW_FIXTURE),
            "--output",
            str(destination),
            "--no-validate",
        ]
    )

    assert_clean_error(capsys, code, "portable privacy validation")
    assert code == cli.EXIT_SCHEMA_VALIDATION
    assert not destination.exists()


@pytest.mark.parametrize("no_validate", [False, True])
def test_normalize_refuses_to_replace_its_input(tmp_path, capsys, no_validate):
    raw = tmp_path / "raw.txt"
    original = RAW_FIXTURE.read_bytes()
    raw.write_bytes(original)
    arguments = ["normalize", "--input", str(raw), "--output", str(raw)]
    if no_validate:
        arguments.append("--no-validate")

    code = cli.main(arguments)

    assert_clean_error(capsys, code, "output must not replace an input artifact")
    assert code == cli.EXIT_OUTPUT_WRITE_FAILURE
    assert raw.read_bytes() == original


def test_normalize_refuses_symlink_alias_of_input(tmp_path, capsys):
    raw = tmp_path / "raw.txt"
    raw.write_bytes(RAW_FIXTURE.read_bytes())
    alias = tmp_path / "report.json"
    alias.symlink_to(raw)

    code = cli.main(["normalize", "--input", str(raw), "--output", str(alias)])

    assert_clean_error(capsys, code, "output must not replace an input artifact")
    assert code == cli.EXIT_OUTPUT_WRITE_FAILURE
    assert alias.is_symlink()
    assert raw.read_bytes() == RAW_FIXTURE.read_bytes()


@pytest.mark.parametrize("invalid_side", ["base", "compare"])
def test_diff_validates_both_inputs_and_preserves_destination(
    tmp_path, capsys, invalid_side
):
    base = valid_report()
    compare = copy.deepcopy(base)
    if invalid_side == "base":
        base.pop("target")
    else:
        compare.pop("target")
    base_path = tmp_path / "base.json"
    compare_path = tmp_path / "compare.json"
    write_document(base_path, base)
    write_document(compare_path, compare)
    destination = tmp_path / "diff.json"
    destination.write_bytes(b"sentinel\n")

    code = cli.main(
        [
            "diff",
            "--base",
            str(base_path),
            "--compare",
            str(compare_path),
            "--output",
            str(destination),
        ]
    )

    assert_clean_error(capsys, code, "report schema validation failed")
    assert code == cli.EXIT_SCHEMA_VALIDATION
    assert destination.read_bytes() == b"sentinel\n"
    assert list(tmp_path.glob(".diff.json.*.tmp")) == []


def test_diff_rejects_unsupported_input_schema_version(tmp_path, capsys):
    base = valid_report()
    base["schema_version"] = "999.0.0"
    base_path = tmp_path / "base.json"
    compare_path = tmp_path / "compare.json"
    write_document(base_path, base)
    write_document(compare_path, valid_report())
    destination = tmp_path / "diff.json"
    destination.write_bytes(b"sentinel\n")

    code = cli.main(
        [
            "diff",
            "--base",
            str(base_path),
            "--compare",
            str(compare_path),
            "--output",
            str(destination),
        ]
    )

    assert_clean_error(capsys, code, "unsupported report schema version")
    assert code == cli.EXIT_UNSUPPORTED_SCHEMA
    assert destination.read_bytes() == b"sentinel\n"


@pytest.mark.parametrize("output_side", ["base", "compare"])
def test_diff_refuses_to_replace_an_input(tmp_path, capsys, output_side):
    base_path = tmp_path / "base.json"
    compare_path = tmp_path / "compare.json"
    write_document(base_path, valid_report())
    write_document(compare_path, valid_report())
    output = base_path if output_side == "base" else compare_path
    original = output.read_bytes()

    code = cli.main(
        [
            "diff",
            "--base",
            str(base_path),
            "--compare",
            str(compare_path),
            "--output",
            str(output),
        ]
    )

    assert_clean_error(capsys, code, "output must not replace an input artifact")
    assert code == cli.EXIT_OUTPUT_WRITE_FAILURE
    assert output.read_bytes() == original


def test_project_error_text_cannot_forge_stderr_lines(tmp_path, capsys):
    report = valid_report()
    report["schema_version"] = "999\nforged-line"
    path = tmp_path / "report.json"
    write_document(path, report)

    code = cli.main(["validate-report", str(path)])

    captured = assert_clean_error(capsys, code, "unsupported report schema version")
    assert code == cli.EXIT_UNSUPPORTED_SCHEMA
    assert captured.out == ""
    assert captured.err == "error: unsupported report schema version\n"


def test_project_error_text_escapes_unencodable_characters(monkeypatch, capsys):
    def fail_normalize(*args, **kwargs):
        raise NormalizationError("bad\n\ud800")

    monkeypatch.setattr(cli, "normalize_raw_file", fail_normalize)
    code = cli.main(
        ["normalize", "--input", str(RAW_FIXTURE), "--output", "report.json"]
    )

    captured = assert_clean_error(capsys, code, r"bad \ud800")
    assert code == cli.EXIT_NORMALIZATION_FAILURE
    assert captured.err == "error: bad \\ud800\n"


def test_diff_noncanonical_evidence_is_clean_and_preserves_destination(
    tmp_path, capsys
):
    base = valid_report()
    compare = copy.deepcopy(base)
    compare["properties"]["security"]["value"]["ro.secure"] = "\ud800"
    base_path = tmp_path / "base.json"
    compare_path = tmp_path / "compare.json"
    write_document(base_path, base)
    write_document(compare_path, compare)
    destination = tmp_path / "diff.json"
    destination.write_bytes(b"sentinel\n")

    code = cli.main(
        [
            "diff",
            "--base",
            str(base_path),
            "--compare",
            str(compare_path),
            "--output",
            str(destination),
        ]
    )

    assert_clean_error(
        capsys, code, "report is outside the bounded canonical JSON model"
    )
    assert code == cli.EXIT_SCHEMA_VALIDATION
    assert destination.read_bytes() == b"sentinel\n"
    assert list(tmp_path.glob(".diff.json.*.tmp")) == []


def test_invalid_generated_diff_preserves_destination(tmp_path, monkeypatch, capsys):
    base_path = tmp_path / "base.json"
    compare_path = tmp_path / "compare.json"
    write_document(base_path, valid_report())
    write_document(compare_path, valid_report())
    monkeypatch.setattr(
        cli, "make_diff", lambda *args, **kwargs: {"schema_version": "1.0.0"}
    )
    destination = tmp_path / "diff.json"
    destination.write_bytes(b"sentinel\n")

    code = cli.main(
        [
            "diff",
            "--base",
            str(base_path),
            "--compare",
            str(compare_path),
            "--output",
            str(destination),
        ]
    )

    assert_clean_error(capsys, code, "diff schema validation failed")
    assert code == cli.EXIT_SCHEMA_VALIDATION
    assert destination.read_bytes() == b"sentinel\n"


def test_invalid_json_has_stable_exit_code_and_no_traceback(tmp_path, capsys):
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{\n", encoding="utf-8")
    code = cli.main(["validate-report", str(invalid)])
    assert_clean_error(capsys, code, "invalid JSON: invalid.json")
    assert code == cli.EXIT_INVALID_JSON


def test_missing_file_has_stable_exit_code_and_no_traceback(tmp_path, capsys):
    code = cli.main(["validate-report", str(tmp_path / "missing.json")])
    assert_clean_error(capsys, code, "input file not found: missing.json")
    assert code == cli.EXIT_MISSING_FILE


def test_normalize_missing_raw_file_uses_missing_exit_code(tmp_path, capsys):
    output = tmp_path / "report.json"
    code = cli.main(
        ["normalize", "--input", str(tmp_path / "missing.raw"), "--output", str(output)]
    )
    assert_clean_error(capsys, code, "input file not found: missing.raw")
    assert code == cli.EXIT_MISSING_FILE
    assert not output.exists()


def test_normalize_invalid_utf8_uses_collection_exit_code(tmp_path, capsys):
    raw = tmp_path / "invalid.raw"
    raw.write_bytes(b"\xff\xfe")
    output = tmp_path / "report.json"
    code = cli.main(["normalize", "--input", str(raw), "--output", str(output)])
    assert_clean_error(capsys, code, "input artifact is not valid UTF-8")
    assert code == cli.EXIT_COLLECTION_FAILURE
    assert not output.exists()


def test_normalize_parser_failure_uses_normalization_exit_code(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(
        normalizer,
        "parse_artifact_text",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            ValueError("injected parser failure")
        ),
    )
    output = tmp_path / "report.json"
    code = cli.main(["normalize", "--input", str(RAW_FIXTURE), "--output", str(output)])
    assert_clean_error(capsys, code, "could not normalize input artifact")
    assert code == cli.EXIT_NORMALIZATION_FAILURE
    assert not output.exists()


def test_windows_input_path_does_not_leak_host_directories(capsys):
    windows_path = "\\".join(
        ["C:", "Users", "PrivateAccount", "reports", "missing.json"]
    )
    code = cli.main(["validate-report", windows_path])
    captured = assert_clean_error(capsys, code, "input file not found: missing.json")
    assert code == cli.EXIT_MISSING_FILE
    assert "PrivateAccount" not in captured.err
    assert "Users" not in captured.err


@pytest.mark.parametrize("nested", [False, True])
def test_validate_report_rejects_duplicate_json_members(tmp_path, capsys, nested):
    payload = json.dumps(valid_report())
    if nested:
        payload = payload.replace(
            '"observer": {',
            '"observer": {"observer_type": "adb_shell", ',
            1,
        )
    else:
        payload = '{"schema_version": "3.0.0", ' + payload[1:]
    source = tmp_path / "duplicate.json"
    source.write_text(payload, encoding="utf-8")

    code = cli.main(["validate-report", str(source)])

    assert_clean_error(capsys, code, "invalid JSON")
    assert code == cli.EXIT_INVALID_JSON


def test_migrate_and_diff_reject_duplicate_json_before_output(tmp_path, capsys):
    v1_text = (ROOT / "tests/fixtures/report_v1_historical.json").read_text(
        encoding="utf-8"
    )
    duplicate_v1 = tmp_path / "duplicate-v1.json"
    duplicate_v1.write_text(
        '{"schema_version": "1.0.0", ' + v1_text.lstrip()[1:],
        encoding="utf-8",
    )
    output = tmp_path / "output.json"
    code = cli.main(
        [
            "migrate-report",
            "--input",
            str(duplicate_v1),
            "--output",
            str(output),
        ]
    )
    assert_clean_error(capsys, code, "invalid JSON")
    assert code == cli.EXIT_INVALID_JSON
    assert not output.exists()

    duplicate_report = tmp_path / "duplicate-report.json"
    duplicate_report.write_text(
        '{"schema_version": "3.0.0", '
        + REPORT_FIXTURE.read_text(encoding="utf-8").lstrip()[1:],
        encoding="utf-8",
    )
    code = cli.main(
        [
            "diff",
            "--base",
            str(duplicate_report),
            "--compare",
            str(REPORT_FIXTURE),
            "--output",
            str(output),
        ]
    )
    assert_clean_error(capsys, code, "invalid JSON")
    assert code == cli.EXIT_INVALID_JSON
    assert not output.exists()


def test_validate_report_nesting_limit_is_a_clean_schema_failure(tmp_path, capsys):
    report = valid_report()
    nested: object = None
    for _ in range(70):
        nested = {"value": nested}
    report["extensions"] = {"org.example.nested": {"value": nested}}
    source = tmp_path / "nested.json"
    write_document(source, report)

    code = cli.main(["validate-report", str(source)])

    assert_clean_error(capsys, code, "bounded canonical JSON model")
    assert code == cli.EXIT_SCHEMA_VALIDATION


def test_collection_failure_has_stable_exit_code(monkeypatch, capsys):
    def fail_read(*args, **kwargs):
        raise CollectionError("could not read input: private.json")

    monkeypatch.setattr(report_writer, "read_bounded_regular_file", fail_read)
    code = cli.main(["validate-report", "private.json"])
    assert_clean_error(capsys, code, "could not read input: private.json")
    assert code == cli.EXIT_COLLECTION_FAILURE


def test_cli_rejects_over_limit_json_before_parsing(tmp_path, monkeypatch, capsys):
    source = tmp_path / "large.json"
    source.write_bytes(b"{" + (b" " * 8) + b"}")
    monkeypatch.setattr(report_writer, "MAX_JSON_INPUT_BYTES", 8)

    code = cli.main(["validate-report", str(source)])

    assert_clean_error(capsys, code, "JSON input exceeds the byte limit")
    assert code == cli.EXIT_COLLECTION_FAILURE


def test_cli_rejects_over_limit_raw_before_normalizing(tmp_path, monkeypatch, capsys):
    source = tmp_path / "large.txt"
    source.write_bytes(b"x" * 9)
    output = tmp_path / "report.json"
    monkeypatch.setattr(normalizer, "MAX_RAW_ARTIFACT_BYTES", 8)

    code = cli.main(["normalize", "--input", str(source), "--output", str(output)])

    assert_clean_error(capsys, code, "raw input artifact exceeds the byte limit")
    assert code == cli.EXIT_COLLECTION_FAILURE
    assert not output.exists()


def test_normalization_failure_has_stable_exit_code(tmp_path, monkeypatch, capsys):
    def fail_normalize(*args, **kwargs):
        raise NormalizationError("normalization failed safely")

    monkeypatch.setattr(cli, "normalize_raw_file", fail_normalize)
    destination = tmp_path / "report.json"
    code = cli.main(
        ["normalize", "--input", str(RAW_FIXTURE), "--output", str(destination)]
    )
    assert_clean_error(capsys, code, "normalization failed safely")
    assert code == cli.EXIT_NORMALIZATION_FAILURE
    assert not destination.exists()


def test_output_write_failure_has_stable_exit_code(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "write_json",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            OutputWriteError("write failed safely")
        ),
    )
    destination = tmp_path / "report.json"
    code = cli.main(
        ["normalize", "--input", str(RAW_FIXTURE), "--output", str(destination)]
    )
    assert_clean_error(capsys, code, "write failed safely")
    assert code == cli.EXIT_OUTPUT_WRITE_FAILURE
    assert not destination.exists()


def test_debug_reraises_expected_error(tmp_path):
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{\n", encoding="utf-8")
    with pytest.raises(cli.InvalidJSONError):
        cli.main(["--debug", "validate-report", str(invalid)])


def test_debug_traceback_keeps_rejected_schema_values_private(tmp_path):
    report = valid_report()
    sensitive_value = "private-rejected-device-value"
    report["observer"]["privilege_level"] = sensitive_value
    invalid = tmp_path / "invalid.json"
    write_document(invalid, report)

    with pytest.raises(SchemaValidationError) as caught:
        cli.main(["--debug", "validate-report", str(invalid)])

    rendered = "".join(traceback.format_exception(caught.type, caught.value, caught.tb))
    assert sensitive_value not in rendered
    assert "value is not permitted" in rendered


def test_unexpected_error_is_sanitized_without_debug(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_json", lambda *args, **kwargs: 1 / 0)
    code = cli.main(["validate-report", "report.json"])
    assert_clean_error(capsys, code, "internal project failure")
    assert code == cli.EXIT_INTERNAL_ERROR


def test_debug_reraises_unexpected_error(monkeypatch):
    monkeypatch.setattr(cli, "load_json", lambda *args, **kwargs: 1 / 0)
    with pytest.raises(ZeroDivisionError):
        cli.main(["--debug", "validate-report", "report.json"])


def test_summarize_rejects_unrecognized_json_object(tmp_path, capsys):
    unknown = tmp_path / "unknown.json"
    unknown.write_text("{}\n", encoding="utf-8")
    code = cli.main(["summarize", str(unknown)])
    assert_clean_error(capsys, code, "unrecognized JSON artifact")
    assert code == cli.EXIT_SCHEMA_VALIDATION


def test_no_validate_is_visibly_dangerous_and_diff_has_no_bypass(capsys):
    with pytest.raises(SystemExit) as normalize_help:
        cli.build_parser().parse_args(["normalize", "--help"])
    assert normalize_help.value.code == 0
    assert "DANGEROUS" in capsys.readouterr().out

    with pytest.raises(SystemExit) as diff_help:
        cli.build_parser().parse_args(["diff", "--help"])
    assert diff_help.value.code == 0
    assert "--no-validate" not in capsys.readouterr().out


def test_compatibility_wrapper_propagates_expected_exit_code(tmp_path):
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "analyzer")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "analyzer/cli.py"),
            "validate-report",
            str(tmp_path / "missing.json"),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == cli.EXIT_MISSING_FILE
    assert result.stdout == ""
    assert result.stderr == "error: input file not found: missing.json\n"


def test_non_ascii_output_path_cannot_fail_after_publish(tmp_path):
    output = tmp_path / "réport.json"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "analyzer")
    environment["PYTHONIOENCODING"] = "ascii"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "trustlab.cli",
            "normalize",
            "--input",
            str(RAW_FIXTURE),
            "--output",
            str(output),
            "--collection-timestamp",
            "2026-07-16T00:00:00Z",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    assert output.is_file()


def test_closed_stdout_cannot_fail_after_publish(tmp_path):
    output = tmp_path / "report.json"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "analyzer")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "trustlab.cli",
            "normalize",
            "--input",
            str(RAW_FIXTURE),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    process.stdout.close()
    stderr = process.stderr.read()
    code = process.wait()
    assert code == 0
    assert stderr == b""
    assert output.is_file()
