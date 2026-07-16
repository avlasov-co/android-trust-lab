from __future__ import annotations

import json
import stat

import pytest

from trustlab import report_writer
from trustlab.exceptions import (
    InvalidJSONError,
    OutputWriteError,
    SchemaValidationError,
)


def temporary_siblings(path):
    return list(path.parent.glob(f".{path.name}.*.tmp"))


def test_successful_write_atomically_replaces_in_same_directory(tmp_path, monkeypatch):
    destination = tmp_path / "report.json"
    destination.write_text("sentinel", encoding="utf-8")
    replaced = []
    real_replace = report_writer.os.replace

    def record_replace(source, target):
        replaced.append((source, target))
        real_replace(source, target)

    monkeypatch.setattr(report_writer.os, "replace", record_replace)
    report_writer.write_json({"status": "valid"}, destination)

    assert json.loads(destination.read_text(encoding="utf-8")) == {"status": "valid"}
    assert len(replaced) == 1
    source, target = map(report_writer.Path, replaced[0])
    assert source.parent == destination.parent
    assert target == destination
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert temporary_siblings(destination) == []


def test_replace_failure_preserves_destination_and_removes_temporary_file(
    tmp_path, monkeypatch
):
    destination = tmp_path / "report.json"
    destination.write_bytes(b"sentinel\n")

    def fail_replace(source, target):
        raise OSError("injected replace failure")

    monkeypatch.setattr(report_writer.os, "replace", fail_replace)
    with pytest.raises(OutputWriteError, match="could not write output"):
        report_writer.write_json({"status": "valid"}, destination)

    assert destination.read_bytes() == b"sentinel\n"
    assert temporary_siblings(destination) == []


def test_flush_failure_leaves_no_output_or_partial_file(tmp_path, monkeypatch):
    destination = tmp_path / "report.json"

    def fail_fsync(fd):
        raise OSError("injected fsync failure")

    monkeypatch.setattr(report_writer.os, "fsync", fail_fsync)
    with pytest.raises(OutputWriteError, match="could not write output"):
        report_writer.write_json({"status": "valid"}, destination)

    assert not destination.exists()
    assert temporary_siblings(destination) == []


def test_encoding_failure_is_an_output_write_error_and_removes_temporary_file(
    tmp_path,
):
    destination = tmp_path / "report.json"
    with pytest.raises(OutputWriteError, match="could not write output"):
        report_writer.write_json({"invalid": "\ud800"}, destination)

    assert not destination.exists()
    assert temporary_siblings(destination) == []


def test_serialization_failure_does_not_create_destination_parent(tmp_path):
    destination = tmp_path / "new-parent" / "report.json"
    with pytest.raises(OutputWriteError, match="could not serialize"):
        report_writer.write_json({"invalid": {object()}}, destination)
    assert not destination.parent.exists()


def test_load_json_rejects_invalid_utf8(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(InvalidJSONError, match="invalid UTF-8 JSON"):
        report_writer.load_json(path)


def test_load_json_rejects_non_object(tmp_path):
    path = tmp_path / "array.json"
    path.write_text("[]\n", encoding="utf-8")
    with pytest.raises(SchemaValidationError, match="must be an object"):
        report_writer.load_json(path)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_load_json_rejects_nonstandard_numeric_constants(tmp_path, constant):
    path = tmp_path / "invalid.json"
    path.write_text(f'{{"value": {constant}}}\n', encoding="utf-8")
    with pytest.raises(InvalidJSONError, match="invalid JSON"):
        report_writer.load_json(path)
