from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from io import BytesIO
from pathlib import Path

from trustlab.normalizer import normalize_collection_manifest
from trustlab.validators import validate_report

ROOT = Path(__file__).resolve().parents[1]
EXPORT_FIXTURE = ROOT / "tests/fixtures/app_probe_v2_export.zip.b64"
BUNDLE_FIXTURE = ROOT / "tests/fixtures/app_probe_v2_bundle"
EXPECTED_ENTRIES = (
    "SHA256SUMS.txt",
    "app_probe.json",
    "export_metadata.json",
    "manifest.json",
)


def export_bytes() -> bytes:
    encoded = "".join(EXPORT_FIXTURE.read_text(encoding="ascii").split())
    payload = base64.b64decode(encoded, validate=True)
    assert base64.b64encode(payload).decode("ascii") == encoded
    return payload


def test_canonical_app_export_is_flat_bounded_and_fully_checksum_bound() -> None:
    payload = export_bytes()
    assert 0 < len(payload) <= 4 * 1024 * 1024

    with zipfile.ZipFile(BytesIO(payload)) as archive:
        entries = archive.infolist()
        assert tuple(entry.filename for entry in entries) == EXPECTED_ENTRIES
        assert all(not entry.is_dir() for entry in entries)
        assert all(
            "/" not in entry.filename and "\\" not in entry.filename
            for entry in entries
        )
        assert all(entry.file_size <= 4 * 1024 * 1024 for entry in entries)
        files = {entry.filename: archive.read(entry) for entry in entries}

    sums = {}
    for line in files["SHA256SUMS.txt"].decode("ascii").splitlines():
        digest, name = line.split("  ", maxsplit=1)
        sums[name] = digest
    assert sums == {
        name: hashlib.sha256(files[name]).hexdigest()
        for name in ("app_probe.json", "manifest.json", "export_metadata.json")
    }

    metadata = json.loads(files["export_metadata.json"])
    assert metadata == {
        "app_probe_schema_version": "2.0.0",
        "app_version": "0.3.0-dev0",
        "artifact_sha256": sums["app_probe.json"],
        "collection_id": "atlcol-0001020304050607",
        "completion_status": "complete",
        "ended_at": "2026-07-16T10:00:01Z",
        "export_format": "android-trust-lab-app-export-v1",
        "manifest_schema_version": "1.0.0",
        "manifest_sha256": sums["manifest.json"],
        "started_at": "2026-07-16T10:00:00Z",
    }


def test_canonical_app_export_validates_and_normalizes_through_python(
    tmp_path: Path,
) -> None:
    with zipfile.ZipFile(BytesIO(export_bytes())) as archive:
        artifact = archive.read("app_probe.json")
        manifest = archive.read("manifest.json")

    assert artifact == (BUNDLE_FIXTURE / "app_probe.json").read_bytes()
    assert manifest == (BUNDLE_FIXTURE / "manifest.json").read_bytes()
    (tmp_path / "app_probe.json").write_bytes(artifact)
    (tmp_path / "manifest.json").write_bytes(manifest)

    report = normalize_collection_manifest(tmp_path / "manifest.json")
    validate_report(report)
    assert report["observer"]["observer_type"] == "unprivileged_app"
    assert report["extensions"]["org.androidtrustlab.app-probe"]["status"] == "observed"
    assert report["target"]["sdk"]["value"] == "37"
