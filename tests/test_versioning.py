from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import zipfile
from email.parser import BytesParser
from pathlib import Path

import pytest

from trustlab import __version__
from trustlab._version import __version__ as source_version

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_version_consistency", ROOT / "tools/check_version_consistency.py"
)
check_version_consistency = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(check_version_consistency)


def test_project_version_is_consistent():
    assert check_version_consistency.main() == 0


@pytest.mark.parametrize(
    "spelling",
    ["0.3.0.dev0", "0.3.0-dev0", "v0.3.0-dev0", "0.3.0-dev.0"],
)
def test_development_version_spellings_are_equivalent(spelling):
    assert check_version_consistency.normalized_version(spelling) == (
        check_version_consistency.normalized_version(source_version)
    )


def test_public_version_reexports_single_source():
    assert __version__ == source_version


def test_checker_rejects_deliberate_module_version_drift(tmp_path):
    relative_paths = [
        "analyzer/pyproject.toml",
        "analyzer/trustlab/_version.py",
        "CITATION.cff",
        "module/trustlab-magisk/module.prop",
        "RELEASE_NOTES_v0.2.0.md",
        "results/artifact_manifest.json",
    ]
    for relative in relative_paths:
        source = ROOT / relative
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    module_prop = tmp_path / "module/trustlab-magisk/module.prop"
    module_prop.write_text(
        module_prop.read_text(encoding="utf-8").replace(
            "version=0.3.0-dev0.installfix.1", "version=0.3.0-dev1"
        ),
        encoding="utf-8",
    )
    errors = check_version_consistency.check_errors(
        tmp_path,
        distribution_version=source_version,
        public_version=source_version,
    )
    assert any("Magisk module version" in error for error in errors)


def test_built_wheel_metadata_uses_single_source(tmp_path):
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(tmp_path),
            str(ROOT / "analyzer"),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list(tmp_path.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        metadata_path = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = BytesParser().parsebytes(archive.read(metadata_path))
    assert check_version_consistency.normalized_version(metadata["Version"]) == (
        check_version_consistency.normalized_version(source_version)
    )
