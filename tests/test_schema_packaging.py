from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from trustlab.validators import load_schema

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "analyzer/trustlab/schemas"
COMPATIBILITY = ROOT / "collector/schema"

SPEC = importlib.util.spec_from_file_location(
    "check_schema_consistency", ROOT / "tools/check_schema_consistency.py"
)
schema_consistency = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(schema_consistency)


def test_validator_loads_packaged_resource_not_cwd_shadow(tmp_path, monkeypatch):
    shadow = tmp_path / "collector/schema"
    shadow.mkdir(parents=True)
    (shadow / "trust_report_v2_0_0.schema.json").write_text(
        '{"type":"object"}\n', encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert load_schema("trust_report_v2_0_0.schema.json")["$id"].startswith(
        "https://github.com/avlasov-co/android-trust-lab/"
    )


def test_schema_compatibility_copies_match_packaged_resources():
    schema_consistency.check_schema_directories(CANONICAL, COMPATIBILITY)


def test_frozen_v1_report_schema_has_reviewed_literal_digest():
    expected = (
        "a75f1ad4e4785a750f3545458aa39a84"  # pragma: allowlist secret
        "d8d955b1995298b7f98d0815c2eb669e"  # pragma: allowlist secret
    )
    for schema in (
        CANONICAL / "trust_report_v1_0_0.schema.json",
        COMPATIBILITY / "trust_report_v1_0_0.schema.json",
    ):
        assert hashlib.sha256(schema.read_bytes()).hexdigest() == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (
            "trust_report_v2_0_0.schema.json",
            "15ec46f78ee0807d52971e6c85480a4e79ad207b4db6fd43d6f51e27da4e8d69",  # pragma: allowlist secret
        ),
        (
            "trust_diff.schema.json",
            "ccf5690ea4a57a23753a5243659bc679bdbdeb45ad44285144f74a0f044f5685",  # pragma: allowlist secret
        ),
    ],
)
def test_frozen_legacy_schema_has_reviewed_literal_digest(name, expected):
    for schema in (CANONICAL / name, COMPATIBILITY / name):
        assert hashlib.sha256(schema.read_bytes()).hexdigest() == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (
            "report_v2_historical.json",
            "94071f0fe2b12f1a80f0a353c641cfa167b82fd65831727c56754b60f6e93fae",  # pragma: allowlist secret
        ),
        (
            "diff_v1_historical.json",
            "87034810c7d837ca695b71b018ebf670dbf3ce3be33c329699174c67fe11a1b0",  # pragma: allowlist secret
        ),
    ],
)
def test_frozen_legacy_fixture_has_reviewed_literal_digest(name, expected):
    fixture = ROOT / "tests/fixtures" / name
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == expected


def test_schema_consistency_detects_byte_drift(tmp_path):
    canonical = tmp_path / "canonical"
    compatibility = tmp_path / "compatibility"
    canonical.mkdir()
    compatibility.mkdir()
    (canonical / "example.schema.json").write_bytes(b"{}\n")
    (compatibility / "example.schema.json").write_bytes(b"{ }\n")
    with pytest.raises(ValueError, match="schema copies drifted"):
        schema_consistency.check_schema_directories(canonical, compatibility)


def _run(command, *, cwd, environment=None):
    if environment is None:
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=True,
        text=True,
        capture_output=True,
        timeout=180,
    )


DEPENDENCY_PROJECTS = (
    "attrs",
    "jsonschema",
    "jsonschema-specifications",
    "packaging",
    "referencing",
    "rpds-py",
    "setuptools",
    "typing-extensions",
    "wheel",
)


def _offline_wheelhouse(path):
    path.mkdir()
    source_root = path.parent / "dependency-sources"
    source_root.mkdir()
    for project in DEPENDENCY_PROJECTS:
        try:
            distribution = importlib.metadata.distribution(project)
        except importlib.metadata.PackageNotFoundError:
            continue
        source = source_root / project
        source.mkdir()
        for entry in distribution.files or ():
            relative = Path(str(entry))
            if relative.is_absolute() or ".." in relative.parts:
                continue
            located = Path(distribution.locate_file(entry))
            destination = source / relative
            if located.is_file():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(located, destination)
        _run(
            [
                sys.executable,
                "-m",
                "wheel",
                "pack",
                str(source),
                "--dest-dir",
                str(path),
            ],
            cwd=path.parent,
        )
    return path


def _create_clean_environment(environment_dir, *, cwd):
    _run(
        [sys.executable, "-m", "venv", str(environment_dir)],
        cwd=cwd,
    )
    python = environment_dir / (
        "Scripts/python.exe" if os.name == "nt" else "bin/python"
    )
    purelib = Path(
        _run(
            [
                str(python),
                "-c",
                "import sysconfig; print(sysconfig.get_paths()['purelib'])",
            ],
            cwd=cwd,
        ).stdout.strip()
    )
    return python, purelib


def _installed_smoke(
    python, *, purelib, report, v1_report, diff, manifest, dataset_manifest, cwd
):
    smoke = (
        "from pathlib import Path;"
        "import trustlab;"
        "from trustlab.migrations import migrate_report_v1_to_v2;"
        "from trustlab.report_writer import load_json;"
        "from trustlab.validators import validate_collection_manifest,validate_dataset_manifest,validate_dataset_source,validate_report,validate_diff;"
        "from trustlab.dataset_manifest import verify_dataset_manifest;"
        "validate_report(load_json(__import__('sys').argv[1]));"
        "validate_diff(load_json(__import__('sys').argv[2]));"
        "validate_report(migrate_report_v1_to_v2(load_json(__import__('sys').argv[3])));"
        "validate_collection_manifest(load_json(__import__('sys').argv[4]));"
        "validate_dataset_manifest(load_json(__import__('sys').argv[5]));"
        "validate_dataset_source(load_json(Path(__import__('sys').argv[5]).with_name('source.json')));"
        "verify_dataset_manifest(__import__('sys').argv[5]);"
        "print(Path(trustlab.__file__).resolve())"
    )
    result = _run(
        [
            str(python),
            "-c",
            smoke,
            str(report),
            str(diff),
            str(v1_report),
            str(manifest),
            str(dataset_manifest),
        ],
        cwd=cwd,
    )
    assert Path(result.stdout.strip()).is_relative_to(purelib)
    entry_point = python.parent / ("trustlab.exe" if os.name == "nt" else "trustlab")
    help_result = _run([str(entry_point), "--help"], cwd=cwd)
    assert "Android Trust Lab analyzer" in help_result.stdout
    dataset_result = _run(
        [str(entry_point), "dataset", "verify", str(dataset_manifest)], cwd=cwd
    )
    assert dataset_result.stdout == "dataset verified\n"


def test_wheel_and_sdist_validate_from_outside_checkout(tmp_path):
    dist = tmp_path / "dist"
    source = tmp_path / "source"
    shutil.copytree(
        ROOT / "analyzer",
        source,
        ignore=shutil.ignore_patterns(
            "build", "dist", "*.egg-info", "__pycache__", "*.pyc"
        ),
    )
    _run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--sdist",
            "--outdir",
            str(dist),
            str(source),
        ],
        cwd=tmp_path,
    )
    wheel = next(dist.glob("*.whl"))
    sdist = next(dist.glob("*.tar.gz"))
    expected = {
        "trustlab/schemas/collection_manifest_v1_0_0.schema.json",
        "trustlab/schemas/dataset_manifest_v1_0_0.schema.json",
        "trustlab/schemas/dataset_manifest_v2_0_0.schema.json",
        "trustlab/schemas/dataset_source_v1_0_0.schema.json",
        "trustlab/schemas/trust_report_v1_0_0.schema.json",
        "trustlab/schemas/trust_report_v2_0_0.schema.json",
        "trustlab/schemas/trust_report_v3_0_0.schema.json",
        "trustlab/schemas/trust_diff.schema.json",
        "trustlab/schemas/trust_diff_v2_0_0.schema.json",
    }
    with zipfile.ZipFile(wheel) as archive:
        assert expected <= set(archive.namelist())
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = archive.read(metadata_name).decode("utf-8")
        assert "Requires-Python: >=3.11\n" in metadata
        for version in ("3.11", "3.12", "3.13", "3.14"):
            assert (
                f"Classifier: Programming Language :: Python :: {version}\n" in metadata
            )
        assert "Classifier: Operating System :: POSIX\n" in metadata
        assert "Classifier: Operating System :: OS Independent\n" not in metadata
        assert "Requires-Dist: tomli" not in metadata
    with tarfile.open(sdist, "r:gz") as archive:
        names = {"/".join(name.split("/")[1:]) for name in archive.getnames()}
        assert expected <= names

    report = tmp_path / "report.json"
    diff = tmp_path / "diff.json"
    v1_report = tmp_path / "v1-report.json"
    manifest = tmp_path / "collection-manifest.json"
    report.write_bytes(
        (ROOT / "tests/fixtures/sample_normalized_report.json").read_bytes()
    )
    diff.write_bytes((ROOT / "tests/fixtures/sample_diff.json").read_bytes())
    v1_report.write_bytes(
        (ROOT / "tests/fixtures/report_v1_historical.json").read_bytes()
    )
    manifest.write_bytes(
        (
            ROOT / "datasets/samples/magisk_collector/collector_manifest_sample.json"
        ).read_bytes()
    )
    dataset_bundle = tmp_path / "dataset-bundle"
    shutil.copytree(ROOT / "datasets", dataset_bundle)
    dataset_manifest = dataset_bundle / "manifest.json"
    wheelhouse = _offline_wheelhouse(tmp_path / "wheelhouse")
    wheel_python, wheel_purelib = _create_clean_environment(
        tmp_path / "wheel-env", cwd=tmp_path
    )
    _run(
        [
            str(wheel_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            str(wheel),
        ],
        cwd=tmp_path,
    )
    _installed_smoke(
        wheel_python,
        purelib=wheel_purelib,
        report=report,
        v1_report=v1_report,
        diff=diff,
        manifest=manifest,
        dataset_manifest=dataset_manifest,
        cwd=tmp_path,
    )

    sdist_python, sdist_purelib = _create_clean_environment(
        tmp_path / "sdist-env", cwd=tmp_path
    )
    _run(
        [
            str(sdist_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "setuptools>=68",
            "wheel",
        ],
        cwd=tmp_path,
    )
    _run(
        [
            str(sdist_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-build-isolation",
            "--find-links",
            str(wheelhouse),
            str(sdist),
        ],
        cwd=tmp_path,
    )
    _installed_smoke(
        sdist_python,
        purelib=sdist_purelib,
        report=report,
        v1_report=v1_report,
        diff=diff,
        manifest=manifest,
        dataset_manifest=dataset_manifest,
        cwd=tmp_path,
    )

    zip_smoke = (
        "import sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "import trustlab;"
        "from trustlab.migrations import migrate_report_v1_to_v2;"
        "from trustlab.report_writer import load_json;"
        "from trustlab.validators import validate_collection_manifest,validate_dataset_manifest,validate_dataset_source,validate_report,validate_diff;"
        "from trustlab.dataset_manifest import verify_dataset_manifest;"
        "validate_report(load_json(sys.argv[2]));"
        "validate_diff(load_json(sys.argv[3]));"
        "validate_report(migrate_report_v1_to_v2(load_json(sys.argv[4])));"
        "validate_collection_manifest(load_json(sys.argv[5]));"
        "validate_dataset_manifest(load_json(sys.argv[6]));"
        "validate_dataset_source(load_json(__import__('pathlib').Path(sys.argv[6]).with_name('source.json')));"
        "verify_dataset_manifest(sys.argv[6]);"
        "print(trustlab.__file__)"
    )
    zip_result = _run(
        [
            sys.executable,
            "-I",
            "-c",
            zip_smoke,
            str(wheel),
            str(report),
            str(diff),
            str(v1_report),
            str(manifest),
            str(dataset_manifest),
        ],
        cwd=tmp_path,
    )
    assert ".whl/trustlab/__init__.py" in zip_result.stdout.replace("\\", "/")
