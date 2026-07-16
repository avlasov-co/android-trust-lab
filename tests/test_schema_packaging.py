from __future__ import annotations

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
    (shadow / "trust_report.schema.json").write_text(
        '{"type":"object"}\n', encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert load_schema("trust_report.schema.json")["$id"].startswith(
        "https://github.com/avlasov-co/android-trust-lab/"
    )


def test_schema_compatibility_copies_match_packaged_resources():
    schema_consistency.check_schema_directories(CANONICAL, COMPATIBILITY)


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


def _installed_smoke(python, *, purelib, report, diff, cwd):
    smoke = (
        "from pathlib import Path;"
        "import trustlab;"
        "from trustlab.report_writer import load_json;"
        "from trustlab.validators import validate_report,validate_diff;"
        "validate_report(load_json(__import__('sys').argv[1]));"
        "validate_diff(load_json(__import__('sys').argv[2]));"
        "print(Path(trustlab.__file__).resolve())"
    )
    result = _run(
        [str(python), "-c", smoke, str(report), str(diff)],
        cwd=cwd,
    )
    assert Path(result.stdout.strip()).is_relative_to(purelib)
    entry_point = python.parent / ("trustlab.exe" if os.name == "nt" else "trustlab")
    help_result = _run([str(entry_point), "--help"], cwd=cwd)
    assert "Android Trust Lab analyzer" in help_result.stdout


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
        "trustlab/schemas/trust_report.schema.json",
        "trustlab/schemas/trust_diff.schema.json",
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
        assert "Requires-Dist: tomli" not in metadata
    with tarfile.open(sdist, "r:gz") as archive:
        names = {"/".join(name.split("/")[1:]) for name in archive.getnames()}
        assert expected <= names

    report = tmp_path / "report.json"
    diff = tmp_path / "diff.json"
    report.write_bytes(
        (ROOT / "tests/fixtures/sample_normalized_report.json").read_bytes()
    )
    diff.write_bytes((ROOT / "tests/fixtures/sample_diff.json").read_bytes())
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
        diff=diff,
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
        diff=diff,
        cwd=tmp_path,
    )

    zip_smoke = (
        "import sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "import trustlab;"
        "from trustlab.report_writer import load_json;"
        "from trustlab.validators import validate_report,validate_diff;"
        "validate_report(load_json(sys.argv[2]));"
        "validate_diff(load_json(sys.argv[3]));"
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
        ],
        cwd=tmp_path,
    )
    assert ".whl/trustlab/__init__.py" in zip_result.stdout.replace("\\", "/")
