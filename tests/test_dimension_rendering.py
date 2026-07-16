from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from pathlib import Path

from trustlab.dimension_registry import (
    TRUST_DIMENSION_DEFINITIONS,
    TRUST_DIMENSIONS_BY_ID,
)
from trustlab.dimension_rendering import (
    MATRIX_DIMENSIONS,
    RENDERER_LOOKUP,
    dimension_label,
    registry_markdown,
    render_dimension,
)
from trustlab.report_writer import diff_to_markdown, report_to_markdown

ROOT = Path(__file__).resolve().parents[1]


def load_json(relative: str) -> dict[str, object]:
    value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "dimension_rendering_generate_report", ROOT / "tools/generate_report.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_renderer_lookup_is_fixed_complete_and_fully_referenced():
    assert tuple(RENDERER_LOOKUP) == (
        "evidence_v1",
        "presence_v1",
        "mount_integrity_v1",
        "property_map_v1",
        "not_applicable_v1",
    )
    assert {
        definition.renderer_hints.renderer_id
        for definition in TRUST_DIMENSION_DEFINITIONS
    } == set(RENDERER_LOOKUP)


def test_matrix_dimensions_derive_from_registry_order():
    assert [definition.id for definition in MATRIX_DIMENSIONS] == [
        "bootloader_lock_state",
        "verified_boot_state",
        "vbmeta_state",
        "verity_mode",
        "selinux_mode",
        "mount_integrity",
        "root_shell_availability",
        "magisk_binary_visibility",
        "property_consistency",
    ]
    assert [
        definition.renderer_hints.matrix_order for definition in MATRIX_DIMENSIONS
    ] == list(range(1, 10))


def test_every_renderer_preserves_status_aware_deterministic_output():
    report = load_json("tests/fixtures/sample_normalized_report.json")

    assert render_dimension(report, "selinux_mode") == "enforcing"
    assert render_dimension(report, "root_shell_availability") == "not_collected"
    assert render_dimension(report, "magisk_binary_visibility") == "not present"
    assert render_dimension(report, "mount_integrity") == "writable=none; overlay=false"
    assert render_dimension(report, "property_consistency") == (
        '{"ro.adb.secure": "1", "ro.debuggable": "0", "ro.secure": "1", '
        '"sys.boot_completed": "1"}'
    )
    assert render_dimension(report, "physical_device_state") == "not_collected"


def test_generic_renderer_recursively_removes_evidence_metadata():
    report = load_json("tests/fixtures/sample_normalized_report.json")

    assert render_dimension(report, "selinux_denial_collection") == "not_collected"
    assert render_dimension(report, "magisk_command_status") == "observed"
    selected_processes = render_dimension(report, "selected_process_visibility")
    assert '"name": "init"' in selected_processes
    assert '"context": "u:r:init:s0"' in selected_processes
    assert '"visibility": "not_collected"' in selected_processes
    for dimension in TRUST_DIMENSION_DEFINITIONS:
        rendered = render_dimension(report, dimension)
        assert "evidence_refs" not in rendered
        assert "reason" not in rendered


def test_presence_renderer_uses_presence_words_only_for_observed_booleans():
    report = load_json("tests/fixtures/sample_normalized_report.json")
    magisk = report["magisk_state"]
    assert isinstance(magisk, dict)

    present = deepcopy(report)
    present["magisk_state"]["binary_visibility"] = {
        "status": "observed",
        "value": True,
        "reason": None,
        "evidence_refs": [],
    }
    unavailable = deepcopy(report)
    unavailable["magisk_state"]["binary_visibility"] = {
        "status": "inaccessible",
        "value": None,
        "reason": "observer could not access the probe",
        "evidence_refs": [],
    }

    assert render_dimension(present, "magisk_binary_visibility") == "present"
    assert render_dimension(report, "magisk_binary_visibility") == "not present"
    assert render_dimension(unavailable, "magisk_binary_visibility") == "inaccessible"


def test_renderers_fail_readably_for_noncanonical_but_bounded_values():
    report = load_json("tests/fixtures/sample_normalized_report.json")

    nullable_presence = deepcopy(report)
    nullable_presence["root_state"]["root_shell_available"] = {
        "status": "observed",
        "value": None,
        "reason": None,
        "evidence_refs": [],
    }
    raw_presence = deepcopy(report)
    raw_presence["root_state"]["root_shell_available"] = "unknown"
    raw_mount = deepcopy(report)
    raw_mount["mounts"]["integrity_summary"] = "unknown"

    assert render_dimension(nullable_presence, "root_shell_availability") == "None"
    assert render_dimension(raw_presence, "root_shell_availability") == "unknown"
    assert render_dimension(raw_mount, "mount_integrity") == "unknown"


def test_every_dimension_has_a_renderer_and_a_registry_derived_label():
    report = load_json("tests/fixtures/sample_normalized_report.json")
    for definition in TRUST_DIMENSION_DEFINITIONS:
        assert isinstance(render_dimension(report, definition), str)
        assert dimension_label(definition) == f"{definition.title} (`{definition.id}`)"


def test_registry_documentation_is_deterministic_and_complete():
    first = registry_markdown()
    assert first == registry_markdown()
    assert first.startswith("# Trust Dimension Registry\n")
    assert "arbitrary" not in first
    for definition in TRUST_DIMENSION_DEFINITIONS:
        assert f"`{definition.id}`" in first
        assert definition.title in first
        assert definition.description in first
        assert definition.interpretation in first


def test_report_and_diff_markdown_use_registry_titles():
    report = load_json("tests/fixtures/sample_normalized_report.json")
    report_markdown = report_to_markdown(report)
    assert "- SELinux policy mode: `enforcing`" in report_markdown
    assert "- Magisk binary visibility: `not present`" in report_markdown
    assert "- Emulator state: `True`" in report_markdown

    diff = load_json("tests/fixtures/sample_diff.json")
    diff_markdown = diff_to_markdown(diff)
    for item in diff["changed_dimensions"]:
        assert isinstance(item, dict)
        dimension = item["dimension"]
        assert isinstance(dimension, str)
        definition = TRUST_DIMENSIONS_BY_ID[dimension]
        assert dimension_label(definition) in diff_markdown


def test_generator_consumes_matrix_titles_and_emits_registry_documentation():
    generator = load_generator()
    report = load_json("tests/fixtures/sample_normalized_report.json")
    matrix = generator.matrix_markdown(
        {
            "E01_stock_avd": report,
            "E02_rooted_avd": report,
            "E03_writable_system_avd": report,
            "E05_magisk_collector": report,
        }
    )
    matrix_rows = [line for line in matrix.splitlines() if line.startswith("| ")][1:]
    assert len(matrix_rows) == len(MATRIX_DIMENSIONS)
    for definition, row in zip(MATRIX_DIMENSIONS, matrix_rows, strict=True):
        assert row.startswith(f"| {dimension_label(definition)} |")

    outputs = generator.build_outputs()
    documentation_path = ROOT / "docs/trust_dimension_registry.md"
    assert outputs[documentation_path] == registry_markdown().encode()
    manifest = json.loads(outputs[ROOT / "results/artifact_manifest.json"])
    documentation = [
        artifact
        for artifact in manifest["artifacts"]
        if artifact["path"] == "docs/trust_dimension_registry.md"
    ]
    assert documentation == [
        {
            "path": "docs/trust_dimension_registry.md",
            "type": "generated_registry_documentation",
            "generated_by": "python tools/generate_report.py",
            "sha256": __import__("hashlib")
            .sha256(outputs[documentation_path])
            .hexdigest(),
            "status": "checked",
        }
    ]
