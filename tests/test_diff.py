from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyzer"))

from trustlab.diff import make_diff
from trustlab.report_writer import load_json

ROOT = Path(__file__).resolve().parents[1]


def load_report(relative: str):
    return load_json(ROOT / relative)


def test_diff_root_change_without_observer_change():
    base = load_report("datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json")
    compare = load_report("datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json")
    diff = make_diff(base, compare)
    dimensions = {item["dimension"] for item in diff["changed_dimensions"]}
    assert "root_presence" in dimensions
    assert "observer_privilege" not in dimensions


def test_diff_observer_change_is_separate_from_target_mutation():
    base = load_report("datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json")
    compare = load_report("datasets/samples/rooted_avd/E02_rooted_avd__observer-root__sample.json")
    diff = make_diff(base, compare)
    dimensions = {item["dimension"] for item in diff["changed_dimensions"]}
    assert "observer_privilege" in dimensions
    assert "root_presence" not in dimensions


def test_diff_does_not_emit_fake_visibility_or_physical_dimensions():
    base = load_report("datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json")
    compare = load_report("datasets/samples/rooted_avd/E02_rooted_avd__observer-root__sample.json")
    diff = make_diff(base, compare)
    dimensions = {item["dimension"] for item in diff["changed_dimensions"]}
    assert "app_visible_state" not in dimensions
    assert "root_visible_state" not in dimensions
    assert "physical_device_state" not in dimensions
    assert "bootloader_lock_state" in diff["unchanged_dimensions"]


def test_writable_system_diff_detects_mount_integrity():
    base = load_report("datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json")
    compare = load_report("datasets/samples/writable_system_avd/E03_writable_system_avd__observer-adb__sample.json")
    diff = make_diff(base, compare)
    dimensions = {item["dimension"] for item in diff["changed_dimensions"]}
    assert "mount_integrity" in dimensions


def test_diff_id_is_deterministic():
    base = load_report("datasets/samples/stock_avd/E01_stock_avd__observer-adb__sample.json")
    compare = load_report("datasets/samples/rooted_avd/E02_rooted_avd__observer-adb__sample.json")
    assert make_diff(base, compare)["diff_id"] == make_diff(base, compare)["diff_id"]
