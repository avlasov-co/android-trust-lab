from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyzer"))

from trustlab.report_writer import load_json
from trustlab.validators import validate_report, validate_diff

ROOT = Path(__file__).resolve().parents[1]


def test_sample_report_schema():
    report = load_json(ROOT / "datasets" / "samples" / "stock_avd" / "E01_stock_avd__observer-adb__sample.json")
    validate_report(report)


def test_sample_diff_schema():
    diff = load_json(ROOT / "tests" / "fixtures" / "sample_diff.json")
    validate_diff(diff)



def test_all_manifest_reports_validate():
    manifest = load_json(ROOT / "datasets" / "manifest.json")
    for sample in manifest["samples"]:
        validate_report(load_json(ROOT / sample["report_path"]))


def test_result_diffs_validate():
    for path in (ROOT / "results" / "diffs").glob("*.json"):
        validate_diff(load_json(path))
