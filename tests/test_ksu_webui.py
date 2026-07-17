from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from test_magisk_runtime import _runtime

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "module/trustlab-magisk"
WEBROOT = MODULE / "webroot"


def _run_api(module: Path, *args: str) -> dict[str, object]:
    result = subprocess.run(
        ["sh", module / "scripts/webui_api.sh", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.stderr == ""
    return json.loads(result.stdout)


def _api_runtime(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, str]]:
    module, private, environment = _runtime(tmp_path)
    exported = tmp_path / "exported"
    api = module / "scripts/webui_api.sh"
    api.write_text(
        api.read_text(encoding="utf-8")
        .replace('BASE_DIR="/data/adb/android-trust-lab"', f'BASE_DIR="{private}"')
        .replace(
            'EXPORT_PARENT="/sdcard/Download/AndroidTrustLab"',
            f'EXPORT_PARENT="{exported}"',
        ),
        encoding="utf-8",
    )
    return module, private, exported, environment


def test_webui_api_handles_fixed_operations_and_verified_export(tmp_path: Path):
    module, private, exported, environment = _api_runtime(tmp_path)
    info = _run_api(module, "info")
    assert info["ok"] is True
    assert info["data"]["webuiApiVersion"] == 1
    assert _run_api(module, "unknown")["error"]["code"] == "invalid_command"
    assert _run_api(module, "inspect", "../bad")["error"]["code"] == "invalid_id"

    completed = subprocess.run(
        ["sh", module / "scripts/write_report.sh", "magisk_module_webui", "auto"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    collection = next((private / "reports").glob("run_*"))
    collection_id = collection.name

    listed = _run_api(module, "list")
    assert listed["ok"] is True
    assert listed["data"]["collections"][0]["source"] == "webui"
    assert not list(private.glob(".webui_verify_*"))
    inspected = _run_api(module, "inspect", collection_id)
    assert inspected["ok"] is True
    assert "raw.txt" not in json.dumps(inspected)
    assert _run_api(module, "verify", collection_id)["data"]["verified"] is True
    assert not list(private.glob(".webui_verify_*"))
    exported_response = _run_api(module, "export", collection_id)
    assert exported_response["ok"] is True
    assert (exported / collection_id / "collector_manifest.json").is_file()
    assert not list(private.glob(".webui_verify_*"))
    assert _run_api(module, "export", collection_id)["error"]["code"] == "export_exists"
    assert (
        _run_api(module, "delete", collection_id, "wrong")["error"]["code"]
        == "delete_refused"
    )
    assert (
        _run_api(module, "delete", collection_id, f"DELETE:{collection_id}")["data"][
            "deleted"
        ]
        is True
    )
    assert not collection.exists()


def test_webui_verification_rejects_undeclared_files_and_symlinks(tmp_path: Path):
    module, private, _, environment = _api_runtime(tmp_path)
    result = subprocess.run(
        ["sh", module / "scripts/write_report.sh", "magisk_module_webui", "auto"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0
    collection = next((private / "reports").glob("run_*"))
    (collection / "extra.txt").write_text("unexpected", encoding="utf-8")
    assert (
        _run_api(module, "verify", collection.name)["error"]["code"]
        == "verification_failed"
    )
    (collection / "extra.txt").unlink()
    (collection / "alias").symlink_to(collection / "raw.txt")
    assert (
        _run_api(module, "verify", collection.name)["error"]["code"]
        == "verification_failed"
    )


def test_webui_static_boundary_and_vendored_bridge_integrity():
    index = (WEBROOT / "index.html").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in index
    assert "connect-src 'none'" in index
    files = [path for path in WEBROOT.rglob("*") if path.is_file()]
    runtime_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in files
        if path.suffix in {".html", ".js", ".css"}
    )
    assert "http://" not in runtime_text and "https://" not in runtime_text
    assert "innerHTML" not in runtime_text
    assert "document.write" not in runtime_text
    assert "eval(" not in runtime_text
    assert "onclick=" not in runtime_text
    assert "/data/adb/modules/androidtrustlab/scripts/webui_api.sh" in (
        WEBROOT / "bridge.js"
    ).read_text(encoding="utf-8")
    bridge = WEBROOT / "vendor/kernelsu.js"
    assert (
        hashlib.sha256(bridge.read_bytes()).hexdigest()
        == (
            "868805848c3a208c79fbf0f7581255a33c33b812dfaae8b457125fbbb2c400ca"  # pragma: allowlist secret
        )
    )
    notice = (WEBROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert "package `kernelsu` version `3.0.2`" in notice
    assert "Apache-2.0" in notice
