from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path

import pytest

from trustlab.exceptions import CollectionError
from trustlab.magisk_importer import import_magisk
from trustlab.normalizer import normalize_collection_manifest
from trustlab.validators import validate_collection_manifest, validate_report

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "module" / "trustlab-magisk"
WRITER = Path("scripts/write_report.sh")

EXPECTED_ARTIFACTS = {
    "raw_report",
    "command_results",
    "collector_log",
    "boot_completion",
    "boot_state",
    "properties",
    "mounts",
    "selinux",
    "root_state",
    "magisk_state",
    "process_state",
}


def _executable(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _runtime(
    tmp_path: Path, *, boot_completed: str = "1"
) -> tuple[Path, Path, dict[str, str]]:
    module = tmp_path / "module"
    shutil.copytree(MODULE, module)
    base = tmp_path / "private-runtime"
    writer = module / WRITER
    source = writer.read_text(encoding="utf-8")
    production = 'BASE_DIR="/data/adb/android-trust-lab"'
    assert source.count(production) == 1
    writer.write_text(
        source.replace(production, f'BASE_DIR="{base}"'),
        encoding="utf-8",
    )

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _executable(
        fake_bin / "getprop",
        f"""case "$1" in
  sys.boot_completed) printf '%s' '{boot_completed}' ;;
  ro.boot.verifiedbootstate) printf '%s' green ;;
  ro.boot.flash.locked) printf '%s' 1 ;;
  ro.boot.vbmeta.device_state) printf '%s' locked ;;
  ro.boot.veritymode) printf '%s' enforcing ;;
  ro.build.version.release) printf '%s' 16 ;;
  ro.build.version.sdk) printf '%s' 36 ;;
  ro.debuggable|ro.secure|ro.adb.secure|ro.kernel.qemu) printf '%s' 0 ;;
esac
exit 0
""",
    )
    _executable(fake_bin / "getenforce", "printf '%s\n' Enforcing\n")
    _executable(
        fake_bin / "id",
        """case "$1" in
  -u) printf '%s\n' 0 ;;
  -Z) printf '%s\n' 'u:r:magisk:s0' ;;
  *) printf '%s\n' 'uid=0(root) gid=0(root) groups=0(root)' ;;
esac
""",
    )
    _executable(
        fake_bin / "ps",
        """case "$1" in
  -AZ) printf '%s\n' 'u:r:init:s0 root 1 0 init' 'u:r:magisk:s0 root 2 1 magisk' ;;
  *) printf '%s\n' 'root 1 0 init' 'root 2 1 magisk' ;;
esac
""",
    )
    _executable(
        fake_bin / "magisk",
        """case "$1" in
  -v) printf '%s\n' 'v28.1' ;;
  -V) printf '%s\n' '28100' ;;
  *) exit 2 ;;
esac
""",
    )

    # Host tests do not depend on whether the host exposes Android /proc files.
    mount_script = module / "scripts/collect_mounts.sh"
    mount_script.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' '=== MOUNTINFO ===' "
        "'0 0 0:0 / / ro - ext4 redacted-mount-source ro' "
        "'=== PROC_MOUNTS ===' "
        "'redacted-mount-source / ext4 ro 0 0'\n",
        encoding="utf-8",
    )
    mount_script.chmod(0o755)

    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
    return module, base, environment


def _run_writer(
    module: Path,
    environment: dict[str, str],
    *args: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", module / WRITER, *args],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )


def _published(base: Path) -> list[Path]:
    reports = base / "reports"
    return sorted(path for path in reports.glob("run_*") if path.is_dir())


def _manifest(bundle: Path) -> dict[str, object]:
    document = json.loads((bundle / "collector_manifest.json").read_text())
    validate_collection_manifest(document)
    return document


def _assert_private_bundle(bundle: Path, document: dict[str, object]) -> None:
    if os.name != "nt":
        for directory in [
            bundle,
            *(path for path in bundle.rglob("*") if path.is_dir()),
        ]:
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for artifact in document["artifacts"]:
        assert isinstance(artifact, dict)
        relative = artifact["relative_path"]
        if artifact["status"] != "observed":
            assert relative is None
            continue
        assert isinstance(relative, str)
        path = bundle / relative
        payload = path.read_bytes()
        assert len(payload) == artifact["byte_size"]
        assert hashlib.sha256(payload).hexdigest() == artifact["sha256"]
        if os.name != "nt":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
    manifest_path = bundle / "collector_manifest.json"
    if os.name != "nt":
        assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600


def _wait_for(path: Path, *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {path.name}")


def test_runtime_complete_bundle_is_private_bound_and_importable(
    tmp_path: Path,
) -> None:
    module, base, environment = _runtime(tmp_path)

    result = _run_writer(module, environment, "magisk_module_manual", "auto")

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    bundles = _published(base)
    assert len(bundles) == 1
    bundle = bundles[0]
    assert result.stdout == f"{bundle / 'collector_manifest.json'}\n"
    document = _manifest(bundle)
    assert document["completion_status"] == "complete"
    assert {
        entry["logical_name"] for entry in document["artifacts"]
    } == EXPECTED_ARTIFACTS
    assert document["warnings"] == []
    assert document["redaction_policy"]["policy_id"] == "atl_portable_v1"
    assert document["tool_versions"]["trustlab_magisk"] == "0.3.0-dev0"
    assert not (base / "collector.lock").exists()
    assert list((base / "reports").glob(".partial_*")) == []
    _assert_private_bundle(bundle, document)

    results = json.loads((bundle / "command_results.json").read_text())
    assert results["schema_version"] == "1.0.0"
    assert results["redaction_policy_version"] == "atl_portable_v1"
    assert results["boot_completion"] == {"status": "complete"}
    assert all(entry["status"] == "observed" for entry in results["commands"])

    imported = import_magisk(bundle, tmp_path / "imports")
    report = json.loads(imported.report_path.read_text())
    validate_report(report)
    assert report["observer"]["observer_type"] == "root_collector"


def test_runtime_lock_records_already_running_and_hides_staging(tmp_path: Path) -> None:
    module, base, environment = _runtime(tmp_path)
    release = tmp_path / "release"
    blocker = module / "scripts/collect_boot_state.sh"
    original = blocker.read_text(encoding="utf-8")
    blocker.write_text(
        "#!/bin/sh\n"
        f'while [ ! -f "{release}" ]; do sleep 0.05; done\n'
        + original.split("\n", 1)[1],
        encoding="utf-8",
    )

    first = subprocess.Popen(
        ["sh", module / WRITER, "magisk_module_manual", "auto"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_for(base / "collector.lock")
    _wait_for(base / "reports")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not list(
        (base / "reports").glob(".partial_*")
    ):
        time.sleep(0.02)
    assert _published(base) == []
    assert len(list((base / "reports").glob(".partial_*"))) == 1

    second = _run_writer(module, environment, "magisk_module_manual", "auto")
    assert second.returncode == 75
    assert second.stdout == ""
    assert second.stderr == "Android Trust Lab: already_running\n"
    events = list((base / "events").glob("already_running_*/status.log"))
    assert len(events) == 1
    event_lines = events[0].read_text().splitlines()
    assert event_lines[0] == "status=already_running"
    assert event_lines[1].startswith("recorded_at=202")
    assert _published(base) == []

    release.touch()
    stdout, stderr = first.communicate(timeout=10)
    assert first.returncode == 0, stderr
    assert stderr == ""
    assert stdout.endswith("/collector_manifest.json\n")
    assert len(_published(base)) == 1
    assert not (base / "collector.lock").exists()
    assert list((base / "reports").glob(".partial_*")) == []


def test_runtime_collision_never_overwrites_existing_collection(tmp_path: Path) -> None:
    module, base, environment = _runtime(tmp_path)
    fake_bin = Path(environment["PATH"].split(os.pathsep, 1)[0])
    _executable(
        fake_bin / "date",
        """case "$2" in
  +%Y%m%dT%H%M%SZ) printf '%s\n' 20260716T120000Z ;;
  +%Y-%m-%dT%H:%M:%SZ) printf '%s\n' 2026-07-16T12:00:00Z ;;
  *) exit 2 ;;
esac
""",
    )
    _executable(
        fake_bin / "dd",
        """for argument in "$@"; do
  case "$argument" in of=*) output=${argument#of=} ;; esac
done
[ -n "$output" ] || exit 2
printf '00000000000000000000000000000000' > "$output"
""",
    )

    first = _run_writer(module, environment, "magisk_module_manual", "auto")
    assert first.returncode == 0, first.stderr
    bundle = _published(base)[0]
    before = (bundle / "collector_manifest.json").read_bytes()
    sentinel = bundle / "owner-sentinel"
    sentinel.write_text("preserve-me\n", encoding="utf-8")

    second = _run_writer(module, environment, "magisk_module_manual", "auto")

    assert second.returncode == 1
    assert "existing output was preserved" in second.stderr
    assert (bundle / "collector_manifest.json").read_bytes() == before
    assert sentinel.read_text() == "preserve-me\n"
    assert len(_published(base)) == 1
    assert list((base / "reports").glob(".partial_*")) == []
    assert not (base / "collector.lock").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX signal semantics required")
def test_runtime_term_publishes_valid_partial_and_cleans_lock(tmp_path: Path) -> None:
    module, base, environment = _runtime(tmp_path)
    blocker = module / "scripts/collect_boot_state.sh"
    original = blocker.read_text(encoding="utf-8")
    blocker.write_text(
        "#!/bin/sh\nsleep 30\n" + original.split("\n", 1)[1], encoding="utf-8"
    )

    process = subprocess.Popen(
        ["sh", module / WRITER, "magisk_module_manual", "auto"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_for(base / "collector.lock")
    _wait_for(base / "reports")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        staged_captures = list(
            (base / "reports").glob(".partial_*/.boot_state.capture")
        )
        if staged_captures:
            break
        time.sleep(0.02)
    assert staged_captures
    assert _published(base) == []

    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=10)

    assert process.returncode == 130, stderr
    assert stdout.endswith("/collector_manifest.json\n")
    bundle = _published(base)[0]
    document = _manifest(bundle)
    assert document["completion_status"] == "partial"
    artifacts = {entry["logical_name"]: entry for entry in document["artifacts"]}
    assert artifacts["boot_state"]["status"] == "command_error"
    assert artifacts["boot_state"]["exit_code"] == 143
    assert artifacts["properties"]["status"] == "not_collected"
    assert artifacts["boot_completion"]["status"] == "observed"
    _assert_private_bundle(bundle, document)
    assert not (base / "collector.lock").exists()
    assert list((base / "reports").glob(".partial_*")) == []


def test_service_boot_timeout_is_explicit_partial_and_not_importable(
    tmp_path: Path,
) -> None:
    module, base, environment = _runtime(tmp_path, boot_completed="0")
    fake_bin = Path(environment["PATH"].split(os.pathsep, 1)[0])
    _executable(fake_bin / "sleep", "exit 0\n")

    result = subprocess.run(
        ["sh", module / "service.sh"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 2
    assert result.stderr == "Android Trust Lab: boot_timeout\n"
    bundle = _published(base)[0]
    document = _manifest(bundle)
    assert document["completion_status"] == "partial"
    boot = next(
        entry
        for entry in document["artifacts"]
        if entry["logical_name"] == "boot_completion"
    )
    assert boot["status"] == "command_error"
    assert boot["timed_out"] is True
    assert boot["exit_code"] is None
    results = json.loads((bundle / "command_results.json").read_text())
    assert results["boot_completion"] == {"status": "timeout"}

    report = normalize_collection_manifest(bundle / "collector_manifest.json")
    validate_report(report)
    with pytest.raises(CollectionError, match="requires a complete collection"):
        import_magisk(bundle, tmp_path / "imports")


def test_runtime_projects_adversarial_command_output_before_publication(
    tmp_path: Path,
) -> None:
    module, base, environment = _runtime(tmp_path)
    fake_bin = Path(environment["PATH"].split(os.pathsep, 1)[0])
    sentinel = "PRIVATE_TOKEN=user@example.com /Users/alice/secret emulator-5554"
    _executable(
        fake_bin / "getprop",
        f"""if [ "$1" = sys.boot_completed ]; then printf '%s' 1; else printf '%s' '{sentinel}'; fi
exit 0
""",
    )
    _executable(
        fake_bin / "getenforce",
        f"printf '%s\n' '{sentinel}' >&2\nexit 9\n",
    )
    _executable(
        fake_bin / "id",
        f"""case "$1" in
  -u) printf '%s\n' 0 ;;
  -Z) printf '%s\n' 'u:r:evil_{sentinel}:s0' ;;
esac
""",
    )
    _executable(
        fake_bin / "ps",
        f"printf '%s\n' 'u:r:init:s0 root 1 0 init' 'u:r:bad:s0 root 2 1 magisk {sentinel}'\n",
    )
    _executable(
        fake_bin / "magisk",
        f"""case "$1" in
  -v) printf '%s\n' '{sentinel}' ;;
  -V) printf '%s\n' 28100 ;;
esac
""",
    )

    result = _run_writer(module, environment, "magisk_module_manual", "auto")

    assert result.returncode == 2
    bundle = _published(base)[0]
    document = _manifest(bundle)
    assert document["completion_status"] == "partial"
    for path in bundle.rglob("*"):
        if path.is_file():
            assert sentinel.encode() not in path.read_bytes()
            assert b"user@example.com" not in path.read_bytes()
            assert b"/Users/alice/" not in path.read_bytes()
            assert b"emulator-5554" not in path.read_bytes()
    assert (
        b"[ro.boot.verifiedbootstate]: [unknown]"
        in (bundle / "captures/properties.txt").read_bytes()
    )


def test_runtime_rejects_empty_entropy_without_leaving_lock(tmp_path: Path) -> None:
    module, base, environment = _runtime(tmp_path)
    fake_bin = Path(environment["PATH"].split(os.pathsep, 1)[0])
    _executable(
        fake_bin / "dd",
        """for argument in "$@"; do
  case "$argument" in of=*) output=${argument#of=} ;; esac
done
: > "$output"
""",
    )

    result = _run_writer(module, environment, "magisk_module_manual", "auto")

    assert result.returncode == 1
    assert result.stdout == ""
    assert (
        result.stderr
        == "Android Trust Lab: could not create verified collection entropy\n"
    )
    assert not (base / "collector.lock").exists()
    assert _published(base) == []


def test_runtime_recovers_lock_owned_by_dead_process(tmp_path: Path) -> None:
    module, base, environment = _runtime(tmp_path)
    lock = base / "collector.lock"
    lock.mkdir(parents=True)
    lock.chmod(0o700)
    (lock / "owner").write_text(
        "pid=99999999\npid_start_ticks=1\ncollection_id=stale\n",
        encoding="utf-8",
    )
    (lock / "entropy").write_bytes(b"abandoned entropy")

    result = _run_writer(module, environment, "magisk_module_manual", "auto")

    assert result.returncode == 0, result.stderr
    assert len(_published(base)) == 1
    assert not lock.exists()
    assert not (base / "collector.lock.recovery").exists()


def test_runtime_recovers_only_aged_empty_ownerless_lock(tmp_path: Path) -> None:
    module, base, environment = _runtime(tmp_path)
    lock = base / "collector.lock"
    lock.mkdir(parents=True)
    lock.chmod(0o700)

    fresh = _run_writer(module, environment, "magisk_module_manual", "auto")

    assert fresh.returncode == 75
    assert fresh.stderr == "Android Trust Lab: already_running\n"
    assert lock.exists()
    assert _published(base) == []

    stale_time = time.time() - 600
    os.utime(lock, (stale_time, stale_time))
    recovered = _run_writer(module, environment, "magisk_module_manual", "auto")

    assert recovered.returncode == 0, recovered.stderr
    assert len(_published(base)) == 1
    assert not lock.exists()
    assert not (base / "collector.lock.recovery").exists()


def test_runtime_never_reclaims_aged_lock_with_unknown_contents(tmp_path: Path) -> None:
    module, base, environment = _runtime(tmp_path)
    lock = base / "collector.lock"
    lock.mkdir(parents=True)
    unknown = lock / "unexpected"
    unknown.write_text("preserve\n", encoding="utf-8")
    stale_time = time.time() - 600
    os.utime(lock, (stale_time, stale_time))

    result = _run_writer(module, environment, "magisk_module_manual", "auto")

    assert result.returncode == 75
    assert unknown.read_text(encoding="utf-8") == "preserve\n"
    assert lock.exists()
    assert _published(base) == []


def test_runtime_recovers_only_aged_empty_recovery_mutex(tmp_path: Path) -> None:
    module, base, environment = _runtime(tmp_path)
    lock = base / "collector.lock"
    recovery = base / "collector.lock.recovery"
    lock.mkdir(parents=True)
    lock.chmod(0o700)
    (lock / "owner").write_text(
        "pid=99999999\npid_start_ticks=1\ncollection_id=stale\n",
        encoding="utf-8",
    )
    recovery.mkdir(parents=True)
    recovery.chmod(0o700)

    fresh = _run_writer(module, environment, "magisk_module_manual", "auto")

    assert fresh.returncode == 75
    assert recovery.exists()
    assert lock.exists()
    assert _published(base) == []

    stale_time = time.time() - 600
    os.utime(recovery, (stale_time, stale_time))
    recovered = _run_writer(module, environment, "magisk_module_manual", "auto")

    assert recovered.returncode == 0, recovered.stderr
    assert len(_published(base)) == 1
    assert not recovery.exists()
    assert not lock.exists()


def test_real_mount_projection_is_portable_and_fieldwise(tmp_path: Path) -> None:
    mountinfo = tmp_path / "mountinfo"
    mounts = tmp_path / "mounts"
    mountinfo.write_text(
        "24 1 0:1 / / ro shared:1 - ext4 /dev/private ro\n"
        "25 1 0:2 /com.android.runtime@1 /apex/com.android.runtime ro "
        "- tmpfs private-source ro\n"
        "26 1 0:3 /secret /storage/emulated/0 rw - ext4 /dev/secret rw\n",
        encoding="utf-8",
    )
    mounts.write_text(
        "/dev/private / ext4 ro,seclabel 0 0\n"
        "private-source /apex/com.android.runtime tmpfs rw 0 0\n"
        "/dev/secret /storage/emulated/0 ext4 rw 0 0\n",
        encoding="utf-8",
    )
    source = (MODULE / "scripts/collect_mounts.sh").read_text(encoding="utf-8")
    source = source.replace("/proc/self/mountinfo", str(mountinfo)).replace(
        "/proc/mounts", str(mounts)
    )
    script = tmp_path / "collect_mounts.sh"
    _executable(script, source.split("\n", 1)[1])

    result = subprocess.run(["sh", script], capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr
    assert "trustlab: command error" not in result.stdout
    assert "/storage/emulated/0" not in result.stdout
    assert "/dev/private" not in result.stdout
    assert "private-source" not in result.stdout
    assert "redacted-mount-source / ext4 ro" in result.stdout
    assert "/apex/redacted-apex" in result.stdout


def test_runtime_link_failure_leaves_no_published_or_staged_directory(
    tmp_path: Path,
) -> None:
    module, base, environment = _runtime(tmp_path)
    fake_bin = Path(environment["PATH"].split(os.pathsep, 1)[0])
    _executable(
        fake_bin / "ln",
        """case "$2" in
  */collector_manifest.json) exit 70 ;;
esac
exec /bin/ln "$@"
""",
    )

    result = _run_writer(module, environment, "magisk_module_manual", "auto")

    assert result.returncode == 1
    assert "atomic completion-manifest publication failed" in result.stderr
    assert _published(base) == []
    assert list((base / "reports").glob("run_*")) == []
    assert list((base / "reports").glob(".partial_*")) == []
    assert not (base / "collector.lock").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX signal semantics required")
def test_service_boot_wait_interrupt_publishes_explicit_partial(tmp_path: Path) -> None:
    module, base, environment = _runtime(tmp_path, boot_completed="0")
    fake_bin = Path(environment["PATH"].split(os.pathsep, 1)[0])
    sleeping = tmp_path / "sleeping"
    _executable(
        fake_bin / "sleep",
        f'touch "{sleeping}"\nexec /bin/sleep 30\n',
    )
    process = subprocess.Popen(
        ["sh", module / "service.sh"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    _wait_for(sleeping)

    os.killpg(process.pid, signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=10)

    assert process.returncode == 130
    assert stdout.endswith("/collector_manifest.json\n")
    assert "Android Trust Lab: boot_wait_interrupted\n" in stderr
    bundle = _published(base)[0]
    document = _manifest(bundle)
    assert document["completion_status"] == "partial"
    boot = next(
        entry
        for entry in document["artifacts"]
        if entry["logical_name"] == "boot_completion"
    )
    assert boot["status"] == "command_error"
    assert boot["exit_code"] == 143
    assert boot["timed_out"] is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX signal semantics required")
def test_service_recovery_writer_remains_interruptible(tmp_path: Path) -> None:
    module, base, environment = _runtime(tmp_path, boot_completed="0")
    fake_bin = Path(environment["PATH"].split(os.pathsep, 1)[0])
    boot_waiting = tmp_path / "boot-waiting"
    recovery_waiting = tmp_path / "recovery-waiting"
    _executable(
        fake_bin / "sleep",
        f'touch "{boot_waiting}"\nexec /bin/sleep 30\n',
    )
    _executable(
        module / "scripts/collect_boot_state.sh",
        f'touch "{recovery_waiting}"\nexec /bin/sleep 30\n',
    )
    process = subprocess.Popen(
        ["sh", module / "service.sh"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    _wait_for(boot_waiting)

    os.killpg(process.pid, signal.SIGTERM)
    _wait_for(recovery_waiting)
    os.killpg(process.pid, signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=10)

    assert process.returncode != 0
    assert stdout.endswith("/collector_manifest.json\n")
    assert "Android Trust Lab: boot_wait_interrupted\n" in stderr
    bundle = _published(base)[0]
    document = _manifest(bundle)
    assert document["completion_status"] == "partial"
    artifacts = {entry["logical_name"]: entry for entry in document["artifacts"]}
    assert artifacts["boot_completion"]["status"] == "command_error"
    assert artifacts["boot_state"]["status"] == "command_error"
    assert artifacts["boot_state"]["exit_code"] == 143
    assert document["warnings"] == []
    assert "warning=collector_interrupted\n" in (bundle / "collector.log").read_text()
    assert not (base / "collector.lock").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX signal semantics required")
def test_late_interrupt_keeps_fully_captured_manifest_semantically_complete(
    tmp_path: Path,
) -> None:
    module, base, environment = _runtime(tmp_path)
    marker = tmp_path / "all-probes-captured"
    writer = module / WRITER
    source = writer.read_text(encoding="utf-8")
    insertion = (
        'capture_probe process_state "$MODDIR/scripts/collect_process_state.sh"\n\n'
    )
    assert source.count(insertion) == 1
    writer.write_text(
        source.replace(
            insertion,
            insertion
            + f'touch "{marker}"\n'
            + f'while [ -e "{marker}" ]; do /bin/sleep 0.05; done\n\n',
        ),
        encoding="utf-8",
    )
    process = subprocess.Popen(
        ["sh", writer, "magisk_module_manual", "auto"],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_for(marker)

    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=10)

    assert process.returncode == 130, stderr
    assert stdout.endswith("/collector_manifest.json\n")
    bundle = _published(base)[0]
    document = _manifest(bundle)
    assert document["completion_status"] == "complete"
    assert document["warnings"] == []
    assert "warning=collector_interrupted\n" in (bundle / "collector.log").read_text()
    assert all(
        artifact["status"] in {"observed", "observed_absent"}
        for artifact in document["artifacts"]
    )
    _assert_private_bundle(bundle, document)
