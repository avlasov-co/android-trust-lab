from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyzer"))

from trustlab.parser import parse_getprop, parse_id, parse_mounts, parse_raw_report


def test_parse_getprop():
    props = parse_getprop("[ro.secure]: [1]\n[sys.boot_completed]: [1]")
    assert props["ro.secure"] == "1"
    assert props["sys.boot_completed"] == "1"


def test_parse_id():
    parsed = parse_id("uid=2000(shell) gid=2000(shell) groups=2000(shell)")
    assert parsed["uid"] == "2000"
    assert parsed["gid"] == "2000"


def test_parse_mounts():
    mounts = parse_mounts("/dev/block/dm-1 on /system type ext4 (ro,seclabel)")
    assert mounts[0]["mount_point"] == "/system"
    assert mounts[0]["classification"] == "read-only"


def test_parse_raw_report_fixture():
    parsed = parse_raw_report(Path(__file__).parent / "fixtures" / "sample_raw_report.txt")
    assert parsed["properties"]["ro.secure"] == "1"
    assert parsed["selinux_mode"] == "enforcing"


def test_parse_boot_state_section(tmp_path):
    raw = tmp_path / "raw.txt"
    raw.write_text(
        """=== BOOT_STATE ===
sys.boot_completed=1
ro.boot.flash.locked=1
kernel_cmdline=androidboot.foo=bar
=== ID ===
uid=0(root) gid=0(root) groups=0(root)
""",
        encoding="utf-8",
    )
    from trustlab.parser import parse_raw_report

    parsed = parse_raw_report(raw)
    assert parsed["boot_state_raw"]["sys.boot_completed"] == "1"
    assert parsed["boot_state_raw"]["ro.boot.flash.locked"] == "1"
