from __future__ import annotations

import hashlib
import os
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
MODULE = APP / "observer"
ANDROID = "{http://schemas.android.com/apk/res/android}"


def test_android_scaffold_is_unprivileged_by_construction() -> None:
    manifest = ET.parse(MODULE / "src/main/AndroidManifest.xml").getroot()

    for forbidden in ("uses-permission", "uses-feature", "queries"):
        assert manifest.findall(forbidden) == []

    application = manifest.find("application")
    assert application is not None
    assert application.get(f"{ANDROID}allowBackup") == "false"
    assert application.get(f"{ANDROID}fullBackupContent") == "false"
    assert application.get(f"{ANDROID}dataExtractionRules") == (
        "@xml/data_extraction_rules"
    )
    assert application.get(f"{ANDROID}usesCleartextTraffic") == "false"
    assert application.findall("service") == []
    assert application.findall("receiver") == []
    assert application.findall("provider") == []

    activities = application.findall("activity")
    assert len(activities) == 1
    assert activities[0].get(f"{ANDROID}name") == ".MainActivity"
    assert activities[0].get(f"{ANDROID}exported") == "true"


def test_android_toolchain_and_dependency_inputs_are_pinned() -> None:
    catalog = tomllib.loads(
        (APP / "gradle/libs.versions.toml").read_text(encoding="utf-8")
    )
    assert catalog["versions"] == {"agp": "9.2.1", "junit4": "4.13.2"}

    wrapper_properties = (APP / "gradle/wrapper/gradle-wrapper.properties").read_text(
        encoding="utf-8"
    )
    assert "gradle-9.4.1-bin.zip" in wrapper_properties
    assert (
        "distributionSha256Sum="
        "2ab2958f2a1e51120c326cad6f385153bb11ee93b3c216c5fccebfdfbb7ec6cb"  # pragma: allowlist secret
        in wrapper_properties
    )

    wrapper_jar = APP / "gradle/wrapper/gradle-wrapper.jar"
    assert (
        hashlib.sha256(wrapper_jar.read_bytes()).hexdigest()
        == (
            "55243ef57851f12b070ad14f7f5bb8302daceeebc5bce5ece5fa6edb23e1145c"  # pragma: allowlist secret
        )
    )
    assert os.access(APP / "gradlew", os.X_OK)
    settings = (APP / "settings.gradle.kts").read_text(encoding="utf-8")
    assert "JavaVersion.current() == JavaVersion.VERSION_17" in settings

    verification = ET.parse(APP / "gradle/verification-metadata.xml").getroot()
    namespace = "{https://schema.gradle.org/dependency-verification}"
    configuration = verification.find(f"{namespace}configuration")
    assert configuration is not None
    assert configuration.findtext(f"{namespace}verify-metadata") == "true"
    assert configuration.findtext(f"{namespace}verify-signatures") == "false"
    aapt2 = verification.find(
        f".//{namespace}component[@group='com.android.tools.build']"
        "[@name='aapt2'][@version='9.2.1-15009934']"
    )
    assert aapt2 is not None
    assert {
        artifact.get("name") for artifact in aapt2.findall(f"{namespace}artifact")
    } == {
        "aapt2-9.2.1-15009934-linux.jar",
        "aapt2-9.2.1-15009934-osx.jar",
        "aapt2-9.2.1-15009934.pom",
        "aapt2-9.2.1-15009934-windows.jar",
    }
    assert (APP / "settings-gradle.lockfile").is_file()
    assert (MODULE / "gradle.lockfile").is_file()


def test_android_sources_do_not_contain_forbidden_bridges_or_capabilities() -> None:
    source_root = MODULE / "src/main"
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(source_root.rglob("*"))
        if path.is_file()
    )
    forbidden = (
        "android.permission.INTERNET",
        "AccessibilityService",
        "DeviceAdminReceiver",
        "DexClassLoader",
        "ProcessBuilder",
        "Runtime.getRuntime",
        "Shizuku",
        "VpnService",
        "java.lang.reflect",
    )
    for marker in forbidden:
        assert marker not in source
