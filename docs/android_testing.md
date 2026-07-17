# Android Test Strategy

The `:observer` module has four deliberately separate verification layers. The
split keeps the Python repository gate fast while still testing the installed
application on Android.

## Fast host-side gate

With JDK 17 and Android SDK Platform 37 installed, run:

```bash
cd app
./gradlew --dependency-verification strict \
  :observer:assembleDebug \
  :observer:assembleRelease \
  :observer:assembleDebugAndroidTest \
  :observer:testDebugUnitTest \
  :observer:lint \
  :observer:verifyDebugMergedManifest \
  :observer:verifyReleaseMergedManifest
```

JVM tests cover canonical serialization, redaction, categorical outcomes,
manifest/hash binding, collection orchestration, and staged SAF publication.
Lint treats warnings as errors and has no baseline. The merged-manifest tasks
check both build types after dependency merging: there must be no requested
permission, feature, query, service, receiver, provider, or activity alias; no
application or activity permission; no network-security configuration; and no
cleartext traffic. The sole exported component must be the `MAIN`/`LAUNCHER`
activity.

## Installed-app contract suite

`AndroidObserverContractTest` contains seven AndroidJUnit4 cases. On an installed
debug APK they verify:

- the public probe's stable order, statuses, and completion contract;
- sandbox permissions and the exact installed component set;
- absence of network permission and cleartext capability;
- canonical JSON plus artifact/manifest hash binding;
- the flat, bounded, checksum-bound export archive; and
- the deliberate absence of a target-app `FileProvider`, with non-SAF URI
  rejection; and
- successful staged write, readback, rename, metadata, and final-byte checks
  through a test-APK-only `DocumentsContract` tree provider.

The tree provider exists only in `src/androidTest` and never merges into the
target observer APK. Its exported-provider lint warning is suppressed directly
on that test component because the target process must exercise it; production
source has no lint suppression or provider.

Run the PR-equivalent managed-device smoke test with:

```bash
cd app
./gradlew --dependency-verification strict \
  :observer:pixel2Api35DebugAndroidTest \
  -Pandroid.testoptions.manageddevices.emulator.gpu=swiftshader_indirect
```

The app declares API 26 as its minimum, but Gradle Managed Devices use API 27,
30, and 35. API 27 is the oldest supported managed-device level. API 26 has
compile-time and `minSdk` compatibility checks but no on-device lane; runtime
behavior on API 26 is therefore not claimed.

## CI topology

`.github/workflows/android.yml` keeps heavy emulator work out of the Python CI
workflow:

- push and pull-request runs compile, JVM tests, strict lint, and both merged
  manifest checks;
- pull requests run one API 35 managed-device smoke suite; and
- scheduled and manually dispatched runs execute the same seven cases on API 27,
  30, and 35.

Failed managed-device reports are uploaded for review. Maven inputs are locked
and checksum-verified; Android SDK and system-image provisioning remain external
CI prerequisites.

## Kotlin-to-Python export bridge

`tests/fixtures/app_probe_v2_export.zip.b64` is a synthetic canonical,
deterministic archive. `AppExportArchiveTest` byte-compares it with the Kotlin
exporter.
`tests/test_app_export_contract.py` independently decodes the archive, checks
its exact flat inventory and every checksum, compares the embedded artifact and
manifest with the canonical bundle, and sends the extracted manifest through
the Python normalizer and report validator. This closes the language boundary
without requiring an emulator in the Python gate.

Run the focused bridge with:

```bash
PYTHONPATH=analyzer pytest -q \
  tests/test_app_export_contract.py \
  tests/test_android_scaffold.py
```

Managed-device success demonstrates the application contract on an AVD. It is
not physical-device validation and does not support boot-chain, TEE,
hardware-attestation, OEM, Widevine, DRM, or app-bypass conclusions.
