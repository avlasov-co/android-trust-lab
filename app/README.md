# Android observer scaffold

This directory is a self-contained Gradle project for the transparent,
unprivileged Android Trust Lab observer. Step 31 intentionally contains no
probe implementation: opening the app performs no collection, schedules no
work, and makes no network request.

## Fixed identity and platform baseline

- application ID and namespace: `org.androidtrustlab.observer`;
- minimum SDK: 26 (Android 8.0), chosen to keep the first implementation on
  modern framework and storage APIs while covering currently useful test APIs;
- compile SDK and target SDK: 37;
- Android Gradle Plugin: 9.2.1;
- Gradle: 9.4.1;
- build JDK and Java bytecode target: 17;
- Kotlin: AGP 9.2 built-in Kotlin, with no separate Kotlin Android plugin.

The versions follow the official [AGP 9.2 compatibility table](https://developer.android.com/build/releases/agp-9-2-0-release-notes),
which specifies API 37, Gradle 9.4.1, and JDK 17. AGP 9.x enables
[built-in Kotlin](https://developer.android.com/build/migrate-to-built-in-kotlin).
The wrapper locks the official Gradle 9.4.1 binary distribution SHA-256 and the
settings script rejects Gradle execution under a JDK other than 17.

## Prerequisites

Install JDK 17 and Android SDK Platform 37. AGP 9.2 selects its documented
default Build Tools 36.0.0 unless a compatible newer installation is needed. Set
`JAVA_HOME` and `ANDROID_SDK_ROOT` to those installations. Do not commit a
machine-local `local.properties` file.

JDK and Android SDK provisioning remain external prerequisites; this repository
does not checksum those installations. It does checksum the Gradle distribution
and Maven artifacts, including the host-specific AAPT2 artifacts for Linux,
macOS, and Windows.

## Build and checks

From this directory:

```bash
./gradlew --dependency-verification strict :observer:assembleDebug
./gradlew --dependency-verification strict :observer:testDebugUnitTest
./gradlew --dependency-verification strict :observer:lintDebug
./gradlew --dependency-verification strict :observer:dependencies
```

Dependency verification is strict by default. `gradle/verification-metadata.xml`
pins the complete resolved plugin and dependency graph;
`observer/gradle.lockfile` locks module dependencies and
`settings-gradle.lockfile` locks the settings catalog resolution. Update these
only as an intentional dependency change and review the resulting diff.

Lint treats warnings as errors. The only disabled issue is
`AndroidGradlePluginVersion`: the upgrade advisory is intentionally inapplicable
while this phase is pinned to the verified AGP 9.2.1 and Gradle 9.4.1 baseline.
There is no lint baseline.

The manifest contains no `uses-permission` or `uses-feature` declaration. The
only exported component is the launcher activity required to open the app.
Cleartext traffic is disabled, and there are no services, receivers, providers,
native libraries, hidden APIs, shell bridges, or background capabilities.
