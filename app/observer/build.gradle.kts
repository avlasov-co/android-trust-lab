import com.android.build.api.artifact.SingleArtifact
import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.TaskAction
import org.w3c.dom.Element
import javax.xml.parsers.DocumentBuilderFactory

plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "org.androidtrustlab.observer"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.androidtrustlab.observer"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.3.0-dev0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        buildConfig = true
    }

    lint {
        abortOnError = true
        checkDependencies = true
        checkReleaseBuilds = true
        // Step 31 deliberately pins the verified AGP 9.2.1/Gradle 9.4.1 contract.
        disable += "AndroidGradlePluginVersion"
        warningsAsErrors = true
    }

    testOptions {
        animationsDisabled = true
        managedDevices {
            localDevices {
                create("pixel2Api27") {
                    device = "Pixel 2"
                    apiLevel = 27
                    systemImageSource = "aosp"
                    require64Bit = true
                }
                create("pixel2Api30") {
                    device = "Pixel 2"
                    apiLevel = 30
                    systemImageSource = "aosp"
                    require64Bit = true
                }
                create("pixel2Api35") {
                    device = "Pixel 2"
                    apiLevel = 35
                    systemImageSource = "aosp"
                    require64Bit = true
                }
            }
        }
    }

    packaging {
        resources {
            excludes += setOf("META-INF/AL2.0", "META-INF/LGPL2.1")
        }
    }
}

abstract class VerifyMergedManifestTask : DefaultTask() {
    @get:InputFile
    abstract val mergedManifest: RegularFileProperty

    @TaskAction
    fun verify() {
        val factory = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            isXIncludeAware = false
            setExpandEntityReferences(false)
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            setFeature("http://xml.org/sax/features/external-general-entities", false)
            setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        }
        val document = factory.newDocumentBuilder().parse(mergedManifest.get().asFile)
        val root = document.documentElement
        check(root.tagName == "manifest")
        listOf(
            "instrumentation",
            "permission",
            "permission-group",
            "permission-tree",
            "uses-permission",
            "uses-permission-sdk-23",
            "uses-permission-sdk-m",
            "uses-feature",
            "queries",
        ).forEach {
            check(root.getElementsByTagName(it).length == 0) { "unexpected merged $it" }
        }

        val applications = root.getElementsByTagName("application")
        check(applications.length == 1)
        val application = applications.item(0) as Element
        check(application.androidAttribute("allowBackup") == "false")
        check(application.androidAttribute("fullBackupContent") == "false")
        check(application.androidAttribute("usesCleartextTraffic") == "false")
        check(application.androidAttribute("permission").isEmpty())
        check(application.androidAttribute("networkSecurityConfig").isEmpty())
        listOf("activity-alias", "service", "receiver", "provider").forEach {
            check(application.getElementsByTagName(it).length == 0) {
                "unexpected merged $it"
            }
        }
        val activities = application.getElementsByTagName("activity")
        check(activities.length == 1)
        val launcher = activities.item(0) as Element
        check(launcher.androidAttribute("name") == "org.androidtrustlab.observer.MainActivity")
        check(launcher.androidAttribute("exported") == "true")
        check(launcher.androidAttribute("permission").isEmpty())
        val intentFilters = launcher.getElementsByTagName("intent-filter")
        check(intentFilters.length == 1) { "launcher intent-filter count" }
        val intentFilter = intentFilters.item(0) as Element
        val actions = intentFilter.getElementsByTagName("action")
        check(actions.length == 1)
        check((actions.item(0) as Element).androidAttribute("name") == "android.intent.action.MAIN")
        val categories = intentFilter.getElementsByTagName("category")
        check(categories.length == 1)
        check(
            (categories.item(0) as Element).androidAttribute("name") ==
                "android.intent.category.LAUNCHER",
        )
    }

    private fun Element.androidAttribute(name: String): String =
        getAttributeNS("http://schemas.android.com/apk/res/android", name)
}

androidComponents {
    onVariants(selector().all()) { variant ->
        val variantName = variant.name.replaceFirstChar { character ->
            if (character.isLowerCase()) character.titlecase() else character.toString()
        }
        val verifyManifest = tasks.register<VerifyMergedManifestTask>(
            "verify${variantName}MergedManifest",
        ) {
            group = "verification"
            description = "Verifies the security contract of the merged ${variant.name} manifest."
            mergedManifest.set(variant.artifacts.get(SingleArtifact.MERGED_MANIFEST))
        }
        tasks.named("check").configure { dependsOn(verifyManifest) }
    }
}

dependencies {
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
    testImplementation(libs.junit4)
}

dependencyLocking {
    lockAllConfigurations()
}
