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

        testInstrumentationRunner = "android.app.Instrumentation"
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

    packaging {
        resources {
            excludes += setOf("META-INF/AL2.0", "META-INF/LGPL2.1")
        }
    }
}

dependencies {
    testImplementation(libs.junit4)
}

dependencyLocking {
    lockAllConfigurations()
}
