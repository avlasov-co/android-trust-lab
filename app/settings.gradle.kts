check(JavaVersion.current() == JavaVersion.VERSION_17) {
    "Android Trust Lab requires JDK 17 to run Gradle; found ${JavaVersion.current()}."
}

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "android-trust-lab-app"
include(":observer")
