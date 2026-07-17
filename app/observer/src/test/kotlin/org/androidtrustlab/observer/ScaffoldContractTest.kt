package org.androidtrustlab.observer

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScaffoldContractTest {
    private val manifest = File("src/main/AndroidManifest.xml").readText()
    private val sources = File("src/main/kotlin").walkTopDown()
        .filter(File::isFile)
        .joinToString("\n", transform = File::readText)
    private val activity = File(
        "src/main/kotlin/org/androidtrustlab/observer/MainActivity.kt",
    ).readText()
    private val layout = File("src/main/res/layout/activity_main.xml").readText()

    @Test
    fun manifestRequestsNoPermissions() {
        assertFalse(manifest.contains("<uses-permission"))
        assertFalse(manifest.contains("<uses-feature"))
        assertFalse(manifest.contains("android.permission.INTERNET"))
        assertFalse(manifest.contains("android.permission.ACCESS_NETWORK_STATE"))
        assertFalse(manifest.contains("android.permission.ACCESS_LOCAL_NETWORK"))
    }

    @Test
    fun manifestDisablesCleartextAndExportsOnlyLauncherActivity() {
        assertTrue(manifest.contains("android:usesCleartextTraffic=\"false\""))
        assertTrue(manifest.contains("android:name=\".MainActivity\""))
        assertTrue(manifest.contains("android:exported=\"true\""))
        assertFalse(manifest.contains("<service"))
        assertFalse(manifest.contains("<receiver"))
        assertFalse(manifest.contains("<provider"))
    }

    @Test
    fun appHasNoAccountNetworkOrBackgroundCapability() {
        listOf(
            "AccountManager",
            "ConnectivityManager",
            "NetworkCapabilities",
            "java.net.",
            "WorkManager",
            "JobScheduler",
            "AlarmManager",
            "startService(",
            "startForegroundService(",
            "takePersistableUriPermission",
        ).forEach { forbidden ->
            assertFalse("forbidden app capability: $forbidden", sources.contains(forbidden))
        }
    }

    @Test
    fun collectionAndExportRequireExplicitUserActions() {
        assertTrue(activity.contains("startButton.setOnClickListener { controller.startProbe() }"))
        assertTrue(activity.contains("exportButton.setOnClickListener"))
        assertTrue(activity.contains("Intent.ACTION_OPEN_DOCUMENT_TREE"))
        assertTrue(activity.contains("Intent.EXTRA_LOCAL_ONLY"))
        assertFalse(activity.contains("Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION"))
        assertTrue(activity.contains("ProbeSessionStore.getOrCreate { progress, shouldCancel ->"))
        assertEquals(1, Regex("PublicAppProbe\\.collect\\(").findAll(activity).count())
    }

    @Test
    fun reviewLayoutSupportsAccessibilityAndLargeText() {
        assertTrue(layout.contains("android:id=\"@+id/scope_acknowledgement\""))
        assertTrue(layout.contains("android:minHeight=\"48dp\""))
        assertTrue(layout.contains("android:accessibilityLiveRegion=\"polite\""))
        assertTrue(layout.contains("android:textIsSelectable=\"true\""))
        assertFalse(layout.contains("android:maxLines="))
        assertFalse(layout.contains("android:layout_height=\"48dp\""))
    }
}
