package org.androidtrustlab.observer

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScaffoldContractTest {
    private val manifest = File("src/main/AndroidManifest.xml").readText()

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
}
