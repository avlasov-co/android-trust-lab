package org.androidtrustlab.observer

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.DocumentsContract
import android.security.NetworkSecurityPolicy
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.util.zip.ZipInputStream
import org.androidtrustlab.observer.export.AppExportArchive
import org.androidtrustlab.observer.export.SafExportGateway
import org.androidtrustlab.observer.probe.PublicAppProbe
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/** On-device checks for the observer's public-only collection and export contracts. */
@RunWith(AndroidJUnit4::class)
class AndroidObserverContractTest {
    private val targetContext: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun publicProbeBundleUsesTheStableBoundedContract() {
        val bundle = PublicAppProbe.collect(targetContext)

        assertEquals(PROBE_IDS, bundle.outcomes.map { it.probeId })
        assertTrue(bundle.outcomes.all { it.status in ALLOWED_STATUSES })
        assertTrue(bundle.outcomes.none { it.status == "error" })
        REQUIRED_OBSERVED_PROBES.forEach { probeId ->
            assertEquals("observed", bundle.outcomes.single { it.probeId == probeId }.status)
        }
        val expectedCompletion = if (
            bundle.outcomes.any { it.status in setOf("inaccessible", "error") }
        ) {
            "partial"
        } else {
            "complete"
        }
        assertEquals(expectedCompletion, bundle.metadata.completionStatus)
    }

    @Suppress("DEPRECATION")
    @Test
    fun installedAppRetainsTheUnprivilegedSandbox() {
        val packageManager = targetContext.packageManager
        val packageInfo = packageManager.getPackageInfo(
            targetContext.packageName,
            PackageManager.GET_PERMISSIONS or
                PackageManager.GET_ACTIVITIES or
                PackageManager.GET_PROVIDERS or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS,
        )

        assertTrue(packageInfo.requestedPermissions.isNullOrEmpty())
        assertTrue(packageInfo.providers.isNullOrEmpty())
        assertTrue(packageInfo.services.isNullOrEmpty())
        assertTrue(packageInfo.receivers.isNullOrEmpty())
        val activities = packageInfo.activities.orEmpty()
        assertEquals(1, activities.size)
        assertEquals(MainActivity::class.java.name, activities.single().name)
        assertTrue(activities.single().exported)
        listOf(
            Manifest.permission.INTERNET,
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.ACCESS_FINE_LOCATION,
        ).forEach { permission ->
            assertEquals(
                PackageManager.PERMISSION_DENIED,
                targetContext.checkSelfPermission(permission),
            )
        }
    }

    @Test
    fun installedAppHasNoNetworkCapabilityOrCleartextPolicy() {
        assertEquals(
            PackageManager.PERMISSION_DENIED,
            targetContext.checkSelfPermission(Manifest.permission.INTERNET),
        )
        assertFalse(NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted)
    }

    @Test
    fun publicProbeProducesCanonicalHashBoundJson() {
        val bundle = PublicAppProbe.collect(targetContext)
        val artifactText = bundle.artifactBytes.decodeToString()
        val manifestText = bundle.manifestBytes.decodeToString()

        assertTrue(artifactText.startsWith("{\"artifact_kind\":\"app_probe_json\""))
        assertTrue(artifactText.contains("\"schema_version\":\"2.0.0\""))
        assertFalse(artifactText.contains("/data/user/"))
        assertEquals(sha256(bundle.artifactBytes), bundle.artifactSha256)
        assertEquals(sha256(bundle.manifestBytes), bundle.manifestSha256)
        assertTrue(manifestText.contains("\"sha256\":\"${bundle.artifactSha256}\""))
    }

    @Test
    fun exportArchiveIsFlatBoundedAndChecksumBound() {
        val bundle = PublicAppProbe.collect(targetContext)
        val archive = AppExportArchive.build(bundle)
        val entries = linkedMapOf<String, ByteArray>()
        ZipInputStream(ByteArrayInputStream(archive)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                assertFalse(entry.isDirectory)
                assertFalse('/' in entry.name)
                assertFalse('\\' in entry.name)
                entries[entry.name] = zip.readBytes()
                zip.closeEntry()
            }
        }

        assertEquals(
            setOf(
                "SHA256SUMS.txt",
                "app_probe.json",
                "export_metadata.json",
                "manifest.json",
            ),
            entries.keys,
        )
        assertTrue(entries.getValue("app_probe.json").contentEquals(bundle.artifactBytes))
        assertTrue(entries.getValue("manifest.json").contentEquals(bundle.manifestBytes))
        val sums = entries.getValue("SHA256SUMS.txt").decodeToString()
        assertTrue(sums.contains(bundle.artifactSha256))
        assertTrue(sums.contains(bundle.manifestSha256))
        assertTrue(sums.contains(sha256(entries.getValue("export_metadata.json"))))
    }

    @Test
    fun safOnlyExportRejectsFileUrisAndHasNoFileProvider() {
        val providers = targetContext.packageManager
            .getPackageInfo(targetContext.packageName, PackageManager.GET_PROVIDERS)
            .providers
        assertTrue(providers.isNullOrEmpty())

        try {
            SafExportGateway.publish(
                targetContext,
                Uri.parse("file:///not-a-saf-tree"),
                "android-trust-lab-app-probe-20260716T100001Z-0011223344556677-aabbccdd.zip",
                byteArrayOf(1),
            )
            fail("non-SAF URI accepted")
        } catch (_: IllegalArgumentException) {
            // Expected: exports are permitted only through a caller-selected SAF tree.
        }
    }

    @Test
    fun safExportPublishesVerifiedBytesThroughADocumentsProvider() {
        val archive = AppExportArchive.build(PublicAppProbe.collect(targetContext))
        val treeUri = DocumentsContract.buildTreeDocumentUri(
            TestDocumentsProvider.AUTHORITY,
            TestDocumentsProvider.ROOT_DOCUMENT_ID,
        )
        val finalName =
            "android-trust-lab-app-probe-20260716T100001Z-0011223344556677-aabbccdd.zip"

        SafExportGateway.publish(targetContext, treeUri, finalName, archive)

        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(
            treeUri,
            TestDocumentsProvider.ROOT_DOCUMENT_ID,
        )
        val finalUri: Uri = targetContext.contentResolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_SIZE,
            ),
            null,
            null,
            null,
        )?.use { cursor ->
            assertEquals(1, cursor.count)
            assertTrue(cursor.moveToFirst())
            assertEquals(finalName, cursor.getString(1))
            assertEquals(archive.size.toLong(), cursor.getLong(2))
            DocumentsContract.buildDocumentUriUsingTree(treeUri, cursor.getString(0))
        } ?: throw AssertionError("test DocumentsProvider query failed")
        val published: ByteArray = targetContext.contentResolver
            .openInputStream(finalUri)
            ?.use { it.readBytes() }
            ?: throw AssertionError("published document could not be read")
        assertArrayEquals(archive, published)
    }

    private fun sha256(value: ByteArray): String = MessageDigest
        .getInstance("SHA-256")
        .digest(value)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        val PROBE_IDS = listOf(
            "build_version",
            "app_identity",
            "install_source",
            "selinux_self_context",
            "file_system_shell",
            "file_system_su",
            "file_system_xbin_su",
            "file_vendor_bin_su",
            "file_sbin_su",
            "proc_self_status",
            "proc_self_mountinfo",
            "emulator_indicators",
        )
        val ALLOWED_STATUSES = setOf("observed", "inaccessible", "unsupported", "error")
        val REQUIRED_OBSERVED_PROBES = setOf(
            "build_version",
            "app_identity",
            "install_source",
            "emulator_indicators",
        )
    }
}
