package org.androidtrustlab.observer.export

import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import java.util.TimeZone
import java.util.zip.ZipInputStream
import org.androidtrustlab.observer.probe.AppProbeBundle
import org.androidtrustlab.observer.probe.AppProbeExportMetadata
import org.androidtrustlab.observer.probe.AppProbeOutcome
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AppExportArchiveTest {
    @Test
    fun canonicalFixtureExactlyMatchesTheAppExporter() {
        val encoded = File("../../tests/fixtures/app_probe_v2_export.zip.b64")
            .readText()
            .filterNot(Char::isWhitespace)
        assertArrayEquals(Base64.getDecoder().decode(encoded), AppExportArchive.build(goldenBundle()))
    }

    @Test
    fun archiveIsDeterministicCompleteAndDigestBound() {
        val artifact = "{\"artifact_kind\":\"app_probe_json\"}".toByteArray()
        val manifest = "{\"schema_version\":\"1.0.0\"}".toByteArray()
        val bundle = bundle(artifact, manifest)

        val first = AppExportArchive.build(bundle)
        val second = AppExportArchive.build(bundle)
        assertArrayEquals(first, second)

        val entries = unzip(first)
        assertEquals(
            listOf("SHA256SUMS.txt", "app_probe.json", "export_metadata.json", "manifest.json"),
            entries.keys.toList(),
        )
        assertArrayEquals(artifact, entries.getValue("app_probe.json"))
        assertArrayEquals(manifest, entries.getValue("manifest.json"))
        assertEquals(
            "${sha256(artifact)}  app_probe.json\n" +
                "${sha256(manifest)}  manifest.json\n" +
                "${sha256(entries.getValue("export_metadata.json"))}  export_metadata.json\n",
            entries.getValue("SHA256SUMS.txt").decodeToString(),
        )
        val metadata = entries.getValue("export_metadata.json").decodeToString()
        listOf(
            "\"app_probe_schema_version\":\"2.0.0\"",
            "\"app_version\":\"0.3.0-dev0\"",
            "\"completion_status\":\"complete\"",
            "\"manifest_schema_version\":\"1.0.0\"",
            "\"started_at\":\"2026-07-16T10:00:00Z\"",
            "\"ended_at\":\"2026-07-16T10:00:01Z\"",
            "\"artifact_sha256\":\"${sha256(artifact)}\"",
            "\"manifest_sha256\":\"${sha256(manifest)}\"",
        ).forEach { assertTrue(metadata.contains(it)) }
    }

    @Test
    fun archiveBytesDoNotDependOnDefaultTimeZone() {
        val original = TimeZone.getDefault()
        try {
            val bundle = bundle("{}".toByteArray(), "{}".toByteArray())
            val archives = listOf("UTC", "Europe/Madrid", "America/Los_Angeles").map { zone ->
                TimeZone.setDefault(TimeZone.getTimeZone(zone))
                AppExportArchive.build(bundle)
            }
            assertArrayEquals(archives[0], archives[1])
            assertArrayEquals(archives[0], archives[2])
        } finally {
            TimeZone.setDefault(original)
        }
    }

    @Test
    fun corruptedBundleHashIsRejectedBeforePackaging() {
        val valid = bundle("{}".toByteArray(), "{}".toByteArray())
        val corrupted = AppProbeBundle(
            valid.artifactBytes,
            valid.manifestBytes,
            "0".repeat(64),
            valid.manifestSha256,
            valid.metadata,
            valid.outcomes,
        )
        assertThrows(IllegalArgumentException::class.java) {
            AppExportArchive.build(corrupted)
        }
    }

    private fun bundle(artifact: ByteArray, manifest: ByteArray): AppProbeBundle = AppProbeBundle(
        artifact,
        manifest,
        sha256(artifact),
        sha256(manifest),
        AppProbeExportMetadata(
            "atlcol-0011223344556677",
            "0.3.0-dev0",
            "2.0.0",
            "1.0.0",
            "2026-07-16T10:00:00Z",
            "2026-07-16T10:00:01Z",
            "complete",
        ),
        (0 until 12).map { AppProbeOutcome("probe$it", "observed") },
    )

    private fun goldenBundle(): AppProbeBundle {
        val directory = File("../../tests/fixtures/app_probe_v2_bundle")
        val artifact = directory.resolve("app_probe.json").readBytes()
        val manifest = directory.resolve("manifest.json").readBytes()
        return AppProbeBundle(
            artifact,
            manifest,
            sha256(artifact),
            sha256(manifest),
            AppProbeExportMetadata(
                "atlcol-0001020304050607",
                "0.3.0-dev0",
                "2.0.0",
                "1.0.0",
                "2026-07-16T10:00:00Z",
                "2026-07-16T10:00:01Z",
                "complete",
            ),
            (0 until 12).map { AppProbeOutcome("probe$it", "observed") },
        )
    }

    private fun unzip(bytes: ByteArray): LinkedHashMap<String, ByteArray> {
        val entries = linkedMapOf<String, ByteArray>()
        ZipInputStream(ByteArrayInputStream(bytes)).use { archive ->
            while (true) {
                val entry = archive.nextEntry ?: break
                entries[entry.name] = archive.readBytes()
                archive.closeEntry()
            }
        }
        return entries
    }

    private fun sha256(value: ByteArray): String = MessageDigest
        .getInstance("SHA-256")
        .digest(value)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
