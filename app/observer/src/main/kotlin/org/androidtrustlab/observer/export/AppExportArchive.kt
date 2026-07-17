package org.androidtrustlab.observer.export

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.androidtrustlab.observer.probe.AppProbeBundle
import org.androidtrustlab.observer.probe.CanonicalJson
import org.androidtrustlab.observer.probe.json
import org.androidtrustlab.observer.probe.jsonObject

internal object AppExportArchive {
    private const val MAX_ARCHIVE_BYTES = 4 * 1024 * 1024

    fun build(bundle: AppProbeBundle): ByteArray {
        val artifactBytes = bundle.artifactBytes
        val manifestBytes = bundle.manifestBytes
        require(sha256(artifactBytes) == bundle.artifactSha256)
        require(sha256(manifestBytes) == bundle.manifestSha256)

        val metadata = bundle.metadata
        val metadataBytes = CanonicalJson.encode(
            jsonObject(
                "app_probe_schema_version" to metadata.appProbeSchemaVersion.json(),
                "app_version" to metadata.appVersion.json(),
                "artifact_sha256" to bundle.artifactSha256.json(),
                "collection_id" to metadata.collectionId.json(),
                "completion_status" to metadata.completionStatus.json(),
                "ended_at" to metadata.endedAt.json(),
                "export_format" to "android-trust-lab-app-export-v1".json(),
                "manifest_schema_version" to metadata.manifestSchemaVersion.json(),
                "manifest_sha256" to bundle.manifestSha256.json(),
                "started_at" to metadata.startedAt.json(),
            ),
        )
        val hashes = buildString {
            append(bundle.artifactSha256)
            append("  ")
            append(AppProbeBundle.ARTIFACT_FILE_NAME)
            append('\n')
            append(bundle.manifestSha256)
            append("  ")
            append(AppProbeBundle.MANIFEST_FILE_NAME)
            append('\n')
            append(sha256(metadataBytes))
            append("  export_metadata.json\n")
        }.toByteArray(StandardCharsets.US_ASCII)
        val entries = listOf(
            AppProbeBundle.ARTIFACT_FILE_NAME to artifactBytes,
            "export_metadata.json" to metadataBytes,
            AppProbeBundle.MANIFEST_FILE_NAME to manifestBytes,
            "SHA256SUMS.txt" to hashes,
        ).sortedBy { it.first }

        val output = ByteArrayOutputStream()
        ZipOutputStream(output, StandardCharsets.UTF_8).use { archive ->
            entries.forEach { (name, payload) ->
                require('/' !in name && '\\' !in name)
                val checksum = CRC32().apply { update(payload) }.value
                val entry = ZipEntry(name).apply {
                    method = ZipEntry.STORED
                    size = payload.size.toLong()
                    compressedSize = payload.size.toLong()
                    crc = checksum
                    time = 0L
                }
                archive.putNextEntry(entry)
                archive.write(payload)
                archive.closeEntry()
            }
        }
        return output.toByteArray().also {
            require(it.isNotEmpty() && it.size <= MAX_ARCHIVE_BYTES)
        }
    }

    private fun sha256(value: ByteArray): String = MessageDigest
        .getInstance("SHA-256")
        .digest(value)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

/**
 * Publishes a fully staged archive through a verified temporary SAF document.
 * Provider rename is a single publication step, but Android does not promise
 * filesystem-level atomicity for every third-party DocumentsProvider.
 */
internal object SafExportGateway {
    private const val MIME_TYPE = "application/zip"
    private val finalNamePattern = Regex(
        "^android-trust-lab-app-probe-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{16}-[a-f0-9]{8}\\.zip$",
    )

    fun publish(context: Context, treeUri: Uri, finalName: String, archiveBytes: ByteArray) {
        require(treeUri.scheme == ContentResolver.SCHEME_CONTENT)
        require(DocumentsContract.isTreeUri(treeUri))
        require(finalNamePattern.matches(finalName))
        require(archiveBytes.isNotEmpty())

        VerifiedDocumentPublisher(SafDocumentOperations(context, treeUri))
            .publish(finalName, archiveBytes)
    }

    private class SafDocumentOperations(context: Context, treeUri: Uri) :
        PublicationOperations<Uri> {
        private val resolver = context.contentResolver
        private val parent = DocumentsContract.buildDocumentUriUsingTree(
            treeUri,
            DocumentsContract.getTreeDocumentId(treeUri),
        )

        override fun createTemporary(): Uri {
            val temporaryName = ".android-trust-lab-${randomHex(8)}.tmp"
            return DocumentsContract.createDocument(resolver, parent, MIME_TYPE, temporaryName)
                ?: throw IOException()
        }

        override fun requirePublicationCapabilities(document: Uri) {
            val required = (Document.FLAG_SUPPORTS_WRITE or
                Document.FLAG_SUPPORTS_DELETE or
                Document.FLAG_SUPPORTS_RENAME).toLong()
            val flags = queryLong(document, Document.COLUMN_FLAGS) ?: throw IOException()
            if (flags and required != required) throw IOException()
        }

        override fun writeAndSync(document: Uri, bytes: ByteArray) {
            val descriptor = resolver.openFileDescriptor(document, "rwt") ?: throw IOException()
            ParcelFileDescriptor.AutoCloseOutputStream(descriptor).use { output ->
                output.write(bytes)
                output.flush()
                descriptor.fileDescriptor.sync()
            }
        }

        override fun verifyBytes(document: Uri, expected: ByteArray) {
            val input = resolver.openInputStream(document) ?: throw IOException()
            input.use { verifyExactContent(it, expected) }
        }

        override fun rename(document: Uri, finalName: String): Uri =
            DocumentsContract.renameDocument(resolver, document, finalName) ?: throw IOException()

        override fun verifyFinalMetadata(
            document: Uri,
            expectedName: String,
            expectedSize: Long,
        ) {
            resolver.query(
                document,
                arrayOf(Document.COLUMN_DISPLAY_NAME, Document.COLUMN_SIZE),
                null,
                null,
                null,
            )?.use { cursor ->
                if (!cursor.moveToFirst() || cursor.isNull(0) || cursor.isNull(1)) {
                    throw IOException()
                }
                if (cursor.getString(0) != expectedName || cursor.getLong(1) != expectedSize) {
                    throw IOException()
                }
                return
            }
            throw IOException()
        }

        override fun delete(document: Uri) {
            DocumentsContract.deleteDocument(resolver, document)
        }

        private fun queryLong(uri: Uri, column: String): Long? =
            resolver.query(uri, arrayOf(column), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getLong(0) else null
            }
    }

    private fun randomHex(bytes: Int): String {
        val value = ByteArray(bytes).also(SecureRandom()::nextBytes)
        return value.joinToString("") { "%02x".format(it) }
    }
}

internal interface PublicationOperations<Handle> {
    fun createTemporary(): Handle
    fun requirePublicationCapabilities(document: Handle)
    fun writeAndSync(document: Handle, bytes: ByteArray)
    fun verifyBytes(document: Handle, expected: ByteArray)
    fun rename(document: Handle, finalName: String): Handle
    fun verifyFinalMetadata(document: Handle, expectedName: String, expectedSize: Long)
    fun delete(document: Handle)
}

internal class VerifiedDocumentPublisher<Handle>(
    private val operations: PublicationOperations<Handle>,
) {
    fun publish(finalName: String, archiveBytes: ByteArray) {
        var cleanupDocument = operations.createTemporary()
        var published = false
        try {
            operations.requirePublicationCapabilities(cleanupDocument)
            operations.writeAndSync(cleanupDocument, archiveBytes)
            operations.verifyBytes(cleanupDocument, archiveBytes)
            cleanupDocument = operations.rename(cleanupDocument, finalName)
            operations.verifyFinalMetadata(
                cleanupDocument,
                finalName,
                archiveBytes.size.toLong(),
            )
            operations.verifyBytes(cleanupDocument, archiveBytes)
            published = true
        } finally {
            if (!published) {
                try {
                    operations.delete(cleanupDocument)
                } catch (_: Exception) {
                    // The UI reports one categorical failure; provider details stay private.
                }
            }
        }
    }
}

internal fun verifyExactContent(input: InputStream, expected: ByteArray) {
    val expectedDigest = MessageDigest.getInstance("SHA-256").digest(expected)
    val actualDigest = MessageDigest.getInstance("SHA-256")
    var size = 0
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    while (size <= expected.size) {
        val remainingWithSentinel = expected.size + 1 - size
        val read = input.read(buffer, 0, minOf(buffer.size, remainingWithSentinel))
        if (read < 0) break
        if (read == 0) throw IOException()
        actualDigest.update(buffer, 0, read)
        size += read
        if (size > expected.size) throw IOException()
    }
    if (size != expected.size || !actualDigest.digest().contentEquals(expectedDigest)) {
        throw IOException()
    }
}
