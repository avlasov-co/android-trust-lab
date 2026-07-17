package org.androidtrustlab.observer.export

import java.io.ByteArrayInputStream
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class VerifiedDocumentPublisherTest {
    @Test
    fun successfulPublicationUsesTheExactVerifiedOrder() {
        val operations = FakeOperations()
        VerifiedDocumentPublisher(operations).publish("final.zip", byteArrayOf(1, 2, 3))

        assertEquals(
            listOf(
                "create",
                "capabilities:temporary",
                "write:temporary",
                "verify:temporary",
                "rename:temporary:final.zip",
                "metadata:final:final.zip:3",
                "verify:final",
            ),
            operations.events,
        )
    }

    @Test
    fun failuresBeforeAndAfterRenameCleanTheActiveDocument() {
        val missingCapabilities = FakeOperations(failAt = "capabilities")
        assertThrows(IOException::class.java) {
            VerifiedDocumentPublisher(missingCapabilities).publish("final.zip", byteArrayOf(1))
        }
        assertEquals(
            listOf("create", "capabilities:temporary", "delete:temporary"),
            missingCapabilities.events,
        )

        val renameFailure = FakeOperations(failAt = "rename")
        assertThrows(IOException::class.java) {
            VerifiedDocumentPublisher(renameFailure).publish("final.zip", byteArrayOf(1))
        }
        assertEquals("delete:temporary", renameFailure.events.last())

        val metadataMismatch = FakeOperations(failAt = "metadata")
        assertThrows(IOException::class.java) {
            VerifiedDocumentPublisher(metadataMismatch).publish("final.zip", byteArrayOf(1))
        }
        assertEquals("delete:final", metadataMismatch.events.last())
    }

    @Test
    fun cleanupFailureDoesNotReplaceThePublicationFailure() {
        val operations = FakeOperations(failAt = "write", failDelete = true)
        assertThrows(IOException::class.java) {
            VerifiedDocumentPublisher(operations).publish("final.zip", byteArrayOf(1))
        }
        assertEquals("delete:temporary", operations.events.last())
    }

    @Test
    fun readbackRejectsShortOverlongAndChangedContent() {
        val expected = byteArrayOf(1, 2, 3)
        verifyExactContent(ByteArrayInputStream(expected), expected)
        listOf(
            byteArrayOf(1, 2),
            byteArrayOf(1, 2, 3, 4),
            byteArrayOf(1, 9, 3),
        ).forEach { actual ->
            assertThrows(IOException::class.java) {
                verifyExactContent(ByteArrayInputStream(actual), expected)
            }
        }
    }

    private class FakeOperations(
        private val failAt: String? = null,
        private val failDelete: Boolean = false,
    ) : PublicationOperations<String> {
        val events = mutableListOf<String>()

        override fun createTemporary(): String {
            events += "create"
            fail("create")
            return "temporary"
        }

        override fun requirePublicationCapabilities(document: String) {
            events += "capabilities:$document"
            fail("capabilities")
        }

        override fun writeAndSync(document: String, bytes: ByteArray) {
            events += "write:$document"
            fail("write")
        }

        override fun verifyBytes(document: String, expected: ByteArray) {
            events += "verify:$document"
            fail(if (document == "temporary") "temporary_verify" else "final_verify")
        }

        override fun rename(document: String, finalName: String): String {
            events += "rename:$document:$finalName"
            fail("rename")
            return "final"
        }

        override fun verifyFinalMetadata(
            document: String,
            expectedName: String,
            expectedSize: Long,
        ) {
            events += "metadata:$document:$expectedName:$expectedSize"
            fail("metadata")
        }

        override fun delete(document: String) {
            events += "delete:$document"
            if (failDelete) throw IOException()
        }

        private fun fail(stage: String) {
            if (failAt == stage) throw IOException()
        }
    }
}
