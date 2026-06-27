package dev.zerodpi.android.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ZeroDpiConfigSchemaTest {
    @Test
    fun schemaFieldsMatchRustConfigFields() {
        val rustConfig = findRepoFile("crates/zerodpi-core/src/config.rs")
        assertTrue("Missing Rust config source at ${rustConfig.absolutePath}", rustConfig.isFile)

        val configBody = Regex("""(?s)pub struct Config\s*\{(.*?)\n\}""")
            .find(rustConfig.readText())
            ?.groupValues
            ?.get(1)
            .orEmpty()
        val rustFields = Regex("""(?m)^\s+pub\s+([A-Z0-9_]+):""")
            .findAll(configBody)
            .map { it.groupValues[1] }
            .toSet()
        val androidFieldNames = ZeroDpiConfigSchema.fields.map { it.name }
        val androidFields = androidFieldNames.toSet()

        assertEquals("Android schema contains duplicate field names.", androidFields.size, androidFieldNames.size)
        assertEquals(rustFields, androidFields)
    }

    @Test
    fun validationRejectsInvalidStartConfigs() {
        val editorState = ZeroDpiConfigToml.analyze(
            """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            SCAN_TIMEOUT_SECS = 0
            BYPASS_TIMEOUT_SECS = 2
            BYPASS_METHOD = "wrong_seq"
            MODE = "sni_spoof"
            """.trimIndent(),
        )

        assertFalse(editorState.canStart)
        assertTrue(editorState.issues.any { it.fieldName == "SCAN_TIMEOUT_SECS" })
    }

    @Test
    fun validationRejectsMalformedRawTomlLines() {
        val editorState = ZeroDpiConfigToml.analyze(
            """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            NOT_A_CONFIG_FIELD = true
            [unexpected]
            """.trimIndent(),
        )

        assertFalse(editorState.canStart)
        assertTrue(editorState.issues.any { it.fieldName == "NOT_A_CONFIG_FIELD" })
        assertTrue(editorState.issues.any { it.fieldName == null })
    }

    @Test
    fun rootRequirementMatchesAndroidMatrix() {
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("sni_spoof", "wrong_seq"))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("sni_spoof", "tls_frag"))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("ip_bypass", "wrong_seq"))
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("ip_bypass_plus", "tls_record_frag"))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("ip_bypass_plus", "tls_frag"))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("sni_scan", "wrong_seq"))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("ip_scan", "wrong_seq"))
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("proxy_scan", "wrong_seq"))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("proxy_scan", "tls_frag"))
    }

    private fun findRepoFile(relativePath: String): File {
        var current = File("").absoluteFile
        while (true) {
            val candidate = File(current, relativePath)
            if (candidate.isFile) {
                return candidate
            }
            current = current.parentFile ?: return candidate
        }
    }
}
