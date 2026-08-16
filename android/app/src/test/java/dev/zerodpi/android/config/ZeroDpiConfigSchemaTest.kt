package dev.zerodpi.android.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
    fun validationRejectsMissingRustRequiredListenerFields() {
        val editorState = ZeroDpiConfigToml.analyze(
            """
            MODE = "ip_bypass"
            BYPASS_METHOD = "tls_frag"
            SELECTED_IP = "1.1.1.1"
            """.trimIndent(),
        )

        assertFalse(editorState.canStart)
        assertTrue(editorState.issues.any { it.fieldName == "LISTEN_HOST" })
        assertTrue(editorState.issues.any { it.fieldName == "LISTEN_PORT" })
    }

    @Test
    fun customDnsValidationMatchesRustConfiguration() {
        val missingServer = ZeroDpiConfigToml.analyze(
            """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            CUSTOM_DNS_ENABLED = true
            CUSTOM_DNS_SERVER = ""
            """.trimIndent(),
        )
        assertFalse(missingServer.canStart)
        assertTrue(missingServer.issues.any { it.fieldName == "CUSTOM_DNS_SERVER" })

        for (server in listOf("1.1.1.1", "1.1.1.1:5353", "2606:4700:4700::1111", "[2606:4700:4700::1111]:5353")) {
            val validServer = ZeroDpiConfigToml.analyze(
                """
                LISTEN_HOST = "127.0.0.1"
                LISTEN_PORT = 44444
                CUSTOM_DNS_ENABLED = true
                CUSTOM_DNS_SERVER = "$server"
                """.trimIndent(),
            )
            assertTrue("Unexpected issues for $server: ${validServer.issues}", validServer.canStart)
        }

        for (server in listOf("dns.example.com", "1.1.1.1:0", "[2606:4700:4700::1111]:0")) {
            val invalidServer = ZeroDpiConfigToml.analyze(
                """
                LISTEN_HOST = "127.0.0.1"
                LISTEN_PORT = 44444
                CUSTOM_DNS_ENABLED = true
                CUSTOM_DNS_SERVER = "$server"
                """.trimIndent(),
            )
            assertFalse("Accepted invalid DNS server $server", invalidServer.canStart)
        }
    }

    @Test
    fun tomlEditRoundTripPreservesTypesEscapesAndComments() {
        val original = """
            # User-edited runtime config.
            LISTEN_HOST = "127.0.0.1" # keep listener note
            LISTEN_PORT = 44444
            AUTO_SELECT = false
            TLS_FRAG_PACKETS = "tlshello"
            TLS_FRAG_LENGTH = 4
        """.trimIndent()

        val edited = listOf(
            "LISTEN_HOST" to "vpn \"edge\"",
            "LISTEN_PORT" to "45678",
            "AUTO_SELECT" to "true",
            "TLS_FRAG_PACKETS" to "2-4",
            "TLS_FRAG_LENGTH" to "8-16",
        ).fold(original) { text, (field, value) ->
            ZeroDpiConfigToml.replaceOrAppendField(text, field, value)
        }
        val editorState = ZeroDpiConfigToml.analyze(edited)

        assertTrue(
            "Unexpected validation issues: ${editorState.issues}",
            editorState.canStart,
        )
        assertEquals("vpn \"edge\"", editorState.valueFor("LISTEN_HOST"))
        assertEquals("45678", editorState.valueFor("LISTEN_PORT"))
        assertEquals("true", editorState.valueFor("AUTO_SELECT"))
        assertEquals("2-4", editorState.valueFor("TLS_FRAG_PACKETS"))
        assertEquals("8-16", editorState.valueFor("TLS_FRAG_LENGTH"))
        assertTrue(edited.contains("""LISTEN_HOST = "vpn \"edge\"" # keep listener note"""))
        assertTrue(edited.contains("TLS_FRAG_LENGTH = \"8-16\""))
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

    @Test
    fun parsesTomlStringArrays() {
        assertEquals(listOf("wrong_seq", "tls_frag"), parseTomlStringArray("""["wrong_seq", "tls_frag"]"""))
        assertEquals(listOf("a\"b"), parseTomlStringArray("""["a\"b"]"""))
        assertNull(parseTomlStringArray("""["wrong_seq" "tls_frag"]"""))
        assertNull(parseTomlStringArray("""wrong_seq"""))
        assertNull(parseTomlStringArray("""["a", "b",]""")) // trailing comma invalid
        assertNull(parseTomlStringArray("""["unterminated]"""))
    }

    @Test
    fun expandsComboAliases() {
        assertEquals(listOf("wrong_seq", "wrong_md5"), expandMethodAlias("wrong_seq_wrong_md5"))
        assertEquals(listOf("tls_frag"), expandMethodAlias("tls_frag"))
    }

    @Test
    fun methodListAccessorReadsCanonicalArray() {
        val state = ZeroDpiConfigToml.analyze(
            """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "sni_spoof"
            BYPASS_METHOD = ["wrong_seq", "tls_frag"]
            """.trimIndent(),
        )
        assertEquals(listOf("wrong_seq", "tls_frag"), state.config.methodList("BYPASS_METHOD"))
        assertTrue(state.canStart)
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
