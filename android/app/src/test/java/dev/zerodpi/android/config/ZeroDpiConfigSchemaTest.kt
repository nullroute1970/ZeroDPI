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
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("sni_spoof", setOf("wrong_seq")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("sni_spoof", setOf("tls_frag")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("sni_spoof", setOf("ccs_prefix")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("sni_spoof", setOf("tls_frag", "ccs_prefix")))
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("sni_spoof", setOf("wrong_seq", "ccs_prefix")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("ip_bypass", setOf("wrong_seq")))
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("ip_bypass_plus", setOf("tls_record_frag")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("ip_bypass_plus", setOf("tls_frag")))
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("ip_bypass_plus", setOf("disorder")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("sni_scan", setOf("wrong_seq")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("ip_scan", setOf("wrong_seq")))
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("proxy_scan", setOf("wrong_seq")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("proxy_scan", setOf("tls_frag")))
        assertTrue(ZeroDpiConfigToml.requiresPacketInterception("sni_method_scan", setOf("wrong_seq")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("sni_method_scan", setOf("tls_frag", "ccs_prefix")))
        assertFalse(ZeroDpiConfigToml.requiresPacketInterception("ip_method_scan", setOf("tls_padding")))
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

    @Test
    fun schemaCoversEveryRustConfigField() {
        // existing schemaFieldsMatchRustConfigFields already asserts exact equality;
        // this duplicates it so the two new-field tasks have a scoped gate.
        val rustConfig = findRepoFile("crates/zerodpi-core/src/config.rs")
        val configBody = Regex("""(?s)pub struct Config\s*\{(.*?)\n\}""")
            .find(rustConfig.readText())!!.groupValues[1]
        val rustFields = Regex("""(?m)^\s+pub\s+([A-Z0-9_]+):""")
            .findAll(configBody).map { it.groupValues[1] }.toSet()
        val androidFields = ZeroDpiConfigSchema.fields.map { it.name }.toSet()
        val missing = rustFields - androidFields
        assertTrue("Android schema missing Rust fields: ${missing.sorted()}", missing.isEmpty())
    }

    @Test
    fun methodScanDefaultsMatchCore() {
        val state = ZeroDpiConfigToml.analyze("")
        assertEquals(16, state.config.methodList("METHOD_SCAN_METHODS").size)
        assertEquals("3", state.valueFor("METHOD_SCAN_SAMPLES"))
        assertEquals("1000", state.valueFor("METHOD_SCAN_INTERVAL_MS"))
        assertEquals("10", state.valueFor("METHOD_SCAN_TIMEOUT_SECS"))
        assertEquals("", state.valueFor("METHOD_SCAN_OUTPUT"))
        assertEquals("0x0303", state.valueFor("CCS_PREFIX_RECORD_VERSION"))
        assertEquals("5", state.valueFor("LOW_TTL_VALUE"))
        assertEquals("5000", state.valueFor("LOW_TTL_DISCOVER_TIMEOUT_MS"))
        assertEquals("24", state.valueFor("IP_FRAG_SIZE"))
        assertEquals("2", state.valueFor("DISORDER_SEGMENTS"))
        assertEquals("middle", state.valueFor("SNI_SPLIT_POSITION"))
        assertEquals("extension_length", state.valueFor("SNI_BOUNDARY_FRAG_SPLIT_POINT"))
        assertEquals("5-10", state.valueFor("SNI_BOUNDARY_FRAG_DELAY_MS"))
        assertEquals("1500-2500", state.valueFor("TLS_PADDING_SIZE"))
        assertEquals("before", state.valueFor("TLS_PADDING_POSITION"))
        assertEquals("false", state.valueFor("MIXED_CASE_SNI_FLIP_ALL"))
        assertTrue(ZeroDpiConfigSchema.methodScanModes.contains("sni_method_scan"))
    }

    @Test
    fun rejectsDisorderCombinedWithIpFrag() {
        val state = ZeroDpiConfigToml.analyze(
            """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "sni_spoof"
            BYPASS_METHOD = ["disorder", "ip_frag"]
            """.trimIndent(),
        )
        assertFalse(state.canStart)
        assertTrue(state.issues.any { it.fieldName == "BYPASS_METHOD" && "disorder" in it.message })
    }

    @Test
    fun acceptsCcsPrefixCombinedWithWrongSeq() {
        val state = ZeroDpiConfigToml.analyze(
            """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "sni_spoof"
            BYPASS_METHOD = ["wrong_seq", "ccs_prefix"]
            """.trimIndent(),
        )
        assertTrue("Unexpected issues: ${state.issues}", state.canStart)
    }

    @Test
    fun enforcesIpBypassPlusMethodAllowlist() {
        val state = ZeroDpiConfigToml.analyze(
            """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "ip_bypass_plus"
            BYPASS_METHOD = ["wrong_seq"]
            """.trimIndent(),
        )
        assertFalse(state.canStart)
        assertTrue(state.issues.any { it.fieldName == "BYPASS_METHOD" && "ip_bypass_plus" in it.message })
    }

    @Test
    fun validatesNewMethodParameters() {
        fun issuesFor(config: String) = ZeroDpiConfigToml.analyze(config).issues.map { it.fieldName }
        fun base(method: String) = """
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            MODE = "sni_spoof"
            BYPASS_METHOD = ["$method"]
            """.trimIndent() + "\n"
        assertTrue("IP_FRAG_SIZE" in issuesFor(base("ip_frag") + "IP_FRAG_SIZE = 26\n"))
        assertTrue("DISORDER_SEGMENTS" in issuesFor(base("disorder") + "DISORDER_SEGMENTS = 4\n"))
        assertTrue("DISORDER_DELAY_MS" in issuesFor(base("disorder") + "DISORDER_DELAY_MS = 2000\n"))
        assertTrue("LOW_TTL_VALUE" in issuesFor(base("low_ttl") + "LOW_TTL_VALUE = 0\n"))
        assertTrue("LOW_TTL_DISCOVER_TIMEOUT_MS" in issuesFor(base("low_ttl") + "LOW_TTL_DISCOVER_TIMEOUT_MS = 50\n"))
        assertTrue("TLS_PADDING_SIZE" in issuesFor(base("tls_padding") + "TLS_PADDING_SIZE = \"20000-30000\"\n"))
        assertTrue("TLS_PADDING_POSITION" in issuesFor(base("tls_padding") + "TLS_PADDING_POSITION = \"sideways\"\n"))
        assertTrue("CCS_PREFIX_RECORD_VERSION" in issuesFor(base("ccs_prefix") + "CCS_PREFIX_RECORD_VERSION = \"0x03\"\n"))
        assertTrue("SNI_SPLIT_POSITION" in issuesFor(base("urg_sni_split") + "SNI_SPLIT_POSITION = \"nope\"\n"))
        assertTrue("SNI_BOUNDARY_FRAG_SPLIT_POINT" in issuesFor(base("sni_boundary_frag") + "SNI_BOUNDARY_FRAG_SPLIT_POINT = \"nope\"\n"))
        assertTrue("SNI_BOUNDARY_FRAG_DELAY_MS" in issuesFor(base("sni_boundary_frag") + "SNI_BOUNDARY_FRAG_DELAY_MS = \"-5-10\"\n"))
        assertTrue("METHOD_SCAN_SAMPLES" in issuesFor(base("wrong_seq") + "METHOD_SCAN_SAMPLES = 0\n"))
        assertTrue("METHOD_SCAN_TIMEOUT_SECS" in issuesFor(base("wrong_seq") + "METHOD_SCAN_TIMEOUT_SECS = 0\n"))
        assertTrue("METHOD_SCAN_METHODS" in issuesFor(base("wrong_seq") + "METHOD_SCAN_METHODS = [\"bogus\"]\n"))
    }

    @Test
    fun validatesSniPositions() {
        assertNull(validateSniPosition("middle", setOf("middle", "start", "end")))
        assertNull(validateSniPosition("12", setOf("extension_length", "middle")))
        assertNull(validateSniPosition("0", setOf("extension_length", "middle")))
        assertNotNull(validateSniPosition("nope", setOf("middle", "start", "end")))
        assertNotNull(validateSniPosition("-1", setOf("middle", "start", "end")))
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
