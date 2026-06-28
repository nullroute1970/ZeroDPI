package dev.zerodpi.android.storage

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SupportBundleSanitizerTest {
    @Test
    fun sanitizedConfigRedactsSensitiveTargetsAndKeepsSafeFields() {
        val sanitized = SupportBundleSanitizer.sanitizedConfig(
            """
            LISTEN_PORT = 44444
            SELECTED_SNI = "private.example.com"
            SELECTED_IP = "203.0.113.10"
            SNI_LIST = "production_sni_list.txt"
            IP_LIST = "production_ip_list.txt"
            PROXY_TEST_URL = "https://private.example.com/probe"
            """.trimIndent(),
        )

        assertTrue(sanitized.contains("LISTEN_PORT = 44444"))
        assertTrue(sanitized.contains("SELECTED_SNI = \"<redacted>\""))
        assertTrue(sanitized.contains("SELECTED_IP = \"<redacted>\""))
        assertTrue(sanitized.contains("SNI_LIST = \"<redacted>\""))
        assertTrue(sanitized.contains("IP_LIST = \"<redacted>\""))
        assertTrue(sanitized.contains("PROXY_TEST_URL = \"<redacted>\""))
        assertFalse(sanitized.contains("private.example.com"))
        assertFalse(sanitized.contains("production_sni_list.txt"))
        assertFalse(sanitized.contains("production_ip_list.txt"))
    }

    @Test
    fun noticeStatesWhetherPrivateListsAreIncluded() {
        assertTrue(
            SupportBundleSanitizer.noticeText(includePrivateLists = false)
                .contains("Private SNI/IP lists were omitted"),
        )
        assertTrue(
            SupportBundleSanitizer.noticeText(includePrivateLists = true)
                .contains("explicitly included"),
        )
    }
}
