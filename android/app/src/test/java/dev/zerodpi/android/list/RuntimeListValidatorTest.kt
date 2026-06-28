package dev.zerodpi.android.list

import dev.zerodpi.android.storage.RuntimeFileKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RuntimeListValidatorTest {
    @Test
    fun sniListIgnoresCommentsAndBlankLines() {
        val result = RuntimeListValidator.validate(
            kind = RuntimeFileKind.SniList,
            text = """
                # comment

                cloudflare.com
                api.example.org
            """.trimIndent(),
            mode = "sni_scan",
        )

        assertTrue(result.isValid)
        assertEquals(2, result.activeEntries)
    }

    @Test
    fun sniListRejectsObviousInvalidHostnames() {
        val result = RuntimeListValidator.validate(
            kind = RuntimeFileKind.SniList,
            text = """
                https://example.com
                bad host.example
                _service.example
                104.16.132.229
            """.trimIndent(),
            mode = "sni_scan",
        )

        assertEquals(listOf(1, 2, 3, 4), result.issues.map { it.lineNumber })
    }

    @Test
    fun ipListAcceptsIpLiteralsAndCidr() {
        val result = RuntimeListValidator.validate(
            kind = RuntimeFileKind.IpList,
            text = """
                104.16.132.229
                2606:4700::6810:84e5
                104.16.0.0/20
                2606:4700::/32
            """.trimIndent(),
            mode = "ip_scan",
        )

        assertTrue(result.isValid)
        assertEquals(4, result.activeEntries)
    }

    @Test
    fun ipListRejectsHostnamesAndInvalidCidr() {
        val result = RuntimeListValidator.validate(
            kind = RuntimeFileKind.IpList,
            text = """
                cloudflare.com
                104.16.0.0/33
                2606:4700::/129
            """.trimIndent(),
            mode = "ip_scan",
        )

        assertEquals(listOf(1, 2, 3), result.issues.map { it.lineNumber })
    }

    @Test
    fun ipBypassPlusWarnsThatIpListMustBeIpv4Only() {
        val result = RuntimeListValidator.validate(
            kind = RuntimeFileKind.IpList,
            text = "104.16.132.229",
            mode = "ip_bypass_plus",
        )

        assertTrue(result.isValid)
        assertEquals(1, result.warnings.size)
    }
}
