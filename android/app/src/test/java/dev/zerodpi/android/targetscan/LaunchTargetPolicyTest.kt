package dev.zerodpi.android.targetscan

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LaunchTargetPolicyTest {
    private fun config(autoSelect: String): String = """
        MODE = "sni_spoof"
        AUTO_SELECT = $autoSelect
        SELECTED_SNI = ""
        SELECTED_IP = ""
    """.trimIndent()

    @Test
    fun consumesPinForRealRunsWithAutoSelectOff() {
        assertTrue(LaunchTargetPolicy.consumesPin(config("false"), modeOverride = null))
    }

    @Test
    fun doesNotConsumePinWhenAutoSelectIsOn() {
        assertFalse(LaunchTargetPolicy.consumesPin(config("true"), modeOverride = null))
    }

    @Test
    fun doesNotConsumePinForScanOrTestModeOverrides() {
        assertFalse(LaunchTargetPolicy.consumesPin(config("false"), modeOverride = "sni_scan"))
        assertFalse(LaunchTargetPolicy.consumesPin(config("false"), modeOverride = "ip_scan"))
        assertFalse(LaunchTargetPolicy.consumesPin(config("false"), modeOverride = "sni_method_scan"))
        assertFalse(LaunchTargetPolicy.consumesPin(config("false"), modeOverride = "ip_method_scan"))
    }

    @Test
    fun treatsMissingAutoSelectAsDefaultAutoSelectOff() {
        val noAutoSelectField = """
            MODE = "sni_spoof"
            SELECTED_SNI = ""
        """.trimIndent()
        assertTrue(LaunchTargetPolicy.consumesPin(noAutoSelectField, modeOverride = null))
    }
}
