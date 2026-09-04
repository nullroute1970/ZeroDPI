package dev.zerodpi.android.targetscan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TargetPickPolicyTest {
    @Test
    fun mapsModesToScanKinds() {
        assertEquals("sni_scan", TargetPickPolicy.scanModeFor("sni_spoof"))
        assertEquals("ip_scan", TargetPickPolicy.scanModeFor("ip_bypass"))
        assertEquals("ip_scan", TargetPickPolicy.scanModeFor("ip_bypass_plus"))
        assertNull(TargetPickPolicy.scanModeFor("sni_scan"))
        assertNull(TargetPickPolicy.scanModeFor("sni_method_scan"))
        assertNull(TargetPickPolicy.scanModeFor("proxy_scan"))
    }

    @Test
    fun mapsModesToPinKinds() {
        assertEquals(PinKind.Sni, TargetPickPolicy.pinKindForMode("sni_spoof"))
        assertEquals(PinKind.Ip, TargetPickPolicy.pinKindForMode("ip_bypass"))
        assertEquals(PinKind.Ip, TargetPickPolicy.pinKindForMode("ip_bypass_plus"))
        assertNull(TargetPickPolicy.pinKindForMode("ip_scan"))
    }

    private fun sniPin() = TargetPin(PinKind.Sni, "edge.example.com", "1.2.3.4", 95, 1L)
    private fun ipPin() = TargetPin(PinKind.Ip, null, "5.6.7.8", 96, 1L)

    @Test
    fun gateEligibilityRequiresAutoSelectOffAndNoManualSelection() {
        assertTrue(TargetPickPolicy.isGateEligible("sni_spoof", autoSelect = false, "", "", null))
        assertFalse(TargetPickPolicy.isGateEligible("sni_spoof", autoSelect = true, "", "", null))
        assertFalse(TargetPickPolicy.isGateEligible("sni_spoof", autoSelect = false, "manual.example", "", null))
        assertFalse(TargetPickPolicy.isGateEligible("ip_bypass", autoSelect = false, "", "1.2.3.4", null))
        assertFalse(TargetPickPolicy.isGateEligible("sni_scan", autoSelect = false, "", "", null))
    }

    @Test
    fun gateEligibilityIgnoresMismatchedPinKind() {
        assertFalse(TargetPickPolicy.isGateEligible("sni_spoof", autoSelect = false, "", "", sniPin()))
        assertTrue(TargetPickPolicy.isGateEligible("sni_spoof", autoSelect = false, "", "", ipPin()))
        assertFalse(TargetPickPolicy.isGateEligible("ip_bypass", autoSelect = false, "", "", ipPin()))
        assertTrue(TargetPickPolicy.isGateEligible("ip_bypass", autoSelect = false, "", "", sniPin()))
    }
}
