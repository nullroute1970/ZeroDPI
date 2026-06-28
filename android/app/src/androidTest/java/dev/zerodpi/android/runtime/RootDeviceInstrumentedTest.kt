package dev.zerodpi.android.runtime

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RootDeviceInstrumentedTest {
    @Test
    fun rootedDeviceDiagnosticsAreOptInAndSkippedWithoutRoot() = runBlocking {
        val runRootTests = InstrumentationRegistry.getArguments()
            .getString("zerodpi.runRootTests")
            .toBoolean()
        assumeTrue(
            "Rooted device diagnostics are skipped by default. Run with -e zerodpi.runRootTests true.",
            runRootTests,
        )

        val manager = SuRootManager()
        val rootAccess = manager.requestRootFor("instrumented rooted-device diagnostics")
        assumeTrue("Root was not granted on this device: ${rootAccess.message}", rootAccess.state == RootAccessState.Granted)

        val report = manager.runDiagnostics("iptables")

        assertEquals(RootAccessState.Granted, report.rootAccess.state)
        assertTrue(report.checks.any { it.label == "which iptables" })
        assertTrue(report.checks.any { it.label == "NFQUEUE kernel checks" })
    }
}
