package dev.zerodpi.android.service

import android.content.Context
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.ServiceTestRule
import dev.zerodpi.android.config.ZeroDpiConfigToml
import dev.zerodpi.android.profile.ZeroDpiProfile
import dev.zerodpi.android.storage.RuntimeFileKind
import dev.zerodpi.android.storage.RuntimeStorage
import dev.zerodpi.android.targetscan.PinKind
import dev.zerodpi.android.targetscan.TargetPin
import dev.zerodpi.android.targetscan.TargetPinCodec
import dev.zerodpi.android.targetscan.TargetScanFiles
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * End-to-end pick-session tests against the real [ZeroDpiService] with the
 * fake runner (active in debug builds when no native artifact is packaged).
 * The fake emits scan events and writes the pick scan results JSON, so the
 * full scan -> Choosing -> apply/cancel paths run against real code.
 */
@RunWith(AndroidJUnit4::class)
class TargetPickServiceInstrumentedTest {
    @get:Rule
    val serviceRule = ServiceTestRule()

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        runBlocking { clearRuntimeState() }
    }

    @Test
    fun startGateRunsPickScanThenApplyingPickStartsPinnedRun() = runBlocking {
        val storage = RuntimeStorage(context)
        val config = storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText
            .let { ZeroDpiConfigToml.replaceOrAppendField(it, "AUTO_SELECT", "false") }
        storage.save(ZeroDpiProfile.DEFAULT_PROFILE_ID, RuntimeFileKind.Config, config)
        val service = bindZeroDpiService()

        service.startZeroDpi() // gate fires: scan, not run

        // Scan events arrive (fake runner emits sni_scan flow), then Choosing.
        val choosing = service.waitForState { it.status == RuntimeStatus.Choosing }
        assertEquals(PickOrigin.StartGate, choosing.pickSession?.origin)
        assertEquals("sni_scan", choosing.pickSession?.mode)

        // Simulate the ViewModel pinning the picked target, then apply.
        val pinFile = pinFile(storage)
        pinFile.writeText(
            TargetPinCodec.encode(TargetPin(PinKind.Sni, "cloudflare.com", "1.1.1.1", 95, 1L)),
        )
        service.applyTargetPick()

        val running = service.waitForState { it.status == RuntimeStatus.Running }
        assertNull(running.pickSession)
        assertTrue(running.recentLogs.any { it.contains("Selected sni target cloudflare.com") })
    }

    @Test
    fun cancelFromStartGateStopsWithoutStarting() = runBlocking {
        val storage = RuntimeStorage(context)
        storage.save(
            ZeroDpiProfile.DEFAULT_PROFILE_ID,
            RuntimeFileKind.Config,
            ZeroDpiConfigToml.replaceOrAppendField(
                storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText,
                "AUTO_SELECT",
                "false",
            ),
        )
        val service = bindZeroDpiService()
        service.startZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Choosing }

        service.cancelTargetPick()

        val stopped = service.waitForState {
            it.status == RuntimeStatus.Stopped && it.lastExitCode == 0
        }
        assertNull(stopped.pickSession)
    }

    @Test
    fun midRunRescanStopsScansAndRelaunchesAfterPick() = runBlocking {
        val storage = RuntimeStorage(context)
        val config = storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText
            .let { ZeroDpiConfigToml.replaceOrAppendField(it, "AUTO_SELECT", "false") }
        storage.save(ZeroDpiProfile.DEFAULT_PROFILE_ID, RuntimeFileKind.Config, config)
        val service = bindZeroDpiService()
        // Seed a pin so the initial start runs directly.
        pinFile(storage).writeText(
            TargetPinCodec.encode(TargetPin(PinKind.Sni, "cloudflare.com", "1.1.1.1", 95, 1L)),
        )
        service.startZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Running }

        service.requestTargetPick(ZeroDpiProfile.DEFAULT_PROFILE_ID) // MidRun origin

        service.waitForState { it.status == RuntimeStatus.Choosing }
        // Replace the pin with a different target, then apply -> relaunch.
        pinFile(storage).writeText(
            TargetPinCodec.encode(TargetPin(PinKind.Sni, "speed.cloudflare.com", "1.1.1.1", 98, 2L)),
        )
        service.applyTargetPick()

        val running = service.waitForState { it.status == RuntimeStatus.Running }
        assertTrue(running.recentLogs.any { it.contains("Relaunching ZeroDPI") })
        assertNull(running.pickSession)
    }

    @Test
    fun cancelMidRunRescanRelaunchesPreviousRun() = runBlocking {
        val storage = RuntimeStorage(context)
        storage.save(
            ZeroDpiProfile.DEFAULT_PROFILE_ID,
            RuntimeFileKind.Config,
            ZeroDpiConfigToml.replaceOrAppendField(
                storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText,
                "AUTO_SELECT",
                "false",
            ),
        )
        val service = bindZeroDpiService()
        pinFile(storage).writeText(
            TargetPinCodec.encode(TargetPin(PinKind.Sni, "cloudflare.com", "1.1.1.1", 95, 1L)),
        )
        service.startZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Running }

        service.requestTargetPick(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        service.waitForState { it.status == RuntimeStatus.Choosing }

        service.cancelTargetPick()

        val resumed = service.waitForState { it.status == RuntimeStatus.Running }
        assertNull(resumed.pickSession)
    }

    @Test
    fun standalonePickFromStoppedEndsStoppedAfterApply() = runBlocking {
        val storage = RuntimeStorage(context)
        val service = bindZeroDpiService()
        service.requestTargetPick(ZeroDpiProfile.DEFAULT_PROFILE_ID) // stopped -> Standalone
        service.waitForState { it.status == RuntimeStatus.Choosing }
        pinFile(storage).writeText(
            TargetPinCodec.encode(TargetPin(PinKind.Ip, null, "104.16.132.229", 96, 3L)),
        )
        service.applyTargetPick()
        val stopped = service.waitForState {
            it.status == RuntimeStatus.Stopped && it.lastExitCode == 0
        }
        assertNull(stopped.pickSession)
    }

    @Test
    fun autoSelectOffPinnedRunNetworkRestartKeepsPinnedTargetWithoutScan() = runBlocking {
        val storage = RuntimeStorage(context)
        storage.save(
            ZeroDpiProfile.DEFAULT_PROFILE_ID,
            RuntimeFileKind.Config,
            ZeroDpiConfigToml.replaceOrAppendField(
                storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText,
                "AUTO_SELECT",
                "false",
            ),
        )
        val service = bindZeroDpiService()
        pinFile(storage).writeText(
            TargetPinCodec.encode(TargetPin(PinKind.Sni, "pinned.example.net", "1.1.1.1", 95, 1L)),
        )

        service.startZeroDpi()
        val running = service.waitForState { it.status == RuntimeStatus.Running }
        assertNull(running.pickSession)
        // The pinned run must not scan at launch: the pin reaches the run
        // config as SELECTED_SNI and the native skips its startup scan.
        assertTrue(running.recentLogs.none { it.contains("Started sni scan") })
        assertTrue(running.recentLogs.any { it.contains("Selected sni target pinned.example.net") })

        // A network change restarts the run with the same pinned target.
        service.requestAutomaticRestart()
        val restarted = service.waitForState {
            it.status == RuntimeStatus.Running &&
                it.recentLogs.any { line -> line.contains("Relaunching ZeroDPI") }
        }
        val relaunchIndex = restarted.recentLogs.indexOfFirst { it.contains("Relaunching ZeroDPI") }
        assertTrue(relaunchIndex >= 0)
        val relaunchLines = restarted.recentLogs.drop(relaunchIndex)
        // No scan, no pick session, and the same pinned target is selected.
        assertNull(restarted.pickSession)
        assertTrue(relaunchLines.none { it.contains("Started sni scan") })
        assertTrue(relaunchLines.any { it.contains("Selected sni target pinned.example.net") })
        // The relaunch config carried the pin as SELECTED_SNI.
        val configPath = relaunchLines.firstNotNullOfOrNull { line ->
            Regex("""Loaded config from (.+)\.$""").find(line)?.groupValues?.get(1)
        }
        assertNotNull(configPath)
        val runConfigText = File(configPath!!).readText()
        assertTrue(runConfigText.contains("SELECTED_SNI = \"pinned.example.net\""))

        service.stopZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Stopped && it.lastExitCode == 0 }
    }

    @Test
    fun autoSelectOffClearedPinNetworkRestartStopsInsteadOfScanning() = runBlocking {
        val storage = RuntimeStorage(context)
        storage.save(
            ZeroDpiProfile.DEFAULT_PROFILE_ID,
            RuntimeFileKind.Config,
            ZeroDpiConfigToml.replaceOrAppendField(
                storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText,
                "AUTO_SELECT",
                "false",
            ),
        )
        val service = bindZeroDpiService()
        val pin = pinFile(storage)
        pin.writeText(
            TargetPinCodec.encode(TargetPin(PinKind.Sni, "pinned.example.net", "1.1.1.1", 95, 1L)),
        )
        service.startZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Running }

        // Clear pin while running, then a network change: the automatic
        // restart must not scan on its own and must not open a pick session.
        pin.delete()
        service.requestAutomaticRestart()

        val stopped = service.waitForState {
            it.status == RuntimeStatus.Stopped && it.lastExitCode == 0
        }
        assertNull(stopped.pickSession)
        assertTrue(stopped.recentLogs.any { it.contains("stopping after the network change") })
        assertTrue(stopped.recentLogs.none { it.contains("Relaunching ZeroDPI") })
        assertTrue(stopped.recentLogs.none { it.contains("Started sni scan") })
    }

    // ---- helpers ----

    private suspend fun clearRuntimeState() {
        val storage = RuntimeStorage(context)
        val repositoryFiles = storage.ensureInitialized(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        File(repositoryFiles.runtimeDir, TargetScanFiles.PIN_FILE_NAME).delete()
        storage.deletePickScanResults(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        storage.clearLogs()
    }

    private suspend fun pinFile(storage: RuntimeStorage): File {
        val files = storage.ensureInitialized(ZeroDpiProfile.DEFAULT_PROFILE_ID)
        return File(files.runtimeDir, TargetScanFiles.PIN_FILE_NAME)
    }

    private fun bindZeroDpiService(): ZeroDpiService {
        val binder = serviceRule.bindService(Intent(context, ZeroDpiService::class.java))
        return (binder as ZeroDpiService.LocalBinder).service()
    }

    private fun ZeroDpiService.waitForState(
        timeoutMs: Long = 15_000L,
        condition: (ZeroDpiServiceState) -> Boolean,
    ): ZeroDpiServiceState {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val current = state().value
            if (condition(current)) {
                return current
            }
            Thread.sleep(50)
        }
        throw AssertionError("Timed out waiting for service state; last: ${state().value}")
    }
}
