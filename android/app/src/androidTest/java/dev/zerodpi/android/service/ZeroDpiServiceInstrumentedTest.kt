package dev.zerodpi.android.service

import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.ServiceTestRule
import dev.zerodpi.android.config.ZeroDpiConfigToml
import dev.zerodpi.android.profile.ProfileRepository
import dev.zerodpi.android.profile.ZeroDpiProfile
import dev.zerodpi.android.storage.RuntimeFileKind
import dev.zerodpi.android.storage.RuntimeStorage
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class ZeroDpiServiceInstrumentedTest {
    @get:Rule
    val serviceRule = ServiceTestRule()

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        clearRuntimeDir()
    }

    @Test
    fun fakeScanRunnerDrivesDashboardStateBackToStopped() {
        val service = bindZeroDpiService()

        service.startZeroDpi(modeOverride = "sni_scan")

        val scanning = service.waitForState { it.status == RuntimeStatus.Scanning }
        assertTrue(scanning.activeTarget.startsWith("Scanning sni"))

        val stopped = service.waitForState { it.status == RuntimeStatus.Stopped && it.lastExitCode == 0 }
        assertEquals(RootStatus.NotNeeded, stopped.rootStatus)
        assertEquals("None", stopped.activeTarget)
    }

    @Test
    fun notificationStopActionStopsRunningFakeRunner() {
        configureRootlessRunningMode()
        val service = bindZeroDpiService()

        service.startZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Running }

        service.onStartCommand(
            Intent(service, ZeroDpiService::class.java).setAction(ZeroDpiService.ACTION_STOP),
            0,
            0,
        )

        val stopped = service.waitForState { it.status == RuntimeStatus.Stopped && it.lastExitCode == 0 }
        assertEquals(0, stopped.connectionCount)
    }

    @Test
    fun startUsesExplicitProfileAndLogsProfileMetadata() {
        configureWorkProfile()
        val service = bindZeroDpiService()

        service.startZeroDpi(profileId = WORK_PROFILE_ID)

        val running = service.waitForState {
            it.status == RuntimeStatus.Running && it.listener == "127.0.0.1:45555"
        }
        assertTrue(running.recentLogs.any { it.contains("profile \"Work\" (id: work)") })
        assertTrue(
            running.recentLogs.any {
                it.contains("Profile runtime directory:") && it.contains("profiles") && it.contains("work")
            },
        )

        service.stopZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Stopped && it.lastExitCode == 0 }
    }

    @Test
    fun networkRestartPreservesProfileAndModeOverrideWithoutEndingForegroundRun() {
        configureWorkProfile()
        val service = bindZeroDpiService()

        service.startZeroDpi(profileId = WORK_PROFILE_ID, modeOverride = "ip_bypass")
        service.waitForState {
            it.status == RuntimeStatus.Running &&
                it.mode == "ip_bypass" &&
                it.listener == "127.0.0.1:45555"
        }

        service.requestAutomaticRestart()

        val restarting = service.state().value
        assertEquals(RuntimeStatus.Restarting, restarting.status)
        assertEquals("None", restarting.activeTarget)
        assertEquals(0, restarting.connectionCount)
        assertEquals(0L, restarting.relayBytes)
        assertTrue(restarting.recentLogs.any { it == "Restarting after network change." })
        assertTrue(ZeroDpiRuntimeStateStore.runtimeMarker(context).active)

        service.waitForState {
            it.status == RuntimeStatus.Running &&
                it.mode == "ip_bypass" &&
                it.listener == "127.0.0.1:45555" &&
                it.recentLogs.any { line -> line.contains("Relaunching ZeroDPI with profile \"Work\"") }
        }
        service.stopZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Stopped && it.lastExitCode == 0 }
    }

    @Test
    fun userStopCancelsPendingAutomaticRestart() {
        configureRootlessRunningMode()
        val service = bindZeroDpiService()
        service.startZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Running }

        service.requestAutomaticRestart()
        service.stopZeroDpi()

        val stopped = service.waitForState {
            it.status == RuntimeStatus.Stopped && it.lastExitCode == 0
        }
        assertTrue(stopped.recentLogs.none { it.startsWith("Relaunching ZeroDPI") })
    }

    @Test
    fun clearLogsRemovesMemoryAndPersistedSessionsWhileRunning() {
        configureRootlessRunningMode()
        val service = bindZeroDpiService()

        service.startZeroDpi()
        service.waitForState {
            it.status == RuntimeStatus.Running && it.recentLogs.isNotEmpty()
        }
        val logsDir = File(context.filesDir, "zerodpi/logs")

        service.clearLogs()

        service.waitForState { it.recentLogs.isEmpty() }
        val deadline = SystemClock.elapsedRealtime() + 5_000
        while (
            logsDir.listFiles().orEmpty().any { it.extension == "log" } &&
            SystemClock.elapsedRealtime() < deadline
        ) {
            SystemClock.sleep(50)
        }
        assertTrue(logsDir.listFiles().orEmpty().none { it.extension == "log" })

        service.stopZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Stopped && it.lastExitCode == 0 }
    }

    @Test
    fun selectedProfileConfigControlsWhetherRootIsRequested() {
        configureRootlessRunningMode()
        configureRootRequiredWorkProfile()
        val service = bindZeroDpiService()

        service.startZeroDpi(profileId = ZeroDpiProfile.DEFAULT_PROFILE_ID)

        val rootlessRunning = service.waitForState {
            it.status == RuntimeStatus.Running && it.listener == "127.0.0.1:44444"
        }
        assertEquals(RootStatus.NotNeeded, rootlessRunning.rootStatus)

        service.stopZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Stopped && it.lastExitCode == 0 }

        service.startZeroDpi(profileId = WORK_PROFILE_ID)

        val rootRequiredResult = service.waitForState(timeoutMs = 20_000) {
            (it.status == RuntimeStatus.Failed && it.rootStatus != RootStatus.NotNeeded) ||
                (it.status == RuntimeStatus.Running && it.rootStatus == RootStatus.Granted)
        }
        assertTrue(rootRequiredResult.rootStatus != RootStatus.NotNeeded)
        assertEquals("sni_spoof", rootRequiredResult.mode)
        assertEquals("wrong_seq", rootRequiredResult.bypassMethod)

        if (rootRequiredResult.status == RuntimeStatus.Running) {
            service.stopZeroDpi()
            service.waitForState { it.status == RuntimeStatus.Stopped && it.lastExitCode == 0 }
        }
    }

    private fun configureRootlessRunningMode() = runBlocking {
        val storage = RuntimeStorage(context)
        val rootlessConfig = storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText
            .replaceField("MODE", "sni_spoof")
            .replaceField("BYPASS_METHOD", "tls_frag")
            .replaceField("LISTEN_PORT", "44444")
        storage.save(ZeroDpiProfile.DEFAULT_PROFILE_ID, RuntimeFileKind.Config, rootlessConfig)
    }

    private fun configureWorkProfile() = runBlocking {
        val repository = ProfileRepository(
            context = context,
            idGenerator = { WORK_PROFILE_ID },
        )
        repository.loadIndex()
        repository.createProfile("Work")

        val storage = RuntimeStorage(context)
        val rootlessConfig = storage.readAll(WORK_PROFILE_ID).configText
            .replaceField("MODE", "sni_spoof")
            .replaceField("BYPASS_METHOD", "tls_frag")
            .replaceField("LISTEN_PORT", "45555")
        storage.save(WORK_PROFILE_ID, RuntimeFileKind.Config, rootlessConfig)
    }

    private fun configureRootRequiredWorkProfile() = runBlocking {
        val repository = ProfileRepository(
            context = context,
            idGenerator = { WORK_PROFILE_ID },
        )
        repository.loadIndex()
        repository.createProfile("Work")

        val storage = RuntimeStorage(context)
        val rootRequiredConfig = storage.readAll(WORK_PROFILE_ID).configText
            .replaceField("MODE", "sni_spoof")
            .replaceField("BYPASS_METHOD", "wrong_seq")
            .replaceField("LISTEN_PORT", "45666")
        storage.save(WORK_PROFILE_ID, RuntimeFileKind.Config, rootRequiredConfig)
    }

    private fun bindZeroDpiService(): ZeroDpiService {
        val binder = serviceRule.bindService(Intent(context, ZeroDpiService::class.java))
        return (binder as ZeroDpiService.LocalBinder).service()
    }

    private fun ZeroDpiService.waitForState(
        timeoutMs: Long = 6_000,
        predicate: (ZeroDpiServiceState) -> Boolean,
    ): ZeroDpiServiceState {
        val deadline = SystemClock.uptimeMillis() + timeoutMs
        var latest: ZeroDpiServiceState? = null
        while (SystemClock.uptimeMillis() < deadline) {
            val current = state().value
            latest = current
            if (predicate(current)) {
                return current
            }
            Thread.sleep(50)
        }
        fail("Timed out waiting for service state. Last state: $latest")
        throw AssertionError("unreachable")
    }

    private fun String.replaceField(fieldName: String, value: String): String =
        ZeroDpiConfigToml.replaceOrAppendField(this, fieldName, value)

    private fun clearRuntimeDir() {
        File(context.filesDir, "zerodpi").deleteRecursively()
    }

    private companion object {
        private const val WORK_PROFILE_ID = "work"
    }
}
