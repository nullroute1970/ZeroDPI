package dev.zerodpi.android.service

import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.ServiceTestRule
import dev.zerodpi.android.config.ZeroDpiConfigToml
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

    private fun configureRootlessRunningMode() = runBlocking {
        val storage = RuntimeStorage(context)
        val rootlessConfig = storage.readAll(ZeroDpiProfile.DEFAULT_PROFILE_ID).configText
            .replaceField("MODE", "sni_spoof")
            .replaceField("BYPASS_METHOD", "tls_frag")
            .replaceField("LISTEN_PORT", "44444")
        storage.save(ZeroDpiProfile.DEFAULT_PROFILE_ID, RuntimeFileKind.Config, rootlessConfig)
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
}
