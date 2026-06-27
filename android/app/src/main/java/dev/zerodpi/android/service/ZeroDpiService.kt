package dev.zerodpi.android.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import dev.zerodpi.android.R
import dev.zerodpi.android.runtime.FakeZeroDpiRunner
import dev.zerodpi.android.runtime.ProcessZeroDpiRunner
import dev.zerodpi.android.runtime.ZeroDpiRunRequest
import dev.zerodpi.android.runtime.ZeroDpiRunner
import dev.zerodpi.android.runtime.ZeroDpiRunnerEvent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.File

enum class RuntimeStatus {
    Stopped,
    Starting,
    Scanning,
    Running,
    Stopping,
    Failed,
}

data class ZeroDpiServiceState(
    val status: RuntimeStatus = RuntimeStatus.Stopped,
    val rootStatus: String = "Not needed",
    val mode: String = "sni_spoof",
    val bypassMethod: String = "tls_frag",
    val listener: String = "127.0.0.1:1080",
    val activeTarget: String = "None",
    val connectionCount: Int = 0,
    val relayBytes: Long = 0L,
    val lastError: String? = null,
    val recentLogs: List<String> = emptyList(),
)

class ZeroDpiService : Service() {
    private val binder = LocalBinder()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val state = MutableStateFlow(ZeroDpiServiceState())
    private lateinit var runner: ZeroDpiRunner

    override fun onCreate() {
        super.onCreate()
        runner = createRunner()
        scope.launch {
            runner.events().collect { event ->
                handleRunnerEvent(event)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureForeground()
        return START_STICKY
    }

    override fun onDestroy() {
        runBlocking {
            runner.stop()
        }
        scope.cancel()
        super.onDestroy()
    }

    fun state(): StateFlow<ZeroDpiServiceState> = state.asStateFlow()

    fun startZeroDpi() {
        ensureForeground()
        scope.launch {
            val runtimeDir = File(filesDir, "zerodpi").apply {
                mkdirs()
            }
            val request = ZeroDpiRunRequest(
                configPath = File(runtimeDir, "config.toml").absolutePath,
                workingDirectory = runtimeDir.absolutePath,
            )
            runner.start(request)
        }
    }

    fun stopZeroDpi() {
        state.update { it.copy(status = RuntimeStatus.Stopping) }
        scope.launch {
            runner.stop()
            stopForegroundCompat()
            stopSelf()
        }
    }

    private fun createRunner(): ZeroDpiRunner {
        val nativeExecutable = File(applicationInfo.nativeLibraryDir, "libzerodpi_exec.so")
        return if (nativeExecutable.isFile) {
            ProcessZeroDpiRunner(this, scope)
        } else {
            FakeZeroDpiRunner(scope)
        }
    }

    private fun handleRunnerEvent(event: ZeroDpiRunnerEvent) {
        when (event) {
            ZeroDpiRunnerEvent.Starting -> {
                state.update { it.copy(status = RuntimeStatus.Starting, lastError = null) }
            }
            ZeroDpiRunnerEvent.Scanning -> {
                state.update { it.copy(status = RuntimeStatus.Scanning, activeTarget = "Scanning...") }
            }
            ZeroDpiRunnerEvent.Running -> {
                state.update { it.copy(status = RuntimeStatus.Running, activeTarget = "cloudflare.com") }
            }
            is ZeroDpiRunnerEvent.Log -> {
                appendLog(event.message)
            }
            is ZeroDpiRunnerEvent.Failed -> {
                appendLog(event.message)
                state.update { it.copy(status = RuntimeStatus.Failed, lastError = event.message) }
            }
            is ZeroDpiRunnerEvent.Exited -> {
                appendLog("ZeroDPI exited with code ${event.exitCode}.")
                state.update {
                    it.copy(
                        status = if (event.exitCode == 0) RuntimeStatus.Stopped else RuntimeStatus.Failed,
                        lastError = if (event.exitCode == 0) null else "ZeroDPI exited with code ${event.exitCode}.",
                    )
                }
            }
        }
    }

    private fun appendLog(message: String) {
        state.update { current ->
            current.copy(recentLogs = (current.recentLogs + message).takeLast(12))
        }
    }

    private fun ensureForeground() {
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
    }

    @Suppress("DEPRECATION")
    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            stopForeground(true)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.zerodpi_notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_zerodpi)
            .setContentTitle(getString(R.string.zerodpi_notification_title))
            .setContentText("Listening for upstream VPN traffic.")
            .setOngoing(true)
            .build()

    inner class LocalBinder : Binder() {
        fun service(): ZeroDpiService = this@ZeroDpiService
    }

    companion object {
        private const val CHANNEL_ID = "zerodpi-runtime"
        private const val NOTIFICATION_ID = 1001
    }
}
