package dev.zerodpi.android.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import dev.zerodpi.android.BuildConfig
import dev.zerodpi.android.R
import dev.zerodpi.android.config.ZeroDpiConfigToml
import dev.zerodpi.android.profile.ProfileRepository
import dev.zerodpi.android.profile.ZeroDpiProfile
import dev.zerodpi.android.runtime.FakeZeroDpiRunner
import dev.zerodpi.android.runtime.ProcessZeroDpiRunner
import dev.zerodpi.android.runtime.RootAccessState
import dev.zerodpi.android.runtime.RootDiagnosticReport
import dev.zerodpi.android.runtime.RootManager
import dev.zerodpi.android.runtime.SuRootManager
import dev.zerodpi.android.runtime.ZeroDpiRunRequest
import dev.zerodpi.android.runtime.ZeroDpiRunner
import dev.zerodpi.android.runtime.ZeroDpiRunnerEvent
import dev.zerodpi.android.storage.RuntimeStorage
import dev.zerodpi.android.storage.RuntimeRunConfig
import dev.zerodpi.android.storage.TargetPinStore
import dev.zerodpi.android.targetscan.TargetPickPolicy
import dev.zerodpi.android.targetscan.TargetScanFiles
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File

enum class RuntimeStatus {
    Stopped,
    Starting,
    Scanning,
    Running,
    Restarting,
    Choosing,
    Stopping,
    Failed,
}

enum class RootStatus(val label: String) {
    NotNeeded("Not needed"),
    Needed("Needed"),
    Granted("Granted"),
    Denied("Denied"),
    Unsupported("Unsupported"),
}

data class ScanProgressInfo(
    val scan: String,
    val phase: String? = null,
    val completed: Int? = null,
    val total: Int? = null,
)

enum class PickPhase { Scanning, Choosing }

enum class PickOrigin { StartGate, MidRun, Standalone }

data class PickSessionUi(
    val phase: PickPhase,
    val origin: PickOrigin,
    val mode: String,
    val resumeAvailable: Boolean,
)

data class ZeroDpiServiceState(
    val status: RuntimeStatus = RuntimeStatus.Stopped,
    val rootStatus: RootStatus = RootStatus.Needed,
    val mode: String = "sni_spoof",
    val bypassMethod: String = "wrong_seq",
    val listener: String = "127.0.0.1:44444",
    val activeTarget: String = "None",
    val activeTargetScore: Int? = null,
    val scanProgress: ScanProgressInfo? = null,
    val nextScanAtElapsedRealtimeMs: Long? = null,
    val connectionCount: Int = 0,
    val relayBytes: Long = 0L,
    val lastError: String? = null,
    val lastExitCode: Int? = null,
    val recentLogs: List<String> = emptyList(),
    val forceStopAvailable: Boolean = false,
    val pickSession: PickSessionUi? = null,
)

class ZeroDpiService : Service() {
    private val binder = LocalBinder()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val logScope = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1))
    private val state = MutableStateFlow(ZeroDpiServiceState())
    private lateinit var runner: ZeroDpiRunner
    private lateinit var rootManager: RootManager
    private lateinit var runtimeStorage: RuntimeStorage
    private lateinit var profileRepository: ProfileRepository
    private val activeConnections = mutableSetOf<Int>()
    private val activeRelayBytes = mutableMapOf<Int, Long>()
    private val sessionLogLines = ArrayDeque<String>()
    private var completedRelayBytes = 0L
    private var networkMonitor: DefaultNetworkMonitor? = null
    private var activeRunSpec: ActiveRunSpec? = null
    private var launchJob: Job? = null
    private var restartStopInProgress = false
    private var automaticForceStopRequested = false
    private var userStopRequested = false
    private var restartExitSignal: CompletableDeferred<Unit>? = null
    private var restartStopTimeoutSignal: CompletableDeferred<Unit>? = null
    private lateinit var pinStore: TargetPinStore
    private var pickSession: PickSession? = null
    private var pickStage: PickStage? = null
    private var pickScanMode: String? = null
    private var pickCancelRequested = false

    override fun onCreate() {
        super.onCreate()
        if (!ZeroDpiRuntimeStateStore.isRuntimeActive(this)) {
            ZeroDpiRuntimeStateStore.markRuntimeInactive(this)
        }
        runtimeStorage = RuntimeStorage(this)
        profileRepository = ProfileRepository(this)
        rootManager = SuRootManager()
        pinStore = TargetPinStore(this)
        runner = createRunner()
        scope.launch {
            runner.events().collect { event ->
                handleRunnerEvent(event)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopZeroDpi()
            return START_NOT_STICKY
        }

        ensureForeground()
        return START_STICKY
    }

    override fun onDestroy() {
        networkMonitor?.stop()
        networkMonitor = null
        launchJob?.cancel()
        runBlocking {
            runner.stop()
            runner.forceStop()
            withTimeoutOrNull(LOG_FLUSH_TIMEOUT_MS) {
                logScope.coroutineContext[Job]?.children?.toList()?.joinAll()
            }
        }
        ZeroDpiRuntimeStateStore.markRuntimeInactive(this)
        logScope.cancel()
        scope.cancel()
        super.onDestroy()
    }

    fun state(): StateFlow<ZeroDpiServiceState> = state.asStateFlow()

    fun startZeroDpi(
        profileId: String = ZeroDpiProfile.DEFAULT_PROFILE_ID,
        modeOverride: String? = null,
    ) {
        ensureForeground()
        scope.launch {
            if (state.value.status in activeStatuses) {
                appendLog("ZeroDPI is already ${state.value.status.name.lowercase()}.")
                return@launch
            }
            val runSpec = ActiveRunSpec(profileId, modeOverride)
            activeRunSpec = runSpec
            userStopRequested = false
            restartStopInProgress = false
            automaticForceStopRequested = false
            ZeroDpiRuntimeStateStore.markRuntimeActive(this@ZeroDpiService, profileId = profileId)
            runCatching {
                runtimeStorage.startNewLogSession("runtime")
            }

            resetRuntimeCounters()
            sessionLogLines.clear()
            state.update {
                it.copy(
                    status = RuntimeStatus.Starting,
                    activeTarget = "None",
                    activeTargetScore = null,
                    scanProgress = null,
                    nextScanAtElapsedRealtimeMs = null,
                    connectionCount = 0,
                    relayBytes = 0L,
                    lastError = null,
                    lastExitCode = null,
                    recentLogs = emptyList(),
                    forceStopAvailable = false,
                )
            }
            startNetworkMonitoring()
            launchJob = scope.launch {
                launchRun(runSpec, isAutomaticRestart = false)
            }
        }
    }

    private suspend fun launchRun(
        runSpec: ActiveRunSpec,
        isAutomaticRestart: Boolean,
        preparedConfigOverride: RuntimeRunConfig? = null,
    ) {
        val profileId = runSpec.profileId
        val modeOverride = runSpec.modeOverride

        val runConfig = preparedConfigOverride ?: runCatching {
            runtimeStorage.prepareRunConfig(profileId = profileId, modeOverride = modeOverride)
        }.getOrElse { error ->
            if (error is CancellationException) {
                throw error
            }
            val message = error.message ?: "Failed to prepare runtime storage."
            appendLog(message)
            state.update { it.copy(status = RuntimeStatus.Failed, lastError = message) }
            finishForegroundRun()
            return
        }
        val profileName = runCatching {
            profileRepository.loadIndex().profiles.firstOrNull { profile -> profile.id == profileId }?.name
        }.getOrNull()
        val editorState = ZeroDpiConfigToml.analyze(runConfig.configText)
        val mode = runConfig.modeOverride ?: editorState.valueFor("MODE").ifBlank { "unknown" }
        val listenHost = editorState.valueFor("LISTEN_HOST").ifBlank { "127.0.0.1" }
        val listenPort = editorState.valueFor("LISTEN_PORT").ifBlank { "1080" }
        val bypassMethod = ZeroDpiConfigToml.displayMethodList(
            editorState.valueFor("BYPASS_METHOD"),
        ).ifBlank { "unknown" }
        val rootRequired = editorState.rootRequirement.requiresRoot

        // Target-pick gate: a real run (no mode override) whose config has
        // AUTO_SELECT off, no manual SELECTED_* and no stored pin of the
        // matching kind starts with a scan-and-choose session instead.
        if (modeOverride == null && pickSession == null && !userStopRequested) {
            val gateEligible = runCatching {
                TargetPickPolicy.isGateEligible(
                    mode = editorState.valueFor("MODE"),
                    autoSelect = editorState.valueFor("AUTO_SELECT") == "true",
                    selectedSni = editorState.valueFor("SELECTED_SNI"),
                    selectedIp = editorState.valueFor("SELECTED_IP"),
                    pin = pinStore.read(profileId),
                )
            }.getOrDefault(false)
            if (gateEligible) {
                networkMonitor?.stop()
                appendLog("AUTO_SELECT is off — scanning; choose a target after the scan.")
                pickSession = PickSession(profileId, PickOrigin.StartGate, resumeRunSpec = null)
                state.update {
                    it.copy(
                        pickSession = PickSessionUi(
                            PickPhase.Scanning,
                            PickOrigin.StartGate,
                            mode = "",
                            resumeAvailable = false,
                        ),
                    )
                }
                launchPickScan(pickSession!!)
                return
            }
        }
        resetRuntimeCounters()
        state.update {
            it.copy(
                status = RuntimeStatus.Starting,
                rootStatus = if (rootRequired) RootStatus.Needed else RootStatus.NotNeeded,
                mode = mode,
                bypassMethod = bypassMethod,
                listener = "$listenHost:$listenPort",
                activeTarget = "None",
                activeTargetScore = null,
                scanProgress = null,
                nextScanAtElapsedRealtimeMs = null,
                connectionCount = 0,
                relayBytes = 0L,
                lastError = null,
                lastExitCode = null,
                recentLogs = if (isAutomaticRestart) it.recentLogs else emptyList(),
                forceStopAvailable = false,
            )
        }
        appendLog(
            if (isAutomaticRestart) {
                "Relaunching ZeroDPI with profile ${profileDescription(profileId, profileName)}."
            } else {
                "Starting ZeroDPI with profile ${profileDescription(profileId, profileName)}."
            },
        )
        appendLog("Profile runtime directory: ${runConfig.files.runtimeDir.absolutePath}.")
        modeOverride?.let { modeName ->
            appendLog("Running temporary $modeName test scan config.")
        }
        if (rootRequired) {
            appendLog(editorState.rootRequirement.message)
            appendRootlessAlternatives(editorState.rootRequirement.alternatives)
            val rootResult = rootManager.requestRootFor("starting $mode with $bypassMethod")
            appendLog(rootResult.message)
            when (rootResult.state) {
                RootAccessState.Granted -> {
                    state.update { it.copy(rootStatus = RootStatus.Granted) }
                }
                RootAccessState.Denied -> {
                    failBeforeLaunch(rootStatus = RootStatus.Denied, message = rootResult.message)
                    return
                }
                RootAccessState.Unsupported -> {
                    failBeforeLaunch(rootStatus = RootStatus.Unsupported, message = rootResult.message)
                    return
                }
            }
        }

        val request = ZeroDpiRunRequest(
            configPath = runConfig.configFile.absolutePath,
            workingDirectory = runConfig.files.runtimeDir.absolutePath,
            useRoot = rootRequired,
            mode = mode,
            bypassMethod = bypassMethod,
            listenHost = listenHost,
            listenPort = listenPort.toIntOrNull() ?: 0,
        )
        runCatching { runner.start(request) }
            .onFailure { error ->
                if (error is CancellationException) {
                    throw error
                }
                val message = error.message ?: "Failed to launch ZeroDPI."
                appendLog(message)
                state.update { it.copy(status = RuntimeStatus.Failed, lastError = message) }
                finishForegroundRun()
            }
    }

    fun runRootDiagnostics(
        rootExplanation: String,
        rootlessAlternatives: List<String>,
        firewallBackend: String,
    ) {
        scope.launch {
            runCatching {
                runtimeStorage.startNewLogSession("diagnostics")
            }
            appendLog("Root diagnostics requested by user; invoking su.")
            appendLog(rootExplanation)
            appendRootlessAlternatives(rootlessAlternatives)

            val report = rootManager.runDiagnostics(firewallBackend)
            appendRootDiagnosticReport(report)
            state.update {
                it.copy(
                    rootStatus = when (report.rootAccess.state) {
                        RootAccessState.Granted -> RootStatus.Granted
                        RootAccessState.Denied -> RootStatus.Denied
                        RootAccessState.Unsupported -> RootStatus.Unsupported
                    },
                    lastError = if (report.rootAccess.state == RootAccessState.Granted) {
                        null
                    } else {
                        report.rootAccess.message
                    },
                )
            }
        }
    }

    fun stopZeroDpi() {
        userStopRequested = true
        clearPickSession()
        networkMonitor?.stop()
        launchJob?.cancel()
        ZeroDpiRuntimeStateStore.markRuntimeActive(this, activeRunSpec?.profileId)
        state.update { it.copy(status = RuntimeStatus.Stopping, forceStopAvailable = false) }
        if (!restartStopInProgress) {
            scope.launch {
                runner.stop()
            }
        }
    }

    fun forceStopZeroDpi() {
        userStopRequested = true
        clearPickSession()
        networkMonitor?.stop()
        launchJob?.cancel()
        ZeroDpiRuntimeStateStore.markRuntimeActive(this, activeRunSpec?.profileId)
        state.update { it.copy(status = RuntimeStatus.Stopping, forceStopAvailable = false) }
        scope.launch {
            runner.forceStop()
        }
    }

    // -------------------------------------------------------------------
    // Target pick sessions
    // -------------------------------------------------------------------

    /**
     * Starts an interactive scan-and-choose session. While a session is
     * active the runtime is stopped (or never started); the ViewModel writes
     * the picked target pin and then calls [applyTargetPick], or calls
     * [cancelTargetPick] to abort. Origin is derived from the current status:
     * a running runtime becomes a MidRun session that resumes the previous
     * run after the session resolves.
     */
    fun requestTargetPick(profileId: String) {
        val currentStatus = state.value.status
        when {
            pickSession != null || restartStopInProgress -> {
                appendLog("A target pick session is already in progress.")
            }
            currentStatus in networkRestartableStatuses -> {
                val resume = activeRunSpec ?: run {
                    appendLog("Cannot re-scan: no active run to resume.")
                    return
                }
                networkMonitor?.stop()
                pickSession = PickSession(profileId, PickOrigin.MidRun, resume)
                pickStage = PickStage.StoppingForRescan
                state.update {
                    it.copy(
                        status = RuntimeStatus.Restarting,
                        pickSession = PickSessionUi(
                            PickPhase.Scanning,
                            PickOrigin.MidRun,
                            mode = "",
                            resumeAvailable = true,
                        ),
                        activeTarget = "None",
                        activeTargetScore = null,
                        scanProgress = null,
                    )
                }
                appendLog("Stopping to scan for a new target.")
                scope.launch { runner.stop() }
            }
            currentStatus == RuntimeStatus.Stopped || currentStatus == RuntimeStatus.Failed -> {
                ensureForeground()
                pickSession = PickSession(profileId, PickOrigin.Standalone, resumeRunSpec = null)
                state.update {
                    it.copy(
                        pickSession = PickSessionUi(
                            PickPhase.Scanning,
                            PickOrigin.Standalone,
                            mode = "",
                            resumeAvailable = false,
                        ),
                    )
                }
                launchPickScan(pickSession!!)
            }
            else -> appendLog("Target picking is unavailable while ${currentStatus.name.lowercase()}.")
        }
    }

    /** Applies the ViewModel's already-stored pin and resolves the session. */
    fun applyTargetPick() {
        if (pickStage != PickStage.Choosing) {
            appendLog("No target pick waiting to be applied.")
            return
        }
        appendLog("Target pinned. Applying selection.")
        resolvePickSession(startAfterPick = true)
    }

    /** Aborts the session without touching the stored pin. */
    fun cancelTargetPick() {
        when (pickStage) {
            PickStage.Choosing -> {
                appendLog("Target pick cancelled.")
                resolvePickSession(startAfterPick = false)
            }
            PickStage.Scanning -> {
                pickCancelRequested = true
                scope.launch { runner.stop() }
            }
            null, PickStage.StoppingForRescan -> {
                appendLog("No target pick is waiting for input.")
            }
        }
    }

    /**
     * Shared resolution after a pick session ends (apply or cancel):
     * MidRun sessions resume the previous run; StartGate sessions either
     * start the pinned run (apply) or finish (cancel); Standalone sessions
     * always finish — the pin is applied on the next manual Start.
     */
    private fun resolvePickSession(startAfterPick: Boolean) {
        val session = pickSession ?: return
        val resume = session.resumeRunSpec
        clearPickSession()
        when (session.origin) {
            PickOrigin.MidRun -> {
                if (resume != null && !userStopRequested) {
                    launchJob = scope.launch {
                        launchRun(resume, isAutomaticRestart = true)
                    }
                } else {
                    finishAfterExit(0)
                }
            }
            PickOrigin.StartGate -> {
                if (startAfterPick && !userStopRequested) {
                    state.update {
                        it.copy(status = RuntimeStatus.Stopped, pickSession = null)
                    }
                    startZeroDpi(profileId = session.profileId)
                } else {
                    appendLog("Start aborted — no target selected.")
                    finishAfterExit(0)
                }
            }
            PickOrigin.Standalone -> {
                if (startAfterPick) {
                    appendLog("Target pinned — start ZeroDPI when ready.")
                }
                finishAfterExit(0)
            }
        }
    }

    private fun launchPickScan(session: PickSession) {
        scope.launch {
            val userMode = runCatching {
                ZeroDpiConfigToml.analyze(
                    runtimeStorage.readAll(session.profileId).configText,
                ).valueFor("MODE")
            }.getOrDefault("sni_spoof")
            val scanMode = TargetPickPolicy.scanModeFor(userMode)
            if (scanMode == null) {
                failPickSession("MODE '$userMode' does not support target picking.", session)
                return@launch
            }
            pickScanMode = scanMode
            val runConfig = runCatching {
                runtimeStorage.prepareRunConfig(
                    profileId = session.profileId,
                    modeOverride = scanMode,
                    patchFields = mapOf(
                        "SCAN_OUTPUT" to TargetScanFiles.PICK_SCAN_RESULTS_FILE_NAME,
                    ),
                )
            }.getOrElse { error ->
                if (error is CancellationException) {
                    throw error
                }
                failPickSession(
                    error.message ?: "Could not prepare the pick scan config.",
                    session,
                )
                return@launch
            }
            runtimeStorage.deletePickScanResults(session.profileId)
            pickStage = PickStage.Scanning
            launchRun(
                ActiveRunSpec(profileId = session.profileId, modeOverride = scanMode),
                isAutomaticRestart = false,
                preparedConfigOverride = runConfig,
            )
        }
    }

    private fun failPickSession(message: String, session: PickSession) {
        appendLog(message)
        val resume = session.resumeRunSpec
        clearPickSession()
        if (session.origin == PickOrigin.MidRun && resume != null && !userStopRequested) {
            appendLog("Resuming the previous run.")
            launchJob = scope.launch {
                launchRun(resume, isAutomaticRestart = true)
            }
        } else {
            state.update { it.copy(status = RuntimeStatus.Failed, lastError = message) }
            finishForegroundRun()
        }
    }

    private fun clearPickSession() {
        pickSession = null
        pickStage = null
        pickScanMode = null
        pickCancelRequested = false
        state.update { it.copy(pickSession = null) }
    }

    internal fun requestAutomaticRestart() {
        if (
            userStopRequested ||
            activeRunSpec == null ||
            state.value.status !in networkRestartableStatuses
        ) {
            return
        }
        if (restartStopInProgress) {
            return
        }

        restartStopInProgress = true
        automaticForceStopRequested = false
        restartExitSignal = CompletableDeferred()
        restartStopTimeoutSignal = CompletableDeferred()
        launchJob?.cancel()
        resetRuntimeCounters()
        state.update {
            it.copy(
                status = RuntimeStatus.Restarting,
                activeTarget = "None",
                activeTargetScore = null,
                scanProgress = null,
                nextScanAtElapsedRealtimeMs = null,
                connectionCount = 0,
                relayBytes = 0L,
                lastError = null,
                lastExitCode = null,
                forceStopAvailable = false,
            )
        }
        appendLog("Restarting after network change.")
        scope.launch { performAutomaticRestartShutdown() }
    }

    fun clearLogs() {
        sessionLogLines.clear()
        state.update { current ->
            current.copy(recentLogs = emptyList())
        }
        logScope.launch {
            runCatching { runtimeStorage.clearLogs() }
                .onFailure { error ->
                    state.update { current ->
                        current.copy(lastError = "Could not clear logs: ${error.message}")
                    }
                }
        }
    }

    private fun createRunner(): ZeroDpiRunner {
        val nativeExecutable = File(applicationInfo.nativeLibraryDir, "libzerodpi_exec.so")
        if (nativeExecutable.isFile) {
            return ProcessZeroDpiRunner(this, scope, rootManager)
        }
        if (BuildConfig.ZERODPI_ALLOW_FAKE_RUNNER) {
            return FakeZeroDpiRunner(scope)
        }
        return ProcessZeroDpiRunner(this, scope, rootManager)
    }

    private fun handleRunnerEvent(event: ZeroDpiRunnerEvent) {
        when (event) {
            ZeroDpiRunnerEvent.Starting -> {
                state.update {
                    it.copy(
                        status = RuntimeStatus.Starting,
                        lastError = null,
                        forceStopAvailable = false,
                    )
                }
            }
            ZeroDpiRunnerEvent.RootHelperStarting -> {
                appendLog("Starting privileged packet-interception helper.")
            }
            is ZeroDpiRunnerEvent.RootHelperAuthenticated -> {
                appendLog("Root helper authenticated with pid ${event.pid} and uid ${event.uid}.")
            }
            is ZeroDpiRunnerEvent.DataPlaneStarted -> {
                appendLog("Data plane started with pid ${event.pid} and app uid ${event.uid}.")
            }
            is ZeroDpiRunnerEvent.FirewallCleanup -> {
                appendLog(
                    if (event.completed) "Root-helper firewall cleanup completed."
                    else "Root-helper firewall cleanup could not be confirmed.",
                )
            }
            is ZeroDpiRunnerEvent.ConfigLoaded -> {
                state.update {
                    it.copy(
                        rootStatus = if (event.rootRequired && it.rootStatus != RootStatus.Granted) {
                            RootStatus.Needed
                        } else if (event.rootRequired) {
                            RootStatus.Granted
                        } else {
                            RootStatus.NotNeeded
                        },
                        mode = event.mode.ifBlank { it.mode },
                        bypassMethod = event.bypassMethod.ifBlank { it.bypassMethod },
                        listener = "${event.listenHost}:${event.listenPort}",
                    )
                }
                appendLog("Loaded ${event.mode} config for ${event.listenHost}:${event.listenPort}.")
            }
            is ZeroDpiRunnerEvent.ScanStarted -> {
                val total = event.total?.let { " ($it candidates)" }.orEmpty()
                state.update {
                    it.copy(
                        status = RuntimeStatus.Scanning,
                        activeTarget = "Scanning ${event.scan}$total",
                        activeTargetScore = null,
                        scanProgress = ScanProgressInfo(scan = event.scan, total = event.total),
                    )
                }
                appendLog("Started ${event.scan} scan$total.")
            }
            is ZeroDpiRunnerEvent.ScanProgress -> {
                val progress = event.total?.let { "${event.completed}/$it" } ?: event.completed.toString()
                state.update {
                    it.copy(
                        status = RuntimeStatus.Scanning,
                        activeTarget = displayTarget(event.sni, event.ip).ifBlank { "Scanning ${event.scan}" },
                        activeTargetScore = event.score,
                        scanProgress = ScanProgressInfo(
                            scan = event.scan,
                            phase = event.phase,
                            completed = event.completed,
                            total = event.total,
                        ),
                    )
                }
                appendLog("${event.scan} scan progress: $progress.")
            }
            is ZeroDpiRunnerEvent.ScanCompleted -> {
                state.update { it.copy(scanProgress = null) }
                appendLog("${event.scan} scan completed with ${event.results} result(s).")
            }
            is ZeroDpiRunnerEvent.NextScanScheduled -> {
                state.update {
                    it.copy(
                        nextScanAtElapsedRealtimeMs =
                            SystemClock.elapsedRealtime() + event.intervalSeconds * 1_000L,
                    )
                }
            }
            is ZeroDpiRunnerEvent.SelectedTarget -> {
                state.update {
                    it.copy(
                        activeTarget = displayTarget(event.sni, event.ip),
                        activeTargetScore = event.score,
                    )
                }
                appendLog("Selected ${event.target} target ${displayTarget(event.sni, event.ip)}.")
            }
            is ZeroDpiRunnerEvent.ListenerStarted -> {
                state.update {
                    it.copy(
                        status = RuntimeStatus.Running,
                        mode = event.mode.ifBlank { it.mode },
                        listener = event.listenAddress.ifBlank { it.listener },
                    )
                }
                appendLog("Listening on ${event.listenAddress}.")
            }
            is ZeroDpiRunnerEvent.ConnectionAccepted -> {
                activeConnections += event.sourcePort
                state.update { it.copy(connectionCount = activeConnections.size) }
                appendLog("Accepted connection from ${event.peer}.")
            }
            is ZeroDpiRunnerEvent.BypassFinished -> {
                if (event.status == "failed") {
                    activeConnections -= event.sourcePort
                }
                state.update { it.copy(connectionCount = activeConnections.size) }
                appendLog("Bypass ${event.status} for source port ${event.sourcePort}.")
            }
            is ZeroDpiRunnerEvent.RelayBytes -> {
                val bytes = event.clientToServerBytes + event.serverToClientBytes
                if (event.isFinal) {
                    completedRelayBytes += bytes
                    activeRelayBytes -= event.sourcePort
                    activeConnections -= event.sourcePort
                } else {
                    activeRelayBytes[event.sourcePort] = bytes
                }
                state.update {
                    it.copy(
                        connectionCount = activeConnections.size,
                        relayBytes = completedRelayBytes + activeRelayBytes.values.sum(),
                    )
                }
                if (event.isFinal) {
                    appendLog("Relay finished on source port ${event.sourcePort} with $bytes bytes.")
                }
            }
            is ZeroDpiRunnerEvent.ActiveTargetChanged -> {
                state.update {
                    it.copy(
                        activeTarget = displayTarget(event.sni, event.ip),
                        activeTargetScore = event.score,
                    )
                }
                appendLog("Active ${event.target} target changed to ${displayTarget(event.sni, event.ip)}.")
            }
            is ZeroDpiRunnerEvent.RootRequired -> {
                val rootStatus = if (state.value.rootStatus == RootStatus.Granted) {
                    RootStatus.Unsupported
                } else {
                    RootStatus.Needed
                }
                appendLog(event.message)
                if (event.alternatives.isNotEmpty()) {
                    appendLog("Rootless alternatives: ${event.alternatives.joinToString()}.")
                }
                state.update {
                    it.copy(
                        status = RuntimeStatus.Failed,
                        rootStatus = rootStatus,
                        lastError = event.message,
                    )
                }
            }
            is ZeroDpiRunnerEvent.FatalError -> {
                if (pickStage == PickStage.Scanning && pickSession != null) {
                    failPickSession(event.message, pickSession!!)
                    return
                }
                appendLog(event.message)
                state.update { it.copy(status = RuntimeStatus.Failed, lastError = event.message) }
            }
            is ZeroDpiRunnerEvent.GracefulShutdown -> {
                appendLog("Graceful shutdown: ${event.reason}.")
            }
            is ZeroDpiRunnerEvent.Log -> {
                appendLog(event.message)
            }
            is ZeroDpiRunnerEvent.Failed -> {
                if (pickStage == PickStage.Scanning && pickSession != null) {
                    failPickSession(event.message, pickSession!!)
                    return
                }
                appendLog(event.message)
                state.update { it.copy(status = RuntimeStatus.Failed, lastError = event.message) }
                finishForegroundRun()
            }
            is ZeroDpiRunnerEvent.Exited -> {
                appendLog("ZeroDPI exited with code ${event.exitCode}.")
                activeConnections.clear()
                activeRelayBytes.clear()
                when {
                    pickStage == PickStage.StoppingForRescan && !userStopRequested -> {
                        if (event.exitCode == 0) {
                            val session = pickSession
                            if (session != null) {
                                launchPickScan(session) // sets pickStage = Scanning
                            } else {
                                finishAfterExit(event.exitCode)
                            }
                        } else {
                            appendLog("Could not stop the running ZeroDPI for a target pick.")
                            resolvePickSession(startAfterPick = false)
                        }
                        return
                    }
                    pickStage == PickStage.Scanning &&
                        event.exitCode == 0 &&
                        !pickCancelRequested &&
                        !userStopRequested -> {
                        pickStage = PickStage.Choosing
                        state.update {
                            it.copy(
                                status = RuntimeStatus.Choosing,
                                pickSession = PickSessionUi(
                                    phase = PickPhase.Choosing,
                                    origin = pickSession?.origin ?: PickOrigin.Standalone,
                                    mode = pickScanMode.orEmpty(),
                                    resumeAvailable = pickSession?.resumeRunSpec != null,
                                ),
                                scanProgress = null,
                                activeTarget = "Choose a target",
                                activeTargetScore = null,
                            )
                        }
                        appendLog("Scan finished — choose a target from the picker.")
                        return
                    }
                    pickStage == PickStage.Scanning && pickCancelRequested -> {
                        val session = pickSession
                        clearPickSession()
                        if (session?.origin == PickOrigin.MidRun && session.resumeRunSpec != null) {
                            appendLog("Target pick cancelled — resuming the previous run.")
                            launchJob = scope.launch {
                                launchRun(session.resumeRunSpec!!, isAutomaticRestart = true)
                            }
                        } else {
                            finishAfterExit(event.exitCode)
                        }
                        return
                    }
                }
                if (restartStopInProgress) {
                    restartExitSignal?.complete(Unit)
                    if (userStopRequested) {
                        finishAfterExit(event.exitCode)
                    }
                    return
                }
                finishAfterExit(event.exitCode)
            }
            ZeroDpiRunnerEvent.StopTimedOut -> {
                if (restartStopInProgress) {
                    restartStopTimeoutSignal?.complete(Unit)
                }
                if (restartStopInProgress && !userStopRequested) {
                    if (!automaticForceStopRequested) {
                        automaticForceStopRequested = true
                        appendLog("Graceful restart shutdown timed out; force-stopping ZeroDPI.")
                    }
                    return
                }
                val message = "Graceful stop timed out. Force stop is available."
                appendLog(message)
                state.update {
                    it.copy(
                        status = RuntimeStatus.Stopping,
                        forceStopAvailable = true,
                        lastError = message,
                    )
                }
            }
        }
    }

    private fun resetRuntimeCounters() {
        activeConnections.clear()
        activeRelayBytes.clear()
        completedRelayBytes = 0L
    }

    private suspend fun performAutomaticRestartShutdown() {
        runner.stop()
        val exitSignal = restartExitSignal ?: return
        val timeoutSignal = restartStopTimeoutSignal ?: return
        val gracefulStopTimedOut = select {
            exitSignal.onAwait { false }
            timeoutSignal.onAwait { true }
        }
        if (gracefulStopTimedOut && !userStopRequested) {
            runner.forceStop()
            exitSignal.await()
        }
        if (userStopRequested || !restartStopInProgress) {
            return
        }

        val runSpec = activeRunSpec
        restartStopInProgress = false
        automaticForceStopRequested = false
        restartExitSignal = null
        restartStopTimeoutSignal = null
        if (runSpec == null) {
            state.update {
                it.copy(
                    status = RuntimeStatus.Failed,
                    lastError = "Could not restore the active run after a network change.",
                )
            }
            finishForegroundRun()
            return
        }
        launchJob = scope.launch {
            launchRun(runSpec, isAutomaticRestart = true)
        }
    }

    private fun finishAfterExit(exitCode: Int) {
        clearPickSession()
        restartStopInProgress = false
        automaticForceStopRequested = false
        restartExitSignal = null
        restartStopTimeoutSignal = null
        state.update {
            it.copy(
                status = if (exitCode == 0) RuntimeStatus.Stopped else RuntimeStatus.Failed,
                activeTarget = if (exitCode == 0) "None" else it.activeTarget,
                activeTargetScore = if (exitCode == 0) null else it.activeTargetScore,
                nextScanAtElapsedRealtimeMs = null,
                connectionCount = 0,
                lastExitCode = exitCode,
                forceStopAvailable = false,
                lastError = if (exitCode == 0) null else "ZeroDPI exited with code $exitCode.",
            )
        }
        finishForegroundRun()
    }

    private fun failBeforeLaunch(rootStatus: RootStatus, message: String) {
        state.update {
            it.copy(
                status = RuntimeStatus.Failed,
                rootStatus = rootStatus,
                lastError = message,
                forceStopAvailable = false,
            )
        }
        finishForegroundRun()
    }

    private fun startNetworkMonitoring() {
        networkMonitor?.stop()
        networkMonitor = DefaultNetworkMonitor(
            context = this,
            scope = scope,
            onStableNetworkChange = ::requestAutomaticRestart,
        ).also(DefaultNetworkMonitor::start)
    }

    private fun appendRootDiagnosticReport(report: RootDiagnosticReport) {
        appendLog(report.rootAccess.message)
        report.rootAccess.commandResult?.let { result ->
            appendLog(result.diagnosticLine())
        }
        report.checks.forEach { result ->
            appendLog(result.diagnosticLine())
        }
        report.skipped.forEach { message ->
            appendLog(message)
        }
    }

    private fun appendLog(message: String) {
        val line = message.trimEnd()
        if (line.isBlank()) {
            return
        }
        sessionLogLines.addLast(line)
        while (sessionLogLines.size > MAX_SESSION_LOG_LINES) {
            sessionLogLines.removeFirst()
        }
        state.update { current ->
            current.copy(recentLogs = (current.recentLogs + line).takeLast(MAX_RECENT_LOG_LINES))
        }
        logScope.launch {
            runtimeStorage.appendLogLine(line)
        }
    }

    private fun appendRootlessAlternatives(alternatives: List<String>) {
        if (alternatives.isNotEmpty()) {
            appendLog("Rootless alternatives: ${alternatives.joinToString()}.")
        }
    }

    private fun displayTarget(sni: String?, ip: String?): String =
        when {
            !sni.isNullOrBlank() && !ip.isNullOrBlank() -> "$sni ($ip)"
            !sni.isNullOrBlank() -> sni
            !ip.isNullOrBlank() -> ip
            else -> "None"
        }

    private fun profileDescription(profileId: String, profileName: String?): String =
        if (profileName.isNullOrBlank()) {
            "id $profileId"
        } else {
            "\"${profileName.sanitizeForLog()}\" (id: $profileId)"
        }

    private fun String.sanitizeForLog(): String =
        replace('\r', ' ').replace('\n', ' ')

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

    private fun finishForegroundRun() {
        clearPickSession()
        networkMonitor?.stop()
        networkMonitor = null
        launchJob = null
        activeRunSpec = null
        restartStopInProgress = false
        automaticForceStopRequested = false
        restartExitSignal = null
        restartStopTimeoutSignal = null
        ZeroDpiRuntimeStateStore.markRuntimeInactive(this)
        stopForegroundCompat()
        stopSelf()
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
            .addAction(
                R.drawable.ic_stat_zerodpi,
                getString(R.string.zerodpi_notification_stop),
                PendingIntent.getService(
                    this,
                    0,
                    Intent(this, ZeroDpiService::class.java).setAction(ACTION_STOP),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                ),
            )
            .setOngoing(true)
            .build()

    inner class LocalBinder : Binder() {
        fun service(): ZeroDpiService = this@ZeroDpiService
    }

    private data class ActiveRunSpec(
        val profileId: String,
        val modeOverride: String?,
    )

    private enum class PickStage { StoppingForRescan, Scanning, Choosing }

    private data class PickSession(
        val profileId: String,
        val origin: PickOrigin,
        val resumeRunSpec: ActiveRunSpec?,
    )

    companion object {
        const val ACTION_STOP = "dev.zerodpi.android.action.STOP"
        private const val CHANNEL_ID = "zerodpi-runtime"
        private const val NOTIFICATION_ID = 1001
        private const val LOG_FLUSH_TIMEOUT_MS = 1_000L
        private const val MAX_RECENT_LOG_LINES = 12
        private const val MAX_SESSION_LOG_LINES = 500
        private val activeStatuses = setOf(
            RuntimeStatus.Starting,
            RuntimeStatus.Scanning,
            RuntimeStatus.Running,
            RuntimeStatus.Restarting,
            RuntimeStatus.Choosing,
            RuntimeStatus.Stopping,
        )
        // networkRestartableStatuses intentionally does NOT include Choosing:
        // a network change during a pick session must not race the session.
        private val networkRestartableStatuses = setOf(
            RuntimeStatus.Starting,
            RuntimeStatus.Scanning,
            RuntimeStatus.Running,
            RuntimeStatus.Restarting,
        )
    }
}
