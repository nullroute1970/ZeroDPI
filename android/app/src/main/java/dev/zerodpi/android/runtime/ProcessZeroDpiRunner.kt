package dev.zerodpi.android.runtime

import android.content.Context
import android.os.Process as AndroidProcess
import android.system.Os
import android.system.OsConstants
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.BufferedReader
import java.io.File
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

private const val ZERO_DPI_EXECUTABLE_NAME = "libzerodpi_exec.so"
private const val ROOT_HELPER_EXECUTABLE_NAME = "libzerodpi_root_helper_exec.so"
private const val SESSION_PROOF_BYTES = 32
private const val HELPER_READY_TIMEOUT_MS = 10_000L
private const val HELPER_EXIT_STATUS_WAIT_MS = 250L
private const val MAX_HELPER_STARTUP_LINES = 8
private const val MAX_HELPER_STARTUP_LINE_LENGTH = 240

internal interface ZeroDpiProcessLauncher {
    suspend fun start(command: List<String>, workingDirectory: File): Process
}

class ProcessZeroDpiRunner internal constructor(
    private val scope: CoroutineScope,
    private val rootManager: RootManager,
    private val executableProvider: () -> File,
    private val processLauncher: ZeroDpiProcessLauncher,
    private val helperExecutableProvider: () -> File = {
        File(executableProvider().parentFile, ROOT_HELPER_EXECUTABLE_NAME)
    },
    private val appUidProvider: () -> Int = { AndroidProcess.myUid() },
    private val appPidProvider: () -> Int = { AndroidProcess.myPid() },
    private val sessionProofProvider: () -> ByteArray = {
        ByteArray(SESSION_PROOF_BYTES).also(SecureRandom()::nextBytes)
    },
    private val fileModeSetter: (File, Int) -> Unit = { file, mode ->
        Os.chmod(file.absolutePath, mode)
    },
    private val helperBootstrapParentProvider: (File) -> File = { workingDirectory ->
        workingDirectory
    },
) : ZeroDpiRunner {
    constructor(
        context: Context,
        scope: CoroutineScope,
        rootManager: RootManager,
    ) : this(
        scope = scope,
        rootManager = rootManager,
        executableProvider = {
            File(context.applicationContext.applicationInfo.nativeLibraryDir, ZERO_DPI_EXECUTABLE_NAME)
        },
        processLauncher = SystemZeroDpiProcessLauncher,
        helperExecutableProvider = {
            File(context.applicationContext.applicationInfo.nativeLibraryDir, ROOT_HELPER_EXECUTABLE_NAME)
        },
        helperBootstrapParentProvider = {
            context.applicationContext.filesDir
        },
    )

    private val events = MutableSharedFlow<ZeroDpiRunnerEvent>(extraBufferCapacity = 128)
    private var dataPlaneProcess: Process? = null
    private var helperProcess: Process? = null
    private var helperProcessPid: Long? = null
    @Volatile
    private var nativeProcessPid: Long? = null
    private var outputJob: Job? = null
    private var waitJob: Job? = null
    private var helperOutputJob: Job? = null
    private var helperWaitJob: Job? = null
    private var sessionDirectory: File? = null
    private val exitEmitted = AtomicBoolean(false)
    private val stopRequested = AtomicBoolean(false)

    override fun events(): Flow<ZeroDpiRunnerEvent> = events.asSharedFlow()

    override suspend fun start(request: ZeroDpiRunRequest) {
        if (dataPlaneProcess?.isAliveCompat() == true || helperProcess?.isAliveCompat() == true) {
            events.emit(ZeroDpiRunnerEvent.Log("ZeroDPI process is already active."))
            return
        }

        val executable = executableProvider()
        if (!executable.isFile) {
            events.emit(ZeroDpiRunnerEvent.Failed("Missing native runtime artifact: ${executable.absolutePath}"))
            return
        }

        events.emit(ZeroDpiRunnerEvent.Starting)
        exitEmitted.set(false)
        stopRequested.set(false)
        nativeProcessPid = null
        val workingDirectory = File(request.workingDirectory)
        val command = mutableListOf(
            executable.absolutePath,
            "--config",
            request.configPath,
            "--no-tui",
            "--auto-select",
            "--json-events",
        )

        if (request.useRoot) {
            val helperExecutable = helperExecutableProvider()
            if (!helperExecutable.isFile) {
                events.emit(ZeroDpiRunnerEvent.Failed("Missing native root-helper artifact: ${helperExecutable.absolutePath}"))
                return
            }
            val bootstrap = runCatching {
                createBootstrap(helperBootstrapParentProvider(workingDirectory))
            }.getOrElse { error ->
                events.emit(ZeroDpiRunnerEvent.Failed(error.message ?: "Failed to create root-helper bootstrap state."))
                return
            }
            sessionDirectory = bootstrap.directory
            events.emit(ZeroDpiRunnerEvent.RootHelperStarting)
            val launchRequest = RootHelperLaunchRequest(
                executable = helperExecutable,
                socketPath = bootstrap.socket,
                sessionFile = bootstrap.proof,
                expectedAppUid = appUidProvider(),
                parentPid = appPidProvider(),
                workingDirectory = workingDirectory,
            )
            when (val launch = rootManager.launchRootHelper(launchRequest)) {
                is RootProcessLaunchResult.Started -> {
                    helperProcess = launch.process
                    helperProcessPid = launch.pid
                }
                is RootProcessLaunchResult.Failed -> {
                    cleanupBootstrap()
                    events.emit(ZeroDpiRunnerEvent.Failed("${launch.message} ${launch.startFailure}".trim()))
                    return
                }
            }

            val helper = helperProcess ?: run {
                cleanupBootstrap()
                events.emit(ZeroDpiRunnerEvent.Failed("Failed to retain root-helper process handle."))
                return
            }
            val ready = runCatching { awaitHelperReady(helper) }.getOrElse { error ->
                stopHelperProcess()
                cleanupBootstrap()
                events.emit(ZeroDpiRunnerEvent.Failed(error.message ?: "Root helper did not become ready."))
                return
            }
            if (ready.uid != 0L) {
                stopHelperProcess()
                cleanupBootstrap()
                events.emit(ZeroDpiRunnerEvent.Failed("Root helper readiness identity was not UID 0."))
                return
            }
            helperProcessPid = ready.pid
            events.emit(ZeroDpiRunnerEvent.Log("Root helper listener ready with pid ${ready.pid} and uid ${ready.uid}."))
            helperOutputJob = scope.launch(Dispatchers.IO) {
                ready.reader.useLines { lines ->
                    lines.forEach { line -> events.emit(ZeroDpiRunnerEvent.Log(line)) }
                }
            }
            command += listOf(
                "--root-helper-socket",
                bootstrap.socket.absolutePath,
                "--root-helper-session-file",
                bootstrap.proof.absolutePath,
                "--expected-data-plane-uid",
                appUidProvider().toString(),
            )
        }

        val launchedProcess = runCatching {
            processLauncher.start(command, workingDirectory)
        }.getOrElse { error ->
            stopHelperProcess()
            cleanupBootstrap()
            events.emit(ZeroDpiRunnerEvent.Failed(error.message ?: "Failed to start ZeroDPI data plane."))
            return
        }
        dataPlaneProcess = launchedProcess

        outputJob = scope.launch(Dispatchers.IO) {
            launchedProcess.inputStream.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    RuntimeEventLineParser.startupIdentity(line)?.let { identity ->
                        nativeProcessPid = identity.pid
                        if (request.useRoot && identity.uid != appUidProvider().toLong()) {
                            events.emit(
                                ZeroDpiRunnerEvent.Failed(
                                    "Data-plane UID verification failed: expected ${appUidProvider()}, got ${identity.uid}.",
                                ),
                            )
                            stopRequested.set(true)
                            launchedProcess.destroyForciblyCompat()
                            stopHelperProcess()
                        } else {
                            events.emit(ZeroDpiRunnerEvent.DataPlaneStarted(identity.pid, identity.uid))
                        }
                    }
                    events.emit(RuntimeEventLineParser.parse(line) ?: ZeroDpiRunnerEvent.Log(line))
                }
            }
        }

        waitJob = scope.launch(Dispatchers.IO) {
            val exitCode = launchedProcess.waitFor()
            stopRequested.set(true)
            dataPlaneProcess = null
            nativeProcessPid = null
            if (helperProcess?.isAliveCompat() == true) {
                val cleanupConfirmed = stopHelperProcess()
                events.emit(ZeroDpiRunnerEvent.FirewallCleanup(cleanupConfirmed))
            }
            cleanupBootstrap()
            emitExited(exitCode)
        }

        helperProcess?.let { helper ->
            helperWaitJob = scope.launch(Dispatchers.IO) {
                val exitCode = helper.waitFor()
                helperProcess = null
                helperProcessPid = null
                if (exitCode != 0 && !stopRequested.get() && dataPlaneProcess?.isAliveCompat() == true) {
                    events.emit(ZeroDpiRunnerEvent.Failed("Root helper exited unexpectedly with code $exitCode."))
                    events.emit(ZeroDpiRunnerEvent.FirewallCleanup(completed = false))
                    dataPlaneProcess?.destroyForciblyCompat()
                }
            }
        }
    }

    override suspend fun stop() {
        stopRequested.set(true)
        val current = dataPlaneProcess
        if (current != null) {
            if (!sendSigterm(current)) {
                current.destroy()
            }
            val stopped = withContext(Dispatchers.IO) { current.waitForCompat(5, TimeUnit.SECONDS) }
            if (!stopped) {
                events.emit(ZeroDpiRunnerEvent.StopTimedOut)
                return
            }
        }
        val cleanupConfirmed = stopHelperProcess()
        cleanupProcesses()
        cleanupBootstrap()
        events.emit(ZeroDpiRunnerEvent.FirewallCleanup(completed = cleanupConfirmed))
        emitExited(0)
    }

    override suspend fun forceStop() {
        stopRequested.set(true)
        dataPlaneProcess?.destroyForciblyCompat()
        withContext(Dispatchers.IO) {
            dataPlaneProcess?.waitForCompat(2, TimeUnit.SECONDS)
        }
        val cleanupConfirmed = stopHelperProcess()
        cleanupProcesses()
        cleanupBootstrap()
        events.emit(ZeroDpiRunnerEvent.FirewallCleanup(completed = cleanupConfirmed))
        emitExited(-1)
    }

    private suspend fun stopHelperProcess(): Boolean {
        val helper = helperProcess ?: return true
        if (!helper.isAliveCompat()) {
            helperProcess = null
            helperProcessPid = null
            return true
        }
        val pid = helperProcessPid ?: helper.pidOrNull()
        var termRequested = false
        if (pid != null) {
            val result = rootManager.stopRootProcess(pid)
            termRequested = result.isSuccess
            if (!result.isSuccess) {
                events.emit(ZeroDpiRunnerEvent.Log(result.diagnosticLine()))
            }
        }
        val exitedAfterTerm = if (termRequested) {
            withContext(Dispatchers.IO) { helper.waitForCompat(2, TimeUnit.SECONDS) }
        } else {
            false
        }
        if (helper.isAliveCompat()) {
            helper.destroy()
            withContext(Dispatchers.IO) { helper.waitForCompat(2, TimeUnit.SECONDS) }
        }
        if (helper.isAliveCompat()) {
            helper.destroyForciblyCompat()
        }
        helperProcess = null
        helperProcessPid = null
        return exitedAfterTerm
    }

    private fun cleanupProcesses() {
        outputJob?.cancel()
        waitJob?.cancel()
        helperOutputJob?.cancel()
        helperWaitJob?.cancel()
        outputJob = null
        waitJob = null
        helperOutputJob = null
        helperWaitJob = null
        dataPlaneProcess = null
        helperProcess = null
        helperProcessPid = null
        nativeProcessPid = null
    }

    private fun createBootstrap(workingDirectory: File): HelperBootstrap {
        val directory = File(workingDirectory, ".zerodpi-helper-${UUID.randomUUID().toString().take(12)}")
        check(directory.mkdir()) { "Failed to create private root-helper runtime directory." }
        fileModeSetter(directory, 0b111000000)
        val proof = File(directory, "session.proof")
        proof.writeBytes(sessionProofProvider().also {
            require(it.size == SESSION_PROOF_BYTES) { "Session proof must contain $SESSION_PROOF_BYTES bytes." }
        })
        fileModeSetter(proof, 0b110000000)
        return HelperBootstrap(directory, File(directory, "control.sock"), proof)
    }

    private fun cleanupBootstrap() {
        val directory = sessionDirectory ?: return
        File(directory, "control.sock").delete()
        File(directory, "session.proof").delete()
        directory.delete()
        sessionDirectory = null
    }

    private suspend fun awaitHelperReady(process: Process): HelperReady =
        withTimeout(HELPER_READY_TIMEOUT_MS) {
            withContext(Dispatchers.IO) {
                val reader = process.inputStream.bufferedReader()
                val startupOutput = ArrayDeque<String>()
                while (true) {
                    val line = reader.readLine() ?: error(helperExitDiagnostic(process, startupOutput))
                    HELPER_READY.matchEntire(line)?.let { match ->
                        return@withContext HelperReady(
                            pid = match.groupValues[1].toLong(),
                            uid = match.groupValues[2].toLong(),
                            reader = reader,
                        )
                    }
                    startupOutput.addLast(line.compactHelperOutput())
                    if (startupOutput.size > MAX_HELPER_STARTUP_LINES) {
                        startupOutput.removeFirst()
                    }
                    events.emit(ZeroDpiRunnerEvent.Log(line))
                }
                error("unreachable")
            }
        }

    private fun helperExitDiagnostic(process: Process, startupOutput: Collection<String>): String {
        val exitCode = runCatching {
            if (process.waitForCompat(HELPER_EXIT_STATUS_WAIT_MS, TimeUnit.MILLISECONDS)) {
                process.exitValue()
            } else {
                null
            }
        }.getOrNull()
        return buildString {
            append("Root helper exited before listener readiness")
            if (exitCode != null) {
                append(" with code ")
                append(exitCode)
            }
            append('.')
            if (startupOutput.isNotEmpty()) {
                append(" Last output: ")
                append(startupOutput.joinToString(" | "))
            }
        }
    }

    private suspend fun emitExited(exitCode: Int) {
        if (exitEmitted.compareAndSet(false, true)) {
            events.emit(ZeroDpiRunnerEvent.Exited(exitCode))
        }
    }

    private fun sendSigterm(process: Process): Boolean {
        val pid = nativeProcessPid ?: process.pidOrNull() ?: return false
        if (pid < Int.MIN_VALUE.toLong() || pid > Int.MAX_VALUE.toLong()) {
            return false
        }
        return runCatching {
            AndroidProcess.sendSignal(pid.toInt(), OsConstants.SIGTERM)
            true
        }.getOrDefault(false)
    }

    private fun Process.pidOrNull(): Long? =
        runCatching { Process::class.java.getMethod("pid").invoke(this) as? Long }.getOrNull()

    private data class HelperBootstrap(val directory: File, val socket: File, val proof: File)
    private data class HelperReady(val pid: Long, val uid: Long, val reader: BufferedReader)

    private companion object {
        val HELPER_READY = Regex("ZERODPI_HELPER_READY pid=(\\d+) uid=(\\d+)")
    }
}

private fun String.compactHelperOutput(): String {
    val compact = trim().replace(Regex("\\s+"), " ")
    return if (compact.length <= MAX_HELPER_STARTUP_LINE_LENGTH) {
        compact
    } else {
        compact.take(MAX_HELPER_STARTUP_LINE_LENGTH) + "..."
    }
}

private object SystemZeroDpiProcessLauncher : ZeroDpiProcessLauncher {
    override suspend fun start(command: List<String>, workingDirectory: File): Process =
        withContext(Dispatchers.IO) {
            ProcessBuilder(command)
                .directory(workingDirectory)
                .redirectErrorStream(true)
                .start()
        }
}
