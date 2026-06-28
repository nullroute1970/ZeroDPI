package dev.zerodpi.android.runtime

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.TimeUnit

class ProcessZeroDpiRunner(
    context: Context,
    private val scope: CoroutineScope,
) : ZeroDpiRunner {
    private val appContext = context.applicationContext
    private val events = MutableSharedFlow<ZeroDpiRunnerEvent>(extraBufferCapacity = 128)
    private var process: Process? = null
    private var outputJob: Job? = null
    private var waitJob: Job? = null
    private val exitEmitted = AtomicBoolean(false)

    override fun events(): Flow<ZeroDpiRunnerEvent> = events.asSharedFlow()

    override suspend fun start(request: ZeroDpiRunRequest) {
        if (process?.isAlive == true) {
            events.emit(ZeroDpiRunnerEvent.Log("ZeroDPI process is already active."))
            return
        }

        val executable = File(appContext.applicationInfo.nativeLibraryDir, "libzerodpi_exec.so")
        if (!executable.isFile) {
            events.emit(ZeroDpiRunnerEvent.Failed("Missing native runtime artifact: ${executable.absolutePath}"))
            return
        }

        events.emit(ZeroDpiRunnerEvent.Starting)
        exitEmitted.set(false)
        val command = mutableListOf(
            executable.absolutePath,
            "--config",
            request.configPath,
            "--no-tui",
            "--auto-select",
            "--json-events",
        )

        val builder = if (request.useRoot) {
            ProcessBuilder("su", "-c", shellCommand(command))
        } else {
            ProcessBuilder(command)
        }
            .directory(File(request.workingDirectory))
            .redirectErrorStream(true)

        process = runCatching {
            withContext(Dispatchers.IO) {
                builder.start()
            }
        }.getOrElse { error ->
            events.emit(ZeroDpiRunnerEvent.Failed(error.message ?: "Failed to start ZeroDPI."))
            return
        }

        outputJob = scope.launch(Dispatchers.IO) {
            process?.inputStream?.bufferedReader()?.useLines { lines ->
                lines.forEach { line ->
                    events.emit(RuntimeEventLineParser.parse(line) ?: ZeroDpiRunnerEvent.Log(line))
                }
            }
        }

        waitJob = scope.launch(Dispatchers.IO) {
            val exitCode = process?.waitFor() ?: -1
            emitExited(exitCode)
            process = null
        }
    }

    override suspend fun stop() {
        val current = process ?: run {
            events.emit(ZeroDpiRunnerEvent.Exited(0))
            return
        }

        current.destroy()
        val stopped = withContext(Dispatchers.IO) {
            current.waitFor(5, TimeUnit.SECONDS)
        }
        if (!stopped) {
            events.emit(ZeroDpiRunnerEvent.StopTimedOut)
            return
        }
        cleanupProcess()
        emitExited(0)
    }

    override suspend fun forceStop() {
        val current = process ?: run {
            emitExited(0)
            return
        }

        current.destroyForcibly()
        withContext(Dispatchers.IO) {
            current.waitFor(2, TimeUnit.SECONDS)
        }
        cleanupProcess()
        emitExited(-1)
    }

    private fun cleanupProcess() {
        outputJob?.cancel()
        waitJob?.cancel()
        outputJob = null
        waitJob = null
        process = null
    }

    private suspend fun emitExited(exitCode: Int) {
        if (exitEmitted.compareAndSet(false, true)) {
            events.emit(ZeroDpiRunnerEvent.Exited(exitCode))
        }
    }

    private fun shellCommand(args: List<String>): String =
        args.joinToString(" ") { arg ->
            if (arg.matches(SAFE_SHELL_ARG)) {
                arg
            } else {
                "'${arg.replace("'", "'\"'\"'")}'"
            }
        }

    private companion object {
        val SAFE_SHELL_ARG = Regex("""^[A-Za-z0-9_./:=+-]+$""")
    }
}
