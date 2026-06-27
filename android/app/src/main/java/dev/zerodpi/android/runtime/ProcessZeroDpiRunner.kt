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
        val command = mutableListOf(
            executable.absolutePath,
            "--config",
            request.configPath,
            "--no-tui",
            "--auto-select",
            "--json-events",
        )

        val builder = if (request.useRoot) {
            ProcessBuilder("su", "-c", command.joinToString(" "))
        } else {
            ProcessBuilder(command)
        }
            .directory(File(request.workingDirectory))
            .redirectErrorStream(true)

        process = withContext(Dispatchers.IO) {
            builder.start()
        }
        events.emit(ZeroDpiRunnerEvent.Running)

        outputJob = scope.launch(Dispatchers.IO) {
            process?.inputStream?.bufferedReader()?.useLines { lines ->
                lines.forEach { line ->
                    events.emit(ZeroDpiRunnerEvent.Log(line))
                }
            }
        }

        waitJob = scope.launch(Dispatchers.IO) {
            val exitCode = process?.waitFor() ?: -1
            events.emit(ZeroDpiRunnerEvent.Exited(exitCode))
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
            current.destroyForcibly()
        }
        outputJob?.cancel()
        waitJob?.cancel()
        process = null
        events.emit(ZeroDpiRunnerEvent.Exited(if (stopped) 0 else -1))
    }
}
