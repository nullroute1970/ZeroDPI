package dev.zerodpi.android.runtime

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit

private const val MAX_DIAGNOSTIC_TEXT = 240

enum class RootAccessState {
    Granted,
    Denied,
    Unsupported,
}

data class RootAvailability(
    val available: Boolean,
    val message: String,
    val commandResult: RootCommandResult,
)

data class RootAccessResult(
    val state: RootAccessState,
    val message: String,
    val commandResult: RootCommandResult? = null,
)

data class RootCommandResult(
    val label: String,
    val command: List<String>,
    val exitCode: Int?,
    val stdout: String,
    val stderr: String,
    val timedOut: Boolean,
    val startFailure: String? = null,
) {
    val isSuccess: Boolean
        get() = startFailure == null && !timedOut && exitCode == 0

    fun diagnosticLine(): String {
        val status = when {
            startFailure != null -> "failed to start"
            timedOut -> "timed out"
            else -> "exit ${exitCode ?: "unknown"}"
        }
        val details = buildList {
            if (!startFailure.isNullOrBlank()) {
                add("error: ${startFailure.compactForDiagnostic()}")
            }
            if (stdout.isNotBlank()) {
                add("stdout: ${stdout.compactForDiagnostic()}")
            }
            if (stderr.isNotBlank()) {
                add("stderr: ${stderr.compactForDiagnostic()}")
            }
        }
        return if (details.isEmpty()) {
            "$label: $status"
        } else {
            "$label: $status; ${details.joinToString("; ")}"
        }
    }
}

sealed interface RootProcessLaunchResult {
    data class Started(
        val process: Process,
        val pid: Long?,
        val command: List<String>,
    ) : RootProcessLaunchResult

    data class Failed(
        val message: String,
        val startFailure: String,
    ) : RootProcessLaunchResult
}

data class RootHelperLaunchRequest(
    val executable: File,
    val socketPath: File,
    val sessionFile: File,
    val expectedAppUid: Int,
    val parentPid: Int,
    val workingDirectory: File,
)

data class RootDiagnosticReport(
    val rootAccess: RootAccessResult,
    val checks: List<RootCommandResult>,
    val skipped: List<String>,
)

interface RootManager {
    suspend fun isRootAvailable(): RootAvailability
    suspend fun requestRootFor(reason: String): RootAccessResult
    suspend fun launchRootHelper(request: RootHelperLaunchRequest): RootProcessLaunchResult
    suspend fun stopRootProcess(pid: Long): RootCommandResult
    suspend fun runDiagnostics(firewallBackend: String): RootDiagnosticReport
}

interface RootProcessExecutor {
    @Throws(IOException::class)
    fun start(
        command: List<String>,
        workingDirectory: File? = null,
        redirectErrorStream: Boolean = false,
    ): Process
}

class SuRootManager(
    private val executor: RootProcessExecutor = SystemRootProcessExecutor,
) : RootManager {
    private var grantedForSession: RootAccessResult? = null

    override suspend fun isRootAvailable(): RootAvailability {
        val result = runCommand(
            label = "su lookup",
            command = listOf("sh", "-c", "command -v su || which su"),
            timeoutSeconds = COMMAND_TIMEOUT_SECONDS,
        )
        return RootAvailability(
            available = result.isSuccess && result.stdout.isNotBlank(),
            message = if (result.isSuccess && result.stdout.isNotBlank()) {
                "su is available at ${result.stdout.lineSequence().first().trim()}."
            } else {
                "su was not found on this device."
            },
            commandResult = result,
        )
    }

    override suspend fun requestRootFor(reason: String): RootAccessResult =
        checkRootFor(reason = reason, allowCachedGrant = true)

    override suspend fun launchRootHelper(request: RootHelperLaunchRequest): RootProcessLaunchResult =
        withContext(Dispatchers.IO) {
            require(request.executable.name == ROOT_HELPER_EXECUTABLE_NAME) {
                "Refusing to launch an unexpected executable as the ZeroDPI root helper."
            }
            require(request.expectedAppUid > 0) { "Expected app UID must not be root." }
            require(request.socketPath.parentFile == request.sessionFile.parentFile) {
                "Helper socket and session proof must share one private directory."
            }
            val command = listOf(
                request.executable.absolutePath,
                "--socket",
                request.socketPath.absolutePath,
                "--expected-uid",
                request.expectedAppUid.toString(),
                "--session-file",
                request.sessionFile.absolutePath,
                "--parent-pid",
                request.parentPid.toString(),
            )
            val shell = buildString {
                append("cd ")
                append(shellArg(request.workingDirectory.absolutePath))
                append(" && ")
                append("exec ")
                append(shellCommand(command))
            }
            val suCommand = listOf("su", "-c", shell)
            val process = try {
                executor.start(
                    command = suCommand,
                    workingDirectory = null,
                    redirectErrorStream = true,
                )
            } catch (error: IOException) {
                return@withContext RootProcessLaunchResult.Failed(
                    message = "Failed to start root command through su.",
                    startFailure = error.message.orEmpty(),
                )
            }
            RootProcessLaunchResult.Started(
                process = process,
                pid = process.pidOrNull(),
                command = suCommand,
            )
        }

    override suspend fun stopRootProcess(pid: Long): RootCommandResult =
        runRootShellCommand(
            label = "kill -TERM $pid",
            shell = "kill -TERM $pid",
            timeoutSeconds = COMMAND_TIMEOUT_SECONDS,
        )

    override suspend fun runDiagnostics(firewallBackend: String): RootDiagnosticReport {
        val rootAccess = checkRootFor(reason = "root diagnostics", allowCachedGrant = false)
        if (rootAccess.state != RootAccessState.Granted) {
            return RootDiagnosticReport(
                rootAccess = rootAccess,
                checks = emptyList(),
                skipped = listOf("Firewall and NFQUEUE diagnostics skipped because root was not granted."),
            )
        }

        val checks = listOf(
            runRootShellCommand(
                label = "which iptables",
                shell = "which iptables",
                timeoutSeconds = COMMAND_TIMEOUT_SECONDS,
            ),
            runRootShellCommand(
                label = "which nft",
                shell = "which nft",
                timeoutSeconds = COMMAND_TIMEOUT_SECONDS,
            ),
            runRootShellCommand(
                label = "NFQUEUE kernel checks",
                shell = NFQUEUE_CHECK_SHELL,
                timeoutSeconds = COMMAND_TIMEOUT_SECONDS,
            ),
        )
        val selectedBackend = firewallCommandFor(firewallBackend)
        return RootDiagnosticReport(
            rootAccess = rootAccess,
            checks = checks,
            skipped = listOf(
                "ZeroDPI dry startup skipped; no Android validation command exists yet.",
                "Selected firewall backend command: $selectedBackend.",
            ),
        )
    }

    private suspend fun checkRootFor(
        reason: String,
        allowCachedGrant: Boolean,
    ): RootAccessResult {
        if (allowCachedGrant) {
            grantedForSession?.let { cached ->
                return cached.copy(message = "Root already granted for this app session; continuing $reason.")
            }
        }

        val uidResult = runRootShellCommand(
            label = "su -c id -u",
            shell = "id -u",
            timeoutSeconds = ROOT_TIMEOUT_SECONDS,
        )
        val result = rootAccessResultFor(reason, uidResult)
        if (result.state == RootAccessState.Granted) {
            grantedForSession = result
        }
        return result
    }

    private fun rootAccessResultFor(reason: String, uidResult: RootCommandResult): RootAccessResult {
        if (uidResult.startFailure != null) {
            return RootAccessResult(
                state = RootAccessState.Unsupported,
                message = "Root is unsupported for $reason: su is not available. ${uidResult.diagnosticLine()}",
                commandResult = uidResult,
            )
        }
        if (uidResult.timedOut) {
            return RootAccessResult(
                state = RootAccessState.Denied,
                message = "Root request for $reason timed out or was denied. ${uidResult.diagnosticLine()}",
                commandResult = uidResult,
            )
        }
        if (uidResult.exitCode != 0) {
            return RootAccessResult(
                state = RootAccessState.Denied,
                message = "Root request for $reason was denied by su. ${uidResult.diagnosticLine()}",
                commandResult = uidResult,
            )
        }

        val uid = uidResult.stdout.lineSequence().firstOrNull { it.isNotBlank() }?.trim()
        if (uid != "0") {
            return RootAccessResult(
                state = RootAccessState.Denied,
                message = "su did not grant UID 0 for $reason. ${uidResult.diagnosticLine()}",
                commandResult = uidResult,
            )
        }

        return RootAccessResult(
            state = RootAccessState.Granted,
            message = "Root granted for $reason; id -u returned 0.",
            commandResult = uidResult,
        )
    }

    private suspend fun runRootShellCommand(
        label: String,
        shell: String,
        timeoutSeconds: Long,
    ): RootCommandResult =
        runCommand(
            label = label,
            command = listOf("su", "-c", shell),
            timeoutSeconds = timeoutSeconds,
        )

    private suspend fun runCommand(
        label: String,
        command: List<String>,
        timeoutSeconds: Long,
        workingDirectory: File? = null,
    ): RootCommandResult =
        coroutineScope {
            val process = try {
                withContext(Dispatchers.IO) {
                    executor.start(
                        command = command,
                        workingDirectory = workingDirectory,
                        redirectErrorStream = false,
                    )
                }
            } catch (error: IOException) {
                return@coroutineScope RootCommandResult(
                    label = label,
                    command = command,
                    exitCode = null,
                    stdout = "",
                    stderr = "",
                    timedOut = false,
                    startFailure = error.message.orEmpty(),
                )
            }

            val stdout = async(Dispatchers.IO) {
                process.inputStream.bufferedReader().use { it.readText() }
            }
            val stderr = async(Dispatchers.IO) {
                process.errorStream.bufferedReader().use { it.readText() }
            }
            val finished = withContext(Dispatchers.IO) {
                process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            }
            if (!finished) {
                process.destroyForcibly()
                withContext(Dispatchers.IO) {
                    process.waitFor(1, TimeUnit.SECONDS)
                }
            }

            RootCommandResult(
                label = label,
                command = command,
                exitCode = if (finished) process.exitValue() else null,
                stdout = stdout.await(),
                stderr = stderr.await(),
                timedOut = !finished,
                startFailure = null,
            )
        }

    private fun firewallCommandFor(firewallBackend: String): String =
        when (firewallBackend.lowercase()) {
            "nft", "nftables" -> "nft"
            else -> "iptables"
        }

    private fun shellCommand(args: List<String>): String =
        args.joinToString(" ") { arg -> shellArg(arg) }

    private fun shellArg(arg: String): String =
        if (arg.matches(SAFE_SHELL_ARG)) {
            arg
        } else {
            "'${arg.replace("'", "'\"'\"'")}'"
        }

    private fun Process.pidOrNull(): Long? =
        runCatching {
            Process::class.java.getMethod("pid").invoke(this) as? Long
        }.getOrNull()

    private companion object {
        const val ROOT_HELPER_EXECUTABLE_NAME = "libzerodpi_root_helper_exec.so"
        const val ROOT_TIMEOUT_SECONDS = 15L
        const val COMMAND_TIMEOUT_SECONDS = 5L
        val SAFE_SHELL_ARG = Regex("""^[A-Za-z0-9_./:=+-]+$""")
        const val NFQUEUE_CHECK_SHELL =
            "if [ -r /proc/net/netfilter/nfnetlink_queue ]; then " +
                "echo /proc/net/netfilter/nfnetlink_queue readable; " +
                "else echo /proc/net/netfilter/nfnetlink_queue unavailable; fi; " +
                "if [ -d /sys/module/nfnetlink_queue ] || [ -d /sys/module/xt_NFQUEUE ]; then " +
                "echo NFQUEUE module path visible; " +
                "else echo NFQUEUE module path not visible; fi"
    }
}

private object SystemRootProcessExecutor : RootProcessExecutor {
    override fun start(
        command: List<String>,
        workingDirectory: File?,
        redirectErrorStream: Boolean,
    ): Process =
        ProcessBuilder(command)
            .apply {
                workingDirectory?.let { directory(it) }
                redirectErrorStream(redirectErrorStream)
            }
            .start()
}

private fun String.compactForDiagnostic(): String {
    val compact = lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .joinToString(" | ")
    return if (compact.length <= MAX_DIAGNOSTIC_TEXT) {
        compact
    } else {
        compact.take(MAX_DIAGNOSTIC_TEXT) + "..."
    }
}
