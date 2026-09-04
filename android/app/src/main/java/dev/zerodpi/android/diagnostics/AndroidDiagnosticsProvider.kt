package dev.zerodpi.android.diagnostics

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import dev.zerodpi.android.BuildConfig
import dev.zerodpi.android.config.ZeroDpiConfigToml
import dev.zerodpi.android.runtime.destroyForciblyCompat
import dev.zerodpi.android.runtime.waitForCompat
import dev.zerodpi.android.service.ZeroDpiServiceState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.TimeUnit

class AndroidDiagnosticsProvider(context: Context) {
    private val appContext = context.applicationContext

    suspend fun collect(
        serviceState: ZeroDpiServiceState,
        configText: String,
    ): DeviceDiagnostics {
        val config = ZeroDpiConfigToml.analyze(configText)
        val firewallBackend = config.valueFor("LINUX_FIREWALL_BACKEND").ifBlank { "iptables" }
        val firewallCommand = firewallCommandFor(firewallBackend)
        val configValidation = if (config.canStart) {
            "Valid"
        } else {
            "${config.issues.size} error(s): ${config.issues.firstOrNull()?.message.orEmpty()}"
        }

        return DeviceDiagnostics(
            appVersion = appVersion(),
            zeroDpiVersion = zeroDpiVersion(),
            abi = Build.SUPPORTED_ABIS.joinToString().ifBlank { "Unknown" },
            androidVersion = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
            rootStatus = serviceState.rootStatus.label,
            firewallBackendAvailability = commandAvailability(firewallCommand),
            configValidationResult = configValidation,
            lastExitCode = serviceState.lastExitCode?.toString() ?: "None",
            runtimeStatus = serviceState.status.name,
            mode = serviceState.mode,
            bypassMethod = serviceState.bypassMethod,
            listener = serviceState.listener,
        )
    }

    private fun appVersion(): String {
        val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            appContext.packageManager.getPackageInfo(
                appContext.packageName,
                PackageManager.PackageInfoFlags.of(0),
            )
        } else {
            @Suppress("DEPRECATION")
            appContext.packageManager.getPackageInfo(appContext.packageName, 0)
        }
        val versionName = packageInfo.versionName ?: BuildConfig.VERSION_NAME
        val versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            packageInfo.versionCode.toLong()
        }
        return "$versionName ($versionCode)"
    }

    private suspend fun zeroDpiVersion(): String =
        withContext(Dispatchers.IO) {
            val executable = File(appContext.applicationInfo.nativeLibraryDir, "libzerodpi_exec.so")
            if (!executable.isFile) {
                return@withContext "Not packaged; fake runner will be used"
            }
            runShortCommand(listOf(executable.absolutePath, "--version")).toDisplayString("ZeroDPI")
        }

    private suspend fun commandAvailability(command: String): String =
        withContext(Dispatchers.IO) {
            runShortCommand(listOf("sh", "-c", "command -v $command || which $command"))
                .toAvailabilityString(command)
        }

    private fun firewallCommandFor(firewallBackend: String): String =
        when (firewallBackend.lowercase()) {
            "nft", "nftables" -> "nft"
            else -> "iptables"
        }

    private fun runShortCommand(command: List<String>): DiagnosticCommandResult {
        val process = try {
            ProcessBuilder(command)
                .redirectErrorStream(true)
                .start()
        } catch (error: Exception) {
            return DiagnosticCommandResult(
                exitCode = null,
                output = "",
                timedOut = false,
                startFailure = error.message.orEmpty(),
            )
        }

        val finished = process.waitForCompat(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForciblyCompat()
            process.waitForCompat(1, TimeUnit.SECONDS)
        }
        val output = process.inputStream.bufferedReader().use { it.readText() }
        return DiagnosticCommandResult(
            exitCode = if (finished) process.exitValue() else null,
            output = output.trim(),
            timedOut = !finished,
            startFailure = null,
        )
    }

    private data class DiagnosticCommandResult(
        val exitCode: Int?,
        val output: String,
        val timedOut: Boolean,
        val startFailure: String?,
    ) {
        fun toDisplayString(label: String): String =
            when {
                startFailure != null -> "Unavailable: $startFailure"
                timedOut -> "Unavailable: $label command timed out"
                exitCode == 0 && output.isNotBlank() -> output.lineSequence().first().trim()
                exitCode == 0 -> "Available"
                output.isNotBlank() -> "Unavailable (exit $exitCode): ${compactOutput(output)}"
                else -> "Unavailable (exit $exitCode)"
            }

        fun toAvailabilityString(command: String): String =
            when {
                startFailure != null -> "$command lookup failed: $startFailure"
                timedOut -> "$command lookup timed out"
                exitCode == 0 && output.isNotBlank() -> "$command found at ${output.lineSequence().first().trim()}"
                exitCode == 0 -> "$command appears available"
                output.isNotBlank() -> "$command not found (exit $exitCode): ${compactOutput(output)}"
                else -> "$command not found (exit $exitCode)"
            }
    }

    private companion object {
        const val COMMAND_TIMEOUT_SECONDS = 2L
        const val MAX_COMMAND_OUTPUT = 160

        fun compactOutput(value: String): String {
            val compact = value.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .joinToString(" | ")
            return if (compact.length <= MAX_COMMAND_OUTPUT) {
                compact
            } else {
                compact.take(MAX_COMMAND_OUTPUT) + "..."
            }
        }
    }
}
