package dev.zerodpi.android.diagnostics

data class DeviceDiagnostics(
    val appVersion: String,
    val zeroDpiVersion: String,
    val abi: String,
    val androidVersion: String,
    val rootStatus: String,
    val firewallBackendAvailability: String,
    val configValidationResult: String,
    val lastExitCode: String,
    val runtimeStatus: String,
    val mode: String,
    val bypassMethod: String,
    val listener: String,
) {
    fun asText(): String =
        buildString {
            appendLine("App version: $appVersion")
            appendLine("ZeroDPI version: $zeroDpiVersion")
            appendLine("ABI: $abi")
            appendLine("Android version: $androidVersion")
            appendLine("Root status: $rootStatus")
            appendLine("Firewall backend availability: $firewallBackendAvailability")
            appendLine("Config validation result: $configValidationResult")
            appendLine("Last exit code: $lastExitCode")
            appendLine("Runtime status: $runtimeStatus")
            appendLine("Mode: $mode")
            appendLine("Bypass method: $bypassMethod")
            appendLine("Listener: $listener")
        }

    companion object {
        val Empty = DeviceDiagnostics(
            appVersion = "Unknown",
            zeroDpiVersion = "Unknown",
            abi = "Unknown",
            androidVersion = "Unknown",
            rootStatus = "Unknown",
            firewallBackendAvailability = "Unknown",
            configValidationResult = "Unknown",
            lastExitCode = "None",
            runtimeStatus = "Unknown",
            mode = "Unknown",
            bypassMethod = "Unknown",
            listener = "Unknown",
        )
    }
}
