package dev.zerodpi.android.storage

object SupportBundleSanitizer {
    private val assignmentPattern = Regex("""^(\s*)([A-Z0-9_]+)(\s*=\s*)(.*)$""")
    private val redactedConfigFields = setOf(
        "SELECTED_SNI",
        "SELECTED_IP",
        "SNI_LIST",
        "IP_LIST",
        "SCAN_OUTPUT",
        "SCAN_UPLOAD_PATH",
        "IP_SCAN_SNI",
        "PROXY_TEST_SOCKS5_HOST",
        "PROXY_TEST_SOCKS5_PORT",
        "PROXY_TEST_URL",
    )

    fun sanitizedConfig(configText: String): String =
        configText.lineSequence()
            .joinToString("\n") { line ->
                val match = assignmentPattern.find(line) ?: return@joinToString line
                val key = match.groupValues[2]
                if (key !in redactedConfigFields) {
                    line
                } else {
                    "${match.groupValues[1]}$key${match.groupValues[3]}\"<redacted>\""
                }
            }

    fun noticeText(includePrivateLists: Boolean): String =
        buildString {
            appendLine("ZeroDPI Android support bundle")
            appendLine()
            appendLine("config.redacted.toml redacts selected endpoints, list paths, scan paths, and proxy-test targets.")
            if (includePrivateLists) {
                appendLine("Private SNI/IP lists were explicitly included by the user.")
            } else {
                appendLine("Private SNI/IP lists were omitted. Re-export with list inclusion enabled only if you intend to share them.")
            }
            appendLine("Logs and diagnostics are included to help debug failed starts and runtime issues.")
        }
}
