package dev.zerodpi.android.runtime

internal object RuntimeEventLineParser {
    data class StartupIdentity(val pid: Long, val uid: Long)

    fun startupIdentity(line: String): StartupIdentity? {
        val json = line.trim()
        if (!json.startsWith("{") || !json.endsWith("}") || stringValue(json, "event") != "startup") {
            return null
        }
        return StartupIdentity(
            pid = longValue(json, "pid") ?: return null,
            uid = longValue(json, "uid") ?: return null,
        )
    }

    fun startupPid(line: String): Long? {
        val json = line.trim()
        if (!json.startsWith("{") || !json.endsWith("}")) {
            return null
        }
        return if (stringValue(json, "event") == "startup") {
            longValue(json, "pid")
        } else {
            null
        }
    }

    fun parse(line: String): ZeroDpiRunnerEvent? {
        val json = line.trim()
        if (!json.startsWith("{") || !json.endsWith("}")) {
            return null
        }

        return when (stringValue(json, "event")) {
            "startup" -> ZeroDpiRunnerEvent.Log(
                "ZeroDPI ${stringValue(json, "version").orEmpty()} started with pid ${longValue(json, "pid") ?: "unknown"} and uid ${longValue(json, "uid") ?: "unknown"}.",
            )
            "helper_authenticated" -> ZeroDpiRunnerEvent.RootHelperAuthenticated(
                pid = longValue(json, "pid") ?: 0,
                uid = longValue(json, "uid") ?: 0,
            )
            "config_loaded" -> ZeroDpiRunnerEvent.ConfigLoaded(
                mode = stringValue(json, "mode").orEmpty(),
                bypassMethod = stringValue(json, "bypass_method").orEmpty(),
                listenHost = stringValue(json, "listen_host").orEmpty(),
                listenPort = longValue(json, "listen_port")?.toInt() ?: 0,
                rootRequired = boolValue(json, "root_required") ?: false,
            )
            "scan_started" -> ZeroDpiRunnerEvent.ScanStarted(
                scan = stringValue(json, "scan").orEmpty(),
                total = longValue(json, "total")?.toInt(),
            )
            "scan_progress" -> ZeroDpiRunnerEvent.ScanProgress(
                scan = stringValue(json, "scan").orEmpty(),
                phase = stringValue(json, "phase"),
                completed = longValue(json, "completed")?.toInt() ?: 0,
                total = longValue(json, "total")?.toInt(),
                sni = stringValue(json, "sni"),
                ip = stringValue(json, "ip"),
                score = longValue(json, "score")?.toInt(),
            )
            "scan_completed" -> ZeroDpiRunnerEvent.ScanCompleted(
                scan = stringValue(json, "scan").orEmpty(),
                results = longValue(json, "results")?.toInt() ?: 0,
            )
            "next_scan_scheduled" -> ZeroDpiRunnerEvent.NextScanScheduled(
                scan = stringValue(json, "scan").orEmpty(),
                intervalSeconds = longValue(json, "interval_secs") ?: 0L,
            )
            "selected_target" -> ZeroDpiRunnerEvent.SelectedTarget(
                target = stringValue(json, "target").orEmpty(),
                sni = stringValue(json, "sni"),
                ip = stringValue(json, "ip").orEmpty(),
                score = longValue(json, "score")?.toInt(),
            )
            "listener_started" -> ZeroDpiRunnerEvent.ListenerStarted(
                mode = stringValue(json, "mode").orEmpty(),
                listenAddress = stringValue(json, "listen_addr").orEmpty(),
            )
            "connection_accepted" -> ZeroDpiRunnerEvent.ConnectionAccepted(
                peer = stringValue(json, "peer").orEmpty(),
                sourcePort = longValue(json, "src_port")?.toInt() ?: 0,
            )
            "bypass_finished" -> ZeroDpiRunnerEvent.BypassFinished(
                sourcePort = longValue(json, "src_port")?.toInt() ?: 0,
                status = stringValue(json, "status").orEmpty(),
            )
            "relay_bytes" -> ZeroDpiRunnerEvent.RelayBytes(
                sourcePort = longValue(json, "src_port")?.toInt() ?: 0,
                clientToServerBytes = longValue(json, "c2s_bytes") ?: 0L,
                serverToClientBytes = longValue(json, "s2c_bytes") ?: 0L,
                isFinal = boolValue(json, "final") ?: false,
            )
            "active_target_changed" -> ZeroDpiRunnerEvent.ActiveTargetChanged(
                target = stringValue(json, "target").orEmpty(),
                sni = stringValue(json, "sni"),
                ip = stringValue(json, "ip").orEmpty(),
                score = longValue(json, "score")?.toInt(),
            )
            "root_required" -> ZeroDpiRunnerEvent.RootRequired(
                message = stringValue(json, "message").orEmpty(),
                alternatives = stringArrayValue(json, "rootless_alternatives"),
            )
            "fatal_error" -> ZeroDpiRunnerEvent.FatalError(
                message = stringValue(json, "message").orEmpty(),
            )
            "graceful_shutdown" -> ZeroDpiRunnerEvent.GracefulShutdown(
                reason = stringValue(json, "reason").orEmpty(),
            )
            null -> null
            else -> ZeroDpiRunnerEvent.Log(json)
        }
    }

    private fun stringValue(json: String, key: String): String? {
        val start = valueStart(json, key) ?: return null
        if (json.startsWith("null", start)) {
            return null
        }
        if (json.getOrNull(start) != '"') {
            return null
        }
        return parseString(json, start)?.value
    }

    private fun stringArrayValue(json: String, key: String): List<String> {
        var index = valueStart(json, key) ?: return emptyList()
        if (json.getOrNull(index) != '[') {
            return emptyList()
        }
        index++

        val values = mutableListOf<String>()
        while (index < json.length) {
            index = skipWhitespace(json, index)
            when (json.getOrNull(index)) {
                ']' -> return values
                ',' -> index++
                '"' -> {
                    val parsed = parseString(json, index) ?: return values
                    values += parsed.value
                    index = parsed.nextIndex
                }
                else -> return values
            }
        }
        return values
    }

    private fun longValue(json: String, key: String): Long? {
        val start = valueStart(json, key) ?: return null
        if (json.startsWith("null", start)) {
            return null
        }
        var end = start
        if (json.getOrNull(end) == '-') {
            end++
        }
        while (end < json.length && json[end].isDigit()) {
            end++
        }
        if (end == start || (end == start + 1 && json[start] == '-')) {
            return null
        }
        return json.substring(start, end).toLongOrNull()
    }

    private fun boolValue(json: String, key: String): Boolean? {
        val start = valueStart(json, key) ?: return null
        return when {
            json.startsWith("true", start) -> true
            json.startsWith("false", start) -> false
            else -> null
        }
    }

    private fun valueStart(json: String, key: String): Int? {
        val keyPattern = Regex(""""${Regex.escape(key)}"\s*:""")
        val match = keyPattern.find(json) ?: return null
        return skipWhitespace(json, match.range.last + 1)
    }

    private fun skipWhitespace(json: String, start: Int): Int {
        var index = start
        while (index < json.length && json[index].isWhitespace()) {
            index++
        }
        return index
    }

    private data class ParsedString(
        val value: String,
        val nextIndex: Int,
    )

    private fun parseString(json: String, quoteIndex: Int): ParsedString? {
        val builder = StringBuilder()
        var index = quoteIndex + 1
        while (index < json.length) {
            when (val char = json[index]) {
                '"' -> return ParsedString(builder.toString(), index + 1)
                '\\' -> {
                    index++
                    val escaped = json.getOrNull(index) ?: return null
                    when (escaped) {
                        '"', '\\', '/' -> builder.append(escaped)
                        'b' -> builder.append('\b')
                        'f' -> builder.append('\u000C')
                        'n' -> builder.append('\n')
                        'r' -> builder.append('\r')
                        't' -> builder.append('\t')
                        'u' -> {
                            val hex = json.substringOrNull(index + 1, index + 5) ?: return null
                            val codePoint = hex.toIntOrNull(16) ?: return null
                            builder.append(codePoint.toChar())
                            index += 4
                        }
                        else -> return null
                    }
                }
                else -> builder.append(char)
            }
            index++
        }
        return null
    }

    private fun String.substringOrNull(startIndex: Int, endIndex: Int): String? =
        if (startIndex >= 0 && endIndex <= length && startIndex <= endIndex) {
            substring(startIndex, endIndex)
        } else {
            null
        }
}
