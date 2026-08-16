package dev.zerodpi.android.methodscan

import kotlinx.serialization.json.Json

object MethodScanReportParser {
    private val json = Json { ignoreUnknownKeys = true }

    fun parse(text: String): MethodScanReportModel? =
        runCatching { json.decodeFromString<MethodScanReportModel>(text) }.getOrNull()
}
