package dev.zerodpi.android.targetscan

import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

object ScanResultParser {
    private val json = Json { ignoreUnknownKeys = true }

    fun parseSni(text: String): List<SniScanEntryModel>? =
        runCatching {
            json.decodeFromString(ListSerializer(SniScanEntryModel.serializer()), text)
        }.getOrNull()

    fun parseIp(text: String): List<IpScanEntryModel>? =
        runCatching {
            json.decodeFromString(ListSerializer(IpScanEntryModel.serializer()), text)
        }.getOrNull()
}
