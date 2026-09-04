package dev.zerodpi.android.targetscan

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

enum class PinKind {
    @SerialName("sni") Sni,
    @SerialName("ip") Ip,
}

@Serializable
data class TargetPin(
    val kind: PinKind,
    val sni: String? = null,
    val ip: String,
    val score: Int? = null,
    @SerialName("picked_at_ms") val pickedAtMs: Long,
)

object TargetPinCodec {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    fun encode(pin: TargetPin): String = json.encodeToString(TargetPin.serializer(), pin)

    fun decode(text: String): TargetPin? =
        runCatching { json.decodeFromString(TargetPin.serializer(), text) }.getOrNull()
}

object TargetScanFiles {
    const val PIN_FILE_NAME = "target_pin.json"
    const val PICK_SCAN_RESULTS_FILE_NAME = "pick_scan_results.json"
}
