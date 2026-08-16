package dev.zerodpi.android.methodscan

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class MethodScanEntryModel(
    val method: String,
    @SerialName("samples_total") val samplesTotal: Int,
    @SerialName("samples_ok") val samplesOk: Int,
    @SerialName("success_rate") val successRate: Double,
    @SerialName("avg_ttfb_ms") val avgTtfbMs: Double? = null,
    @SerialName("avg_tls_ms") val avgTlsMs: Double? = null,
    @SerialName("http_status") val httpStatus: Int? = null,
    @SerialName("last_error") val lastError: String? = null,
)

@Serializable
data class MethodScanReportModel(
    val mode: String,
    @SerialName("target_sni") val targetSni: String,
    @SerialName("target_ip") val targetIp: String,
    @SerialName("target_score") val targetScore: Int,
    @SerialName("samples_per_method") val samplesPerMethod: Int,
    @SerialName("interval_ms") val intervalMs: Long,
    val methods: List<MethodScanEntryModel>,
)
