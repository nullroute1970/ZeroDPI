package dev.zerodpi.android.targetscan

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SniScanEntryModel(
    val sni: String,
    val ip: String,
    @SerialName("tcp_latency_ms") val tcpLatencyMs: Long? = null,
    @SerialName("tls_ok") val tlsOk: Boolean = false,
    @SerialName("tls_latency_ms") val tlsLatencyMs: Long? = null,
    @SerialName("cert_valid") val certValid: Boolean = false,
    @SerialName("ttfb_ms") val ttfbMs: Long? = null,
    @SerialName("http_status") val httpStatus: Int? = null,
    val score: Int = 0,
)

@Serializable
data class IpScanEntryModel(
    val ip: String,
    @SerialName("tcp_latency_ms") val tcpLatencyMs: Long? = null,
    @SerialName("tls_ok") val tlsOk: Boolean = false,
    @SerialName("tls_latency_ms") val tlsLatencyMs: Long? = null,
    @SerialName("cert_valid") val certValid: Boolean = false,
    @SerialName("ttfb_ms") val ttfbMs: Long? = null,
    @SerialName("http_status") val httpStatus: Int? = null,
    val score: Int = 0,
)
