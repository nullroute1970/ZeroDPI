package dev.zerodpi.android.targetscan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ScanResultParserTest {
    private val sniJson = """
        [
          {
            "sni": "auth.vercel.com",
            "ip": "76.76.21.21",
            "tcp_latency_ms": 42,
            "tls_ok": true,
            "tls_latency_ms": 88,
            "cert_valid": true,
            "ttfb_ms": 140,
            "download_bps": 1048576.0,
            "upload_bps": 786432.0,
            "speed_bps": 1048576.0,
            "http_status": 200,
            "score": 91
          },
          {
            "sni": "unreachable.example",
            "ip": "10.0.0.1",
            "tcp_latency_ms": null,
            "tls_ok": false,
            "tls_latency_ms": null,
            "cert_valid": false,
            "ttfb_ms": null,
            "download_bps": null,
            "upload_bps": null,
            "speed_bps": null,
            "http_status": null,
            "score": 0
          }
        ]
    """.trimIndent()

    private val ipJson = """
        [
          {
            "ip": "104.16.132.229",
            "tcp_latency_ms": 35,
            "tls_ok": true,
            "tls_latency_ms": 70,
            "cert_valid": true,
            "ttfb_ms": 120,
            "download_bps": 2048000.0,
            "upload_bps": 1048576.0,
            "speed_bps": 2048000.0,
            "http_status": 200,
            "score": 96
          }
        ]
    """.trimIndent()

    @Test
    fun parsesSniResults() {
        val entries = ScanResultParser.parseSni(sniJson)
        assertEquals(2, entries?.size)
        assertEquals("auth.vercel.com", entries?.get(0)?.sni)
        assertEquals("76.76.21.21", entries?.get(0)?.ip)
        assertEquals(91, entries?.get(0)?.score)
        assertEquals(42L, entries?.get(0)?.tcpLatencyMs)
        assertEquals(0, entries?.get(1)?.score)
    }

    @Test
    fun parsesIpResults() {
        val entries = ScanResultParser.parseIp(ipJson)
        assertEquals(1, entries?.size)
        assertEquals("104.16.132.229", entries?.get(0)?.ip)
        assertEquals(96, entries?.get(0)?.score)
    }

    @Test
    fun returnsNullForGarbageAndEmptyArrays() {
        assertNull(ScanResultParser.parseSni("nope"))
        assertNull(ScanResultParser.parseIp("{}"))
        assertEquals(0, ScanResultParser.parseSni("[]")?.size)
        assertEquals(0, ScanResultParser.parseIp("[]")?.size)
    }
}
