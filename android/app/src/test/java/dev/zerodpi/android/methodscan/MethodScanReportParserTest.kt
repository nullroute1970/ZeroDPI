package dev.zerodpi.android.methodscan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MethodScanReportParserTest {
    private val sample = """
        {
          "mode": "sni_method_scan",
          "target_sni": "example.com",
          "target_ip": "1.2.3.4",
          "target_score": 99,
          "samples_per_method": 3,
          "interval_ms": 1000,
          "methods": [
            {
              "method": "wrong_seq",
              "samples_total": 3,
              "samples_ok": 3,
              "success_rate": 100.0,
              "avg_ttfb_ms": 120.5,
              "min_ttfb_ms": 110,
              "max_ttfb_ms": 131,
              "avg_tls_ms": 40.0,
              "http_status": 200,
              "last_error": null
            },
            {
              "method": "tls_frag",
              "samples_total": 3,
              "samples_ok": 1,
              "success_rate": 33.33,
              "avg_ttfb_ms": 300.0,
              "min_ttfb_ms": 300,
              "max_ttfb_ms": 300,
              "avg_tls_ms": null,
              "http_status": null,
              "last_error": "handshake timeout"
            }
          ]
        }
    """.trimIndent()

    @Test
    fun parsesMethodScanReport() {
        val report = MethodScanReportParser.parse(sample)
        assertEquals("sni_method_scan", report?.mode)
        assertEquals("example.com", report?.targetSni)
        assertEquals(2, report?.methods?.size)
        assertEquals("wrong_seq", report?.methods?.get(0)?.method)
        assertEquals(100.0, report?.methods?.get(0)?.successRate ?: 0.0, 0.001)
        assertEquals("handshake timeout", report?.methods?.get(1)?.lastError)
    }

    @Test
    fun ignoresUnknownKeysAndRejectsMalformedJson() {
        assertNull(MethodScanReportParser.parse("not json"))
        assertNull(MethodScanReportParser.parse("""{"mode": 5}"""))
        assertEquals("ip_method_scan", MethodScanReportParser.parse("""{"mode":"ip_method_scan","target_sni":"a","target_ip":"1.1.1.1","target_score":1,"samples_per_method":1,"interval_ms":0,"methods":[],"extra":true}""")?.mode)
    }
}
