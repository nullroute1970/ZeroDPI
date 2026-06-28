package dev.zerodpi.android.runtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RuntimeEventLineParserTest {
    @Test
    fun extractsStartupPidForProcessStop() {
        assertEquals(
            1234L,
            RuntimeEventLineParser.startupPid(
                """{"event":"startup","contract_version":1,"version":"0.1.0","pid":1234}""",
            ),
        )
        assertNull(RuntimeEventLineParser.startupPid("""{"event":"config_loaded","pid":1234}"""))
        assertNull(RuntimeEventLineParser.startupPid("plain stderr log line"))
    }

    @Test
    fun parsesConfigLoadedEvent() {
        val event = RuntimeEventLineParser.parse(
            """
            {"event":"config_loaded","path":"/data/config.toml","mode":"sni_spoof","bypass_method":"tls_frag","listen_host":"127.0.0.1","listen_port":1080,"auto_select":true,"no_tui":true,"root_required":false}
            """.trimIndent(),
        )

        assertTrue(event is ZeroDpiRunnerEvent.ConfigLoaded)
        val config = event as ZeroDpiRunnerEvent.ConfigLoaded
        assertEquals("sni_spoof", config.mode)
        assertEquals("tls_frag", config.bypassMethod)
        assertEquals("127.0.0.1", config.listenHost)
        assertEquals(1080, config.listenPort)
        assertEquals(false, config.rootRequired)
    }

    @Test
    fun parsesRelayBytesFinalField() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"relay_bytes","src_port":44300,"c2s_bytes":1200,"s2c_bytes":3400,"final":true}""",
        )

        assertTrue(event is ZeroDpiRunnerEvent.RelayBytes)
        val relay = event as ZeroDpiRunnerEvent.RelayBytes
        assertEquals(44300, relay.sourcePort)
        assertEquals(1200L, relay.clientToServerBytes)
        assertEquals(3400L, relay.serverToClientBytes)
        assertEquals(true, relay.isFinal)
    }

    @Test
    fun parsesRootlessAlternativeArray() {
        val event = RuntimeEventLineParser.parse(
            """
            {"event":"root_required","mode":"sni_spoof","bypass_method":"wrong_seq","message":"root \"needed\"","rootless_alternatives":["MODE = \"ip_bypass\"","BYPASS_METHOD = \"tls_frag\""]}
            """.trimIndent(),
        )

        assertTrue(event is ZeroDpiRunnerEvent.RootRequired)
        val rootRequired = event as ZeroDpiRunnerEvent.RootRequired
        assertEquals("root \"needed\"", rootRequired.message)
        assertEquals(
            listOf("MODE = \"ip_bypass\"", "BYPASS_METHOD = \"tls_frag\""),
            rootRequired.alternatives,
        )
    }

    @Test
    fun ignoresNonJsonLogLines() {
        assertNull(RuntimeEventLineParser.parse("plain stderr log line"))
    }
}
