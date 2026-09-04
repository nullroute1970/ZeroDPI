package dev.zerodpi.android.targetscan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TargetPinCodecTest {
    @Test
    fun encodesSniPinWithSnakeCaseKind() {
        val pin = TargetPin(
            kind = PinKind.Sni,
            sni = "edge.example.com",
            ip = "1.2.3.4",
            score = 95,
            pickedAtMs = 1_757_000_000_000L,
        )
        val json = TargetPinCodec.encode(pin)
        assertEquals(
            """{"kind":"sni","sni":"edge.example.com","ip":"1.2.3.4","score":95,"picked_at_ms":1757000000000}""",
            json,
        )
    }

    @Test
    fun roundTripsIpPinWithoutSni() {
        val pin = TargetPin(kind = PinKind.Ip, sni = null, ip = "104.16.132.229", score = null, pickedAtMs = 42L)
        assertEquals(pin, TargetPinCodec.decode(TargetPinCodec.encode(pin)))
    }

    @Test
    fun returnsNullForGarbage() {
        assertNull(TargetPinCodec.decode("not json"))
        assertNull(TargetPinCodec.decode("""{"ip": 7}"""))
    }

    @Test
    fun ignoresUnknownKeys() {
        val pin = TargetPinCodec.decode(
            """{"kind":"sni","sni":"a.example","ip":"5.6.7.8","extra":true,"picked_at_ms":1}""",
        )
        assertEquals("a.example", pin?.sni)
    }
}
