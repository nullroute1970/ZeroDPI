package dev.zerodpi.android.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class NetworkChangeTrackerTest {
    private val tracker = NetworkChangeTracker(debounceMs = 2_000L)

    @Test
    fun initialNetworkAndDuplicateCallbacksAreSuppressed() {
        tracker.initialize(wifi)

        assertNull(tracker.observe(wifi, nowMs = 100L))
        assertEquals(
            NetworkChangeTracker.DueResult.None,
            tracker.consumeIfDue(wifi, nowMs = 3_000L),
        )
    }

    @Test
    fun wifiToMobileSwitchRestartsAfterDebounce() {
        tracker.initialize(wifi)

        assertEquals(2_100L, tracker.observe(cellular, nowMs = 100L))
        assertEquals(
            NetworkChangeTracker.DueResult.Reschedule(2_100L),
            tracker.consumeIfDue(cellular, nowMs = 2_099L),
        )
        assertEquals(
            NetworkChangeTracker.DueResult.Restart,
            tracker.consumeIfDue(cellular, nowMs = 2_100L),
        )
    }

    @Test
    fun lossWaitsForReplacementAndSameNetworkReconnectionRestarts() {
        tracker.initialize(wifi)

        assertNull(tracker.observe(null, nowMs = 100L))
        assertEquals(
            NetworkChangeTracker.DueResult.None,
            tracker.consumeIfDue(null, nowMs = 5_000L),
        )
        assertEquals(7_100L, tracker.observe(wifi, nowMs = 5_100L))
        assertEquals(
            NetworkChangeTracker.DueResult.Restart,
            tracker.consumeIfDue(wifi, nowMs = 7_100L),
        )
    }

    @Test
    fun firstNetworkAfterStartingDisconnectedRestarts() {
        tracker.initialize(null)

        assertEquals(2_500L, tracker.observe(cellular, nowMs = 500L))
        assertEquals(
            NetworkChangeTracker.DueResult.Restart,
            tracker.consumeIfDue(cellular, nowMs = 2_500L),
        )
    }

    @Test
    fun localAddressAndInterfaceChangesAreRelevant() {
        tracker.initialize(wifi)
        val newAddress = wifi.copy(localAddresses = setOf("192.0.2.11"))

        assertEquals(2_000L, tracker.observe(newAddress, nowMs = 0L))
        assertEquals(
            NetworkChangeTracker.DueResult.Restart,
            tracker.consumeIfDue(newAddress, nowMs = 2_000L),
        )

        val newInterface = newAddress.copy(interfaceName = "wlan1")
        assertEquals(4_100L, tracker.observe(newInterface, nowMs = 2_100L))
    }

    @Test
    fun transportChangeIsRelevantEvenWhenNetworkIdentityIsReused() {
        tracker.initialize(wifi)
        val changedTransport = wifi.copy(transports = setOf("cellular"))

        assertEquals(2_250L, tracker.observe(changedTransport, nowMs = 250L))
    }

    @Test
    fun capabilityNoiseIsIgnoredBySnapshotAndRapidChangesCoalesce() {
        tracker.initialize(wifi)

        assertNull(tracker.observe(wifi, nowMs = 10L))
        assertEquals(2_100L, tracker.observe(cellular, nowMs = 100L))
        assertEquals(2_500L, tracker.observe(otherWifi, nowMs = 500L))
        assertEquals(2_500L, tracker.observe(otherWifi, nowMs = 1_000L))
        assertEquals(
            NetworkChangeTracker.DueResult.Restart,
            tracker.consumeIfDue(otherWifi, nowMs = 2_500L),
        )
        assertEquals(
            NetworkChangeTracker.DueResult.None,
            tracker.consumeIfDue(otherWifi, nowMs = 5_000L),
        )
    }

    private companion object {
        val wifi = NetworkSnapshot(
            identity = "100",
            transports = setOf("wifi"),
            interfaceName = "wlan0",
            localAddresses = setOf("192.0.2.10"),
        )
        val cellular = NetworkSnapshot(
            identity = "101",
            transports = setOf("cellular"),
            interfaceName = "rmnet0",
            localAddresses = setOf("198.51.100.2"),
        )
        val otherWifi = NetworkSnapshot(
            identity = "102",
            transports = setOf("wifi"),
            interfaceName = "wlan0",
            localAddresses = setOf("203.0.113.4"),
        )
    }
}
