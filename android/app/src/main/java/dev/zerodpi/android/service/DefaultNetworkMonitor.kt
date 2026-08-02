package dev.zerodpi.android.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

internal data class NetworkSnapshot(
    val identity: String,
    val transports: Set<String>,
    val interfaceName: String?,
    val localAddresses: Set<String>,
)

/**
 * Tracks only routing-relevant default-network state. Capability updates such as validation and
 * metering do not appear in [NetworkSnapshot], so they cannot restart the runtime.
 */
internal class NetworkChangeTracker(
    private val debounceMs: Long,
) {
    sealed interface DueResult {
        data object None : DueResult
        data object Restart : DueResult
        data class Reschedule(val deadlineMs: Long) : DueResult
    }

    private var committed: NetworkSnapshot? = null
    private var awaitingReplacement = false
    private var candidate: NetworkSnapshot? = null
    private var candidateDeadlineMs: Long? = null

    fun initialize(initial: NetworkSnapshot?) {
        committed = initial
        awaitingReplacement = initial == null
        candidate = null
        candidateDeadlineMs = null
    }

    fun observe(snapshot: NetworkSnapshot?, nowMs: Long): Long? {
        if (snapshot == null) {
            awaitingReplacement = true
            candidate = null
            candidateDeadlineMs = null
            return null
        }

        if (snapshot == candidate) {
            return candidateDeadlineMs
        }
        if (!awaitingReplacement && snapshot == committed) {
            candidate = null
            candidateDeadlineMs = null
            return null
        }

        candidate = snapshot
        candidateDeadlineMs = nowMs + debounceMs
        return candidateDeadlineMs
    }

    fun consumeIfDue(
        snapshot: NetworkSnapshot?,
        nowMs: Long,
    ): DueResult {
        if (snapshot == null) {
            observe(null, nowMs)
            return DueResult.None
        }
        if (snapshot != candidate) {
            return observe(snapshot, nowMs)
                ?.let(DueResult::Reschedule)
                ?: DueResult.None
        }

        val deadline = candidateDeadlineMs ?: return DueResult.None
        if (nowMs < deadline) {
            return DueResult.Reschedule(deadline)
        }

        committed = snapshot
        awaitingReplacement = false
        candidate = null
        candidateDeadlineMs = null
        return DueResult.Restart
    }
}

/** Service-owned default-network observer for API 23 and newer. */
internal class DefaultNetworkMonitor(
    context: Context,
    private val scope: CoroutineScope,
    private val onStableNetworkChange: () -> Unit,
    private val debounceMs: Long = NETWORK_CHANGE_DEBOUNCE_MS,
) {
    private val appContext = context.applicationContext
    private val connectivityManager =
        appContext.getSystemService(ConnectivityManager::class.java)
    private val tracker = NetworkChangeTracker(debounceMs)
    private var debounceJob: Job? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var receiver: BroadcastReceiver? = null
    private var started = false

    fun start() {
        if (started || connectivityManager == null) {
            return
        }
        started = true
        tracker.initialize(currentSnapshot())

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = refresh()
                override fun onLost(network: Network) = refresh()
                override fun onCapabilitiesChanged(
                    network: Network,
                    networkCapabilities: NetworkCapabilities,
                ) = refresh()

                override fun onLinkPropertiesChanged(
                    network: Network,
                    linkProperties: LinkProperties,
                ) = refresh()
            }
            callback = networkCallback
            connectivityManager.registerDefaultNetworkCallback(networkCallback)
        } else {
            @Suppress("DEPRECATION")
            val connectivityReceiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) = refresh()
            }
            receiver = connectivityReceiver
            @Suppress("DEPRECATION")
            appContext.registerReceiver(
                connectivityReceiver,
                IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION),
            )
        }
    }

    fun stop() {
        if (!started) {
            return
        }
        started = false
        debounceJob?.cancel()
        debounceJob = null
        callback?.let { networkCallback ->
            runCatching { connectivityManager?.unregisterNetworkCallback(networkCallback) }
        }
        callback = null
        receiver?.let { connectivityReceiver ->
            runCatching { appContext.unregisterReceiver(connectivityReceiver) }
        }
        receiver = null
    }

    private fun refresh() {
        scope.launch {
            if (!started) {
                return@launch
            }
            val deadline = tracker.observe(currentSnapshot(), SystemClock.elapsedRealtime())
            schedule(deadline)
        }
    }

    private fun schedule(deadlineMs: Long?) {
        debounceJob?.cancel()
        debounceJob = null
        if (deadlineMs == null) {
            return
        }
        debounceJob = scope.launch {
            delay((deadlineMs - SystemClock.elapsedRealtime()).coerceAtLeast(0L))
            when (
                val result = tracker.consumeIfDue(
                    currentSnapshot(),
                    SystemClock.elapsedRealtime(),
                )
            ) {
                NetworkChangeTracker.DueResult.None -> Unit
                NetworkChangeTracker.DueResult.Restart -> onStableNetworkChange()
                is NetworkChangeTracker.DueResult.Reschedule -> schedule(result.deadlineMs)
            }
        }
    }

    private fun currentSnapshot(): NetworkSnapshot? {
        val manager = connectivityManager ?: return null
        val network = manager.activeNetwork ?: return null
        val capabilities = manager.getNetworkCapabilities(network) ?: return null
        val linkProperties = manager.getLinkProperties(network)
        return NetworkSnapshot(
            identity = network.toString(),
            transports = capabilities.routingTransports(),
            interfaceName = linkProperties?.interfaceName,
            localAddresses = linkProperties?.linkAddresses
                .orEmpty()
                .mapNotNull { it.address?.hostAddress }
                .toSet(),
        )
    }

    private fun NetworkCapabilities.routingTransports(): Set<String> = buildSet {
        if (hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add("cellular")
        if (hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add("wifi")
        if (hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) add("bluetooth")
        if (hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add("ethernet")
        if (hasTransport(NetworkCapabilities.TRANSPORT_VPN)) add("vpn")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (hasTransport(NetworkCapabilities.TRANSPORT_WIFI_AWARE)) add("wifi_aware")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            if (hasTransport(NetworkCapabilities.TRANSPORT_LOWPAN)) add("lowpan")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (hasTransport(NetworkCapabilities.TRANSPORT_USB)) add("usb")
        }
    }

    private companion object {
        const val NETWORK_CHANGE_DEBOUNCE_MS = 2_000L
    }
}
