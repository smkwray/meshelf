package com.meshelf.android.tailscale

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log

/**
 * Watches Tailscale-style VPN networks for a unique CGNAT IPv4 address.
 *
 * Tailscale is usually not Android's *default* network (Wi‑Fi/cellular stays default while the
 * VPN carries selected routes). Binding still requires the VPN [Network] and its CGNAT address —
 * never LAN or `0.0.0.0`. Meshelf trust remains Rust-owned; this is route selection only.
 */
class TailscaleRouteProvider(
    context: Context,
    private val listener: Listener,
) {
    data class Snapshot(
        val network: Network,
        val localAddress: String,
        val networkHandle: Long,
    )

    interface Listener {
        fun onRouteAvailable(snapshot: Snapshot)
        fun onRouteUnavailable(reason: String)
    }

    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private var registered = false
    private var published: Snapshot? = null
    private val vpnNetworks = linkedSetOf<Network>()
    private val vpnLinkProperties = mutableMapOf<Network, LinkProperties>()

    private val request = NetworkRequest.Builder()
        .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
        // Builder defaults include NOT_VPN; that capability never matches a VPN network.
        .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build()

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            vpnNetworks.add(network)
            publishBest()
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                vpnNetworks.add(network)
            } else {
                vpnNetworks.remove(network)
                vpnLinkProperties.remove(network)
            }
            publishBest()
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            vpnNetworks.add(network)
            vpnLinkProperties[network] = linkProperties
            publishBest()
        }

        override fun onLost(network: Network) {
            vpnNetworks.remove(network)
            vpnLinkProperties.remove(network)
            publishBest()
        }
    }

    @Synchronized
    fun start() {
        if (registered) return
        registered = true
        vpnNetworks.clear()
        vpnLinkProperties.clear()
        for (network in connectivity.allNetworks) {
            val caps = connectivity.getNetworkCapabilities(network) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                vpnNetworks.add(network)
                connectivity.getLinkProperties(network)?.let { vpnLinkProperties[network] = it }
            }
        }
        connectivity.registerNetworkCallback(request, callback)
        publishBest()
    }

    @Synchronized
    fun stop() {
        if (!registered) return
        registered = false
        runCatching { connectivity.unregisterNetworkCallback(callback) }
        vpnNetworks.clear()
        vpnLinkProperties.clear()
        published = null
    }

    private fun publishBest() {
        if (!registered) return
        val chosen = TailscaleRouteSelector.selectVpnCgnat(
            vpnNetworks.map { network ->
                val lp = vpnLinkProperties[network] ?: connectivity.getLinkProperties(network)
                val candidates = lp?.linkAddresses
                    ?.mapNotNull { it.address.hostAddress?.substringBefore('%') }
                    .orEmpty()
                network to candidates
            },
        )
        when {
            chosen.isSuccess -> {
                val (network, address) = chosen.getOrThrow()
                val snapshot = Snapshot(network, address, network.networkHandle)
                if (published?.networkHandle == snapshot.networkHandle &&
                    published?.localAddress == address
                ) {
                    return
                }
                published = snapshot
                lastWithdrawReason = null
                Log.i("TailscaleRoute", "Route available: $address on network ${network.networkHandle}")
                listener.onRouteAvailable(snapshot)
            }
            else -> {
                val reason = chosen.exceptionOrNull()?.message
                    ?: "No Tailscale VPN with a unique 100.64.0.0/10 IPv4 address is available."
                Log.w("TailscaleRoute", "Route unavailable: $reason (networks: ${vpnNetworks.size})")
                withdraw(reason)
            }
        }
    }

    private fun withdraw(reason: String) {
        val hadRoute = published != null
        published = null
        if (!hadRoute && reason == lastWithdrawReason) return
        lastWithdrawReason = reason
        listener.onRouteUnavailable(reason)
    }

    private var lastWithdrawReason: String? = null
}
