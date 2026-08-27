package com.meshelf.android.tailscale

/**
 * Authoritative route proof is deliberately unavailable in the seed.
 *
 * A production implementation must use the owner-approved signed enrollment +
 * foreground VPN candidate + Rust signed-peer route-proof design. It must pass
 * an ephemeral Android Network handle so Rust can call android_setsocknetwork()
 * before connect/bind. It must not scan, scrape another app, or treat VPN
 * membership as Meshelf trust.
 */
interface TailscaleRouteProvider {
    fun snapshotForExplicitOperation(): Result<TailscaleRouteSnapshot>
}

data class TailscaleRouteSnapshot(
    /** Ephemeral value from android.net.Network.getNetworkHandle(); never persist. */
    val networkHandle: Long,
    val localAddress: String,
    val enrolledPeerAddresses: List<String>,
)

class UnavailableTailscaleRouteProvider : TailscaleRouteProvider {
    override fun snapshotForExplicitOperation(): Result<TailscaleRouteSnapshot> =
        Result.failure(
            UnsupportedOperationException(
                "Tailscale route proof is unavailable until the owner selects enrollment/discovery semantics",
            ),
        )
}
