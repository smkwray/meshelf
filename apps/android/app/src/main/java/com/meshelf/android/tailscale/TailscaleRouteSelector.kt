package com.meshelf.android.tailscale

/** Pure policy for selecting one literal Tailscale-style CGNAT IPv4 address. */
object TailscaleRouteSelector {
    fun isCgnatIpv4(value: String): Boolean {
        val pieces = value.split('.')
        if (pieces.size != 4) return false
        val octets = pieces.map { part ->
            if (part.isEmpty() || part.length > 3 || part.any { !it.isDigit() }) return false
            if (part.length > 1 && part.startsWith('0')) return false
            part.toIntOrNull()?.takeIf { it in 0..255 } ?: return false
        }
        return octets[0] == 100 && octets[1] in 64..127
    }

    /** Fails closed when there is no unique CGNAT IPv4 candidate. */
    fun selectCgnatIpv4(candidates: Iterable<String>): Result<String> = runCatching {
        val matches = candidates
            .map(String::trim)
            .filter(::isCgnatIpv4)
            .distinct()
        require(matches.size == 1) {
            "expected exactly one CGNAT IPv4 address, found ${matches.size}"
        }
        matches.single()
    }

    /**
     * Among VPN networks, pick the single network that exposes exactly one CGNAT IPv4.
     * Ambiguous multi-VPN CGNAT setups fail closed.
     */
    fun <T> selectVpnCgnat(
        vpnLinkAddresses: Iterable<Pair<T, Iterable<String>>>,
    ): Result<Pair<T, String>> = runCatching {
        val matches = vpnLinkAddresses.mapNotNull { (network, candidates) ->
            selectCgnatIpv4(candidates).getOrNull()?.let { network to it }
        }
        require(matches.isNotEmpty()) {
            "No VPN network has a Tailscale CGNAT (100.64.0.0/10) IPv4 address. " +
                "Confirm Tailscale is connected; Wi‑Fi alone is not enough."
        }
        require(matches.size == 1) {
            "expected exactly one VPN with a CGNAT IPv4 address, found ${matches.size}"
        }
        matches.single()
    }
}
