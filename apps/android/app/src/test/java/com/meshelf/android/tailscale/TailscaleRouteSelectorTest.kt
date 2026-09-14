package com.meshelf.android.tailscale

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TailscaleRouteSelectorTest {
    @Test fun selectsOnlyOneCgnatIpv4() {
        assertEquals(
            "100.64.1.40",
            TailscaleRouteSelector.selectCgnatIpv4(listOf("192.168.1.8", "100.64.1.40", "fd7a:115c:a1e0::9")).getOrThrow(),
        )
    }

    @Test fun rejectsNoMatchAndAmbiguity() {
        assertTrue(TailscaleRouteSelector.selectCgnatIpv4(listOf("10.0.0.2")).isFailure)
        assertTrue(TailscaleRouteSelector.selectCgnatIpv4(listOf("100.64.0.1", "100.127.255.254")).isFailure)
        assertTrue(TailscaleRouteSelector.selectCgnatIpv4(listOf("100.128.0.1")).isFailure)
    }

    @Test fun selectsVpnWithCgnatEvenWhenWifiAlsoPresent() {
        val chosen = TailscaleRouteSelector.selectVpnCgnat(
            listOf(
                "wifi" to listOf("192.168.1.132"),
                "tailscale" to listOf("100.64.1.20", "fd7a:115c:a1e0::9"),
            ),
        ).getOrThrow()
        assertEquals("tailscale" to "100.64.1.20", chosen)
    }

    @Test fun rejectsWhenOnlyWifiAddressesAreOfferedAsVpn() {
        assertTrue(
            TailscaleRouteSelector.selectVpnCgnat(
                listOf("wifi-as-default" to listOf("192.168.1.132")),
            ).isFailure,
        )
    }

    @Test fun rejectsAmbiguousVpnsWithCgnat() {
        assertTrue(
            TailscaleRouteSelector.selectVpnCgnat(
                listOf(
                    "vpn-a" to listOf("100.64.0.1"),
                    "vpn-b" to listOf("100.64.0.2"),
                ),
            ).isFailure,
        )
    }
}
