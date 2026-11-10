/*
 * tincstack for Android
 * Copyright (C) 2026 tincstack contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package org.pacien.tincapp.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class ConnectivityChangeReceiverTest {

  @Test
  fun resolveUplinkLocalIpHandlesIpv6OnlyDualStackAndLinkLocal() {
    val linkLocalV4 = InetAddress.getByName("169.254.10.20")
    val linkLocalV6 = InetAddress.getByName("fe80::1234")
    val globalV4 = InetAddress.getByName("192.0.2.44")
    val globalV6 = InetAddress.getByName("2001:db8::abcd")

    // Link-local only -> "-"
    assertEquals(
      "-" to false,
      ConnectivityChangeReceiver.resolveUplinkLocalIp(listOf(linkLocalV4, linkLocalV6), netHandle = 100L),
    )

    // IPv6-only cellular -> passes global IPv6 so C core opens AF_INET6 socket
    assertEquals(
      globalV6.hostAddress to true,
      ConnectivityChangeReceiver.resolveUplinkLocalIp(listOf(linkLocalV6, globalV6), netHandle = 100L),
    )

    // Fresh dual-stack Wi-Fi with netHandle != 0 -> passes "-" so C binds both AF_INET & AF_INET6 via netHandle
    assertEquals(
      "-" to false,
      ConnectivityChangeReceiver.resolveUplinkLocalIp(listOf(globalV4, globalV6), netHandle = 100L),
    )

    // Transition from IPv6-only (previouslyPushedV6 = true) to dual-stack -> pushes IPv4 so AF_INET also opens
    assertEquals(
      "192.0.2.44" to true,
      ConnectivityChangeReceiver.resolveUplinkLocalIp(
        listOf(globalV4, globalV6),
        netHandle = 100L,
        previouslyPushedV6 = true,
      ),
    )
  }

  @Test
  fun unvalidatedCaptivePortalWifiBecomesBackupAndDefaultModeIsFailover() {
    assertEquals(100 to false, ConnectivityChangeReceiver.effectiveUplinkPolicy(100, baseBackup = false, validated = true))
    assertEquals(25 to true, ConnectivityChangeReceiver.effectiveUplinkPolicy(100, baseBackup = false, validated = false))
    assertEquals(50 to true, ConnectivityChangeReceiver.effectiveUplinkPolicy(50, baseBackup = true, validated = true))

    assertEquals("failover", ConnectivityChangeReceiver.normalizeMultipathMode(null))
    assertEquals("failover", ConnectivityChangeReceiver.normalizeMultipathMode("  "))
    assertTrue(ConnectivityChangeReceiver.isMultipathEnabled(null))
    assertTrue(ConnectivityChangeReceiver.isMultipathEnabled("failover"))
    assertFalse(ConnectivityChangeReceiver.isMultipathEnabled("off"))
    assertFalse(ConnectivityChangeReceiver.isMultipathEnabled("no"))
  }
}
