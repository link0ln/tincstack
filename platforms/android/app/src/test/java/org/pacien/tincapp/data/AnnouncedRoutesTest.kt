/*
 * Tinc Mesh VPN: Android client and user interface
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

package org.pacien.tincapp.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AnnouncedRoutesTest {
  /** `tinc dump subnets` on ruvds2, 2026-09-28, plus a LAN behind the windows node. */
  private val dump = listOf(
    "ff:ff:ff:ff:ff:ff owner (broadcast)",
    "10.8.179.1 owner ruvds2",
    "10.8.179.2 owner phone",
    "10.8.179.3 owner windows",
    "10.8.179.4 owner euvds",
    "255.255.255.255 owner (broadcast)",
    "224.0.0.0/4 owner (broadcast)",
    "0.0.0.0/0 owner euvds",
    "192.168.1.0/24#10 owner windows",
    "ff00::/8 owner (broadcast)",
  )
  private val everyone = setOf("phone", "ruvds2", "windows", "euvds")
  private val pool = VpnInterfaceConfiguration(
    addresses = listOf(CidrAddress("10.8.179.2", 24)),
    routes = listOf(CidrAddress("10.8.179.0", 24)))

  private fun cidr(s: String) = CidrAddress.fromSlashSeparated(s)
  private fun select(reachable: Set<String> = everyone, base: VpnInterfaceConfiguration = pool, lines: List<String> = dump) =
    AnnouncedRoutes.select(AnnouncedRoutes.parse(lines), "phone", reachable, base)

  @Test
  fun parsesTheDaemonsDumpAndSkipsBroadcastAndMacEntries() {
    val parsed = AnnouncedRoutes.parse(dump)
    assertEquals(6, parsed.size)
    assertEquals(AnnouncedRoutes.Announcement(cidr("10.8.179.1/32"), "ruvds2"), parsed[0])
    assertEquals(AnnouncedRoutes.Announcement(cidr("0.0.0.0/0"), "euvds"), parsed[4])
    assertEquals(AnnouncedRoutes.Announcement(cidr("192.168.1.0/24"), "windows"), parsed[5]) // "#10" weight dropped
  }

  @Test
  fun theExitsDefaultRouteIsTakenAndCoversTheLanBehindAnotherNode() {
    assertEquals(listOf(cidr("0.0.0.0/0")), select())
  }

  @Test
  fun anUnreachableExitTakesItsDefaultRouteWithIt() {
    assertEquals(listOf(cidr("192.168.1.0/24")), select(reachable = everyone - "euvds"))
  }

  @Test
  fun hostRoutesInsideThePoolAreAlreadyCovered() {
    assertTrue(select(lines = listOf("10.8.179.3 owner windows", "10.8.179.1 owner ruvds2")).isEmpty())
  }

  @Test
  fun withoutAPoolRouteEachNodesAddressIsRoutedOnItsOwn() {
    val bare = pool.copy(routes = emptyList())
    assertEquals(listOf(cidr("10.8.179.1/32"), cidr("10.8.179.3/32")),
      select(base = bare, lines = listOf("10.8.179.3 owner windows", "10.8.179.1 owner ruvds2", "10.8.179.2 owner phone")))
  }

  @Test
  fun ownSubnetsAndMulticastAreNeverRouted() {
    assertTrue(select(lines = listOf("172.16.0.0/16 owner phone", "239.1.0.0/16 owner windows")).isEmpty())
  }

  @Test
  fun ipv6OnlyWithAnIpv6Address() {
    val lines = listOf("::/0 owner euvds", "fd00:1::/64 owner windows")
    assertTrue(select(lines = lines).isEmpty())
    val v6 = pool.copy(addresses = pool.addresses + CidrAddress("fd00:9::2", 64))
    assertEquals(listOf(cidr("::/0")).map { AnnouncedRoutes.normalise(it) }, select(base = v6, lines = lines))
  }

  @Test
  fun hostBitsAreClearedForTheBuilder() {
    assertEquals(cidr("10.1.2.0/24"), AnnouncedRoutes.normalise(cidr("10.1.2.3/24")))
    assertEquals(cidr("0.0.0.0/0"), AnnouncedRoutes.normalise(cidr("10.1.2.3/0")))
    assertEquals(null, AnnouncedRoutes.normalise(CidrAddress("host.example", 24)))
    assertEquals(listOf(cidr("10.9.0.0/16")), select(lines = listOf("10.9.8.7/16 owner windows")))
  }

  @Test
  fun macSubnetsAndMalformedAddressesAreSkippedWithoutALookup() {
    assertTrue(AnnouncedRoutes.parse(listOf(
      "00:11:22:33:44:55 owner windows", "300.1.1.1/32 owner windows", "1::2::3/64 owner windows",
      "1:2:3:4:5:6:7:8:9/64 owner windows", "10.0.0.0/33 owner windows", "garbage")).let {
      it.mapNotNull { a -> AnnouncedRoutes.normalise(a.subnet) }
    }.isEmpty())
    assertEquals(cidr("fd00:1:0:0:0:0:0:0/48").let(AnnouncedRoutes::normalise),
      AnnouncedRoutes.normalise(cidr("fd00:1::5/48")))
  }

  @Test
  fun covers() {
    assertTrue(AnnouncedRoutes.covers(cidr("0.0.0.0/0"), cidr("192.168.1.0/24")))
    assertTrue(AnnouncedRoutes.covers(cidr("10.8.179.0/24"), cidr("10.8.179.4/32")))
    assertFalse(AnnouncedRoutes.covers(cidr("10.8.179.0/24"), cidr("10.8.0.0/16")))
    assertFalse(AnnouncedRoutes.covers(cidr("10.8.179.0/24"), cidr("10.8.180.1/32")))
    assertFalse(AnnouncedRoutes.covers(cidr("0.0.0.0/0"), CidrAddress("fd00::", 8)))
  }

  @Test
  fun theDefaultRouteBringsResolversUnlessTheNetworkNamesItsOwn() {
    val full = AnnouncedRoutes.apply(pool, listOf(cidr("0.0.0.0/0")))
    assertEquals(listOf(cidr("10.8.179.0/24"), cidr("0.0.0.0/0")), full.routes)
    assertEquals(AnnouncedRoutes.FULL_TUNNEL_DNS, full.dnsServers)
    assertEquals(listOf("10.8.179.1"), AnnouncedRoutes.apply(pool.copy(dnsServers = listOf("10.8.179.1")), listOf(cidr("0.0.0.0/0"))).dnsServers)
    assertTrue(AnnouncedRoutes.apply(pool, listOf(cidr("192.168.1.0/24"))).dnsServers.isEmpty())
    assertEquals(pool, AnnouncedRoutes.apply(pool, emptyList()))
  }

  @Test
  fun rememberedRoutesRoundTripAndGarbageIsDropped() {
    val routes = listOf(cidr("0.0.0.0/0"), cidr("192.168.1.0/24"))
    assertEquals(routes, AnnouncedRoutes.deserialise(AnnouncedRoutes.serialise(routes)))
    assertEquals(listOf(cidr("10.1.0.0/16")), AnnouncedRoutes.deserialise(" nonsense, 10.1.2.3/16 ,,x/y"))
    assertTrue(AnnouncedRoutes.deserialise(null).isEmpty())
  }
}
