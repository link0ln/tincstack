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

package org.pacien.tincapp.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** `tinc dump nodes` / `dump connections` lines as core/tincd/src/tincctl.c prints them. */
class PeerStatusTest {
  private val self = "phone id 0a0b0c0d0e0f at MYSELF port 0 cipher 0 digest 0 maclength 0 compression 0 options 700000c " +
    "status 0018 nexthop phone via phone distance 0 pmtu 1518 (min 0 max 1518) rx 0 0 tx 0 0 transports plain,sf"
  private val direct = "node_a id 01 at 10.47.31.10 port 655 cipher 0 digest 0 maclength 0 compression 0 options 700000c " +
    "status 0892 nexthop node_a via node_a distance 1 pmtu 1451 (min 1451 max 1451) rx 10 900 tx 12 1000 transports plain,sf,https rtt 0.667"
  private val relayed = "node_b id 02 at 10.47.31.11 port 655 cipher 0 digest 0 maclength 0 compression 0 options 700000c " +
    "status 0012 nexthop node_a via node_a distance 2 pmtu 1400 (min 0 max 1400) rx 0 0 tx 0 0 transports plain"
  private val down = "node_c id 03 at unknown port unknown cipher 0 digest 0 maclength 0 compression 0 options 0 " +
    "status 0000 nexthop - via - distance 0 pmtu 1518 (min 0 max 1518) rx 0 0 tx 0 0 transports plain"
  private val connections = listOf(
    "<control> at localhost port unix options 0 socket 7 status 0 transport plain",
    "node_a at 10.47.31.10 port 655 options 700000c socket 5 status 5 transport https",
  )

  @Test
  fun thisDevice() {
    val p = PeerStatus.parseNode(self)!!
    assertTrue(p.self)
    assertTrue(p.reachable)
    assertNull(p.address)
    assertFalse(p.directUdp)
  }

  @Test
  fun directPeerWithItsCarrierAndRtt() {
    val p = PeerStatus.parseNode(direct, PeerStatus.parseConnections(connections))!!
    assertTrue(p.reachable)
    assertTrue(p.directUdp)
    assertNull(p.via)
    assertEquals("10.47.31.10", p.address)
    assertEquals("655", p.port)
    assertEquals(0.667, p.rttMs!!, 1e-9)
    assertEquals("https", p.transport)
  }

  @Test
  fun relayedAndUnreachablePeers() {
    val b = PeerStatus.parseNode(relayed)!!
    assertTrue(b.reachable)
    assertEquals("node_a", b.via)
    assertFalse(b.directUdp)
    val c = PeerStatus.parseNode(down)!!
    assertFalse(c.reachable)
    assertNull(c.address)
    assertNull(c.via)
  }

  @Test
  fun controlConnectionIsNotAPeer() {
    assertEquals(mapOf("node_a" to "https"), PeerStatus.parseConnections(connections))
  }

  @Test
  fun orderIsThisDeviceThenReachableThenName() {
    val names = PeerStatus.parse(listOf(down, relayed, direct, self, "garbage"), connections).map { it.name }
    assertEquals(listOf("phone", "node_a", "node_b", "node_c"), names)
  }
}
