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

package org.pacien.tincapp.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.ServerSocket
import java.net.URL

class DiagManagerTest {
  @get:Rule
  val tmp = TemporaryFolder()

  private val selfLine =
    "phone id 0a0b0c at MYSELF port 0 cipher 0 digest 0 maclength 0 compression 0 options 700000c " +
      "status 0018 nexthop phone via phone distance 0 pmtu 1518 (min 0 max 1518) rx 0 0 tx 0 0 transports plain,sf"
  private val ruvdsUdpLine =
    "ruvds id 010203 at 198.51.100.10 port 443 cipher 0 digest 0 maclength 0 compression 0 options 700000c " +
      "status 00d6 nexthop ruvds via ruvds distance 1 pmtu 1420 (min 1420 max 1420) rx 100 50000 tx 120 60000 transports plain,sf,obfs,https,quic rtt 35.5"
  private val ruvdsTcpFallbackLine =
    "ruvds id 010203 at 198.51.100.10 port 443 cipher 0 digest 0 maclength 0 compression 0 options 700000c " +
      "status 0056 nexthop ruvds via ruvds distance 1 pmtu 1250 (min 1250 max 1420) rx 100 50000 tx 150 90000 transports plain,sf,obfs,https,quic rtt 480.0"

  @Test
  fun parseSnapshotAndDiagPingOutput() {
    val snap = DiagManager.buildSnapshotFromLines(
      net = "mynet",
      nodeLines = listOf(selfLine, ruvdsUdpLine),
      edgeLines = listOf("phone to ruvds at 198.51.100.10 port 443 local 10.0.0.2 port 51234 options 700000c weight 71"),
      subnetLines = listOf("10.99.0.5/32#10 owner phone", "10.99.0.1/32#10 owner ruvds"),
      connLines = listOf("ruvds at 198.51.100.10 port 443 options 700000c socket 6 status 5 transport quic"),
    )
    assertEquals(2, snap.nodes.size)
    val selfNode = snap.nodes["phone"]!!
    assertTrue(selfNode.isSelf)
    assertEquals("10.99.0.5", selfNode.vpnAddress)

    val peer = snap.nodes["ruvds"]!!
    assertFalse(peer.isSelf)
    assertTrue(peer.reachable)
    assertEquals("direct-udp", peer.link)
    assertEquals("quic", peer.transport)
    assertEquals("10.99.0.1", peer.vpnAddress)
    assertEquals(1420, peer.pmtu)
    assertEquals(35.5, peer.rtt, 1e-6)

    val pingOk = DiagManager.parseDiagPingOutput(
      listOf("OK from=10.99.0.1 node=ruvds type=0 code=0 rtt_ms=28.45 ttl=64 mtu=0 seq=1 size=56")
    )
    assertEquals(true, pingOk["ok"])
    assertEquals("echo_reply", pingOk["status"])
    assertEquals("10.99.0.1", pingOk["from_ip"])
    assertEquals("ruvds", pingOk["node"])
    assertEquals(28.45, (pingOk["rtt_ms"] as Number).toDouble(), 1e-6)

    val pingFrag = DiagManager.parseDiagPingOutput(
      listOf("OK from=10.99.0.1 node=ruvds type=3 code=4 rtt_ms=12.10 ttl=64 mtu=1380 seq=2 size=1444")
    )
    assertEquals(false, pingFrag["ok"])
    assertEquals("frag_needed", pingFrag["status"])
    assertEquals(1380, pingFrag["mtu"])
  }

  @Test
  fun telemetryCollectorDetectsAnomaliesAndPersistsEvents() {
    val dir = tmp.newFolder("diag-events")
    val collector = DiagManager.TelemetryCollector(dir)

    val s1 = DiagManager.buildSnapshotFromLines(
      net = "mynet",
      nodeLines = listOf(selfLine, ruvdsUdpLine),
      subnetLines = listOf("10.99.0.1/32#10 owner ruvds"),
      connLines = listOf("ruvds at 198.51.100.10 port 443 options 700000c socket 6 status 5 transport quic"),
    )
    collector.recordSnapshot("mynet", s1, now = 1000.0)

    val s2 = DiagManager.buildSnapshotFromLines(
      net = "mynet",
      nodeLines = listOf(selfLine, ruvdsTcpFallbackLine),
      subnetLines = listOf("10.99.0.1/32#10 owner ruvds"),
      connLines = listOf("ruvds at 198.51.100.10 port 443 options 700000c socket 6 status 5 transport https"),
    )
    collector.recordSnapshot("mynet", s2, now = 1002.5)
    collector.recordUserMark("mynet", "video freeze")

    val incs = collector.getIncidents("mynet")
    val kinds = incs.map { it["kind"] }.toSet()
    assertTrue(kinds.contains("UDP_FALLBACK"))
    assertTrue(kinds.contains("TRANSPORT_CHANGED"))
    assertTrue(kinds.contains("PMTU_DROP"))
    assertTrue(kinds.contains("RTT_SPIKE"))
    assertTrue(kinds.contains("USER_MARK"))

    // Verify persistence across new collector instance
    val collector2 = DiagManager.TelemetryCollector(dir)
    val incs2 = collector2.getIncidents("mynet")
    assertEquals(incs.size, incs2.size)
  }

  @Test
  fun embeddedHttpServerServesWebUiAndApi() {
    val freePort = ServerSocket(0).use { it.localPort }
    try {
      val (ok, _) = DiagManager.startServer(freePort)
      assertTrue(ok)
      assertTrue(DiagManager.isEnabled())

      // 1. GET /
      val htmlConn = URL("http://127.0.0.1:$freePort/").openConnection(Proxy.NO_PROXY) as HttpURLConnection
      assertEquals(200, htmlConn.responseCode)
      val html = htmlConn.inputStream.bufferedReader().readText()
      assertTrue(html.contains("tincstack Diagnostic"))

      // 2. GET /api/overview
      val ovConn = URL("http://127.0.0.1:$freePort/api/overview?net=mynet").openConnection(Proxy.NO_PROXY) as HttpURLConnection
      assertEquals(200, ovConn.responseCode)
      val ovJson = DiagManager.JsonCodec.parse(ovConn.inputStream.bufferedReader().readText()) as Map<*, *>
      assertEquals(true, ovJson["ok"])
      assertEquals("android", ovJson["platform"])

      // 3. POST /api/mark
      val markConn = (URL("http://127.0.0.1:$freePort/api/mark").openConnection(Proxy.NO_PROXY) as HttpURLConnection).apply {
        requestMethod = "POST"
        doOutput = true
        setRequestProperty("Content-Type", "application/json")
      }
      val reqBytes = """{"net":"mynet","note":"test lag from junit"}""".toByteArray()
      markConn.outputStream.use { it.write(reqBytes) }
      assertEquals(200, markConn.responseCode)
      val markResp = DiagManager.JsonCodec.parse(markConn.inputStream.bufferedReader().readText()) as Map<*, *>
      assertEquals(true, markResp["ok"])
    } finally {
      DiagManager.stopServer(persist = false)
      assertFalse(DiagManager.isEnabled())
    }
  }
}
