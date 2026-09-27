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

/**
 * One node of the running mesh, as `tinc dump nodes` and `tinc dump
 * connections` print it (core/tincd/src/tincctl.c). Pure parsing, unit-tested.
 *
 *     node_a id 0123 at 10.0.0.1 port 655 cipher 0 digest 0 maclength 0 compression 0
 *       options 700000c status 0892 nexthop node_a via node_a distance 1 pmtu 1451
 *       (min 1451 max 1451) rx 1 2 tx 3 4 transports plain,sf,obfs rtt 0.667
 *     node_a at 10.0.0.1 port 655 options 700000c socket 5 status 5 transport https
 */
data class PeerStatus(
  val name: String,
  val self: Boolean,
  val address: String?,
  val port: String?,
  val reachable: Boolean,
  /** Packets flow straight to it over UDP (not relayed, not TCP-only). */
  val directUdp: Boolean,
  /** The node traffic to it is relayed through, when not direct. */
  val via: String?,
  val rttMs: Double?,
  /** The carrier of our meta connection to it, when we have one. */
  val transport: String?,
) {
  companion object {
    private const val STATUS_REACHABLE = 0x10
    private const val STATUS_UDP_CONFIRMED = 0x80

    private fun fields(line: String): List<String> = line.trim().split(Regex("\\s+"))

    private fun List<String>.after(key: String): String? =
      indexOf(key).takeIf { it >= 0 && it + 1 < size }?.let { this[it + 1] }

    /** `tinc dump connections`: peer name to carrier, the CLI's own control connection left out. */
    fun parseConnections(lines: List<String>): Map<String, String> =
      lines.map(::fields)
        .filter { it.size >= 2 && !it[0].startsWith("<") }
        .associate { it[0] to (it.after("transport") ?: "plain") }

    fun parseNode(line: String, connections: Map<String, String> = emptyMap()): PeerStatus? {
      val f = fields(line)
      if (f.size < 2 || f.after("status") == null) return null
      val name = f[0]
      val host = f.after("at")
      val self = host == "MYSELF"
      val status = f.after("status")?.toLongOrNull(16)?.toInt() ?: 0
      val nexthop = f.after("nexthop")?.takeIf { it != "-" }
      val via = f.after("via")?.takeIf { it != "-" }
      val reachable = self || status and STATUS_REACHABLE != 0
      val relay = listOfNotNull(via, nexthop).firstOrNull { it != name }
      return PeerStatus(
        name = name,
        self = self,
        address = host?.takeIf { !self && it != "unknown" },
        port = f.after("port")?.takeIf { !self && it != "unknown" },
        reachable = reachable,
        directUdp = !self && reachable && status and STATUS_UDP_CONFIRMED != 0 && relay == null,
        via = if (reachable && !self) relay else null,
        rttMs = f.after("rtt")?.toDoubleOrNull(),
        transport = connections[name],
      )
    }

    /** Every node, this device first, then reachable before unreachable, then by name. */
    fun parse(nodeLines: List<String>, connectionLines: List<String>): List<PeerStatus> {
      val connections = parseConnections(connectionLines)
      return nodeLines.mapNotNull { parseNode(it, connections) }
        .sortedWith(compareBy({ !it.self }, { !it.reachable }, { it.name.lowercase() }))
    }
  }
}
