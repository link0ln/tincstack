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

import java.net.InetAddress

/**
 * The subnets the other nodes announce, as routes into the tunnel. Every one
 * is taken, no toggle: a node that announces `192.168.1.0/24` is the way to
 * that LAN, a node that announces `0.0.0.0/0` is the network's exit and then
 * carries all of this device's traffic. Pure, unit-tested; [TincVpnService]
 * feeds it `tinc dump subnets` / `tinc dump reachable nodes` and rebuilds the
 * interface when the result changes.
 *
 * Left out: this node's own subnets, broadcast/multicast and MAC subnets,
 * subnets of nodes that are not reachable (so an exit that goes away takes
 * its default route with it and traffic goes out directly again, as on
 * Windows), IPv6 unless the interface has an IPv6 address, and whatever the
 * configured routes (`InterfaceRoute`, else `AddressPool`) or a wider
 * announced subnet already cover.
 */
object AnnouncedRoutes {
  /**
   * The resolvers used when the tunnel carries the IPv4 default route and the
   * network names none (`DNSServer`). Without them Android keeps asking the
   * underlying network's resolver, outside the tunnel, and a filtered answer
   * sends the connection to the wrong place however it is routed. Both are
   * reached through the exit like everything else.
   */
  val FULL_TUNNEL_DNS = listOf("1.1.1.1", "8.8.8.8")

  data class Announcement(val subnet: CidrAddress, val owner: String)

  private val IPV4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
  private val HEX_GROUP = Regex("""^[0-9a-fA-F]{1,4}$""")

  private fun isV6(c: CidrAddress) = c.address.contains(':')

  /**
   * Address bytes of a numeric literal, null for anything else. Parsed here
   * rather than by InetAddress.getByName, which on Android resolves whatever
   * it cannot parse (a MAC subnet, "300.1.1.1") through DNS.
   */
  private fun bytes(address: String): ByteArray? =
    if (address.contains(':')) v6Bytes(address) else v4Bytes(address)

  private fun v4Bytes(s: String): ByteArray? {
    if (!IPV4.matches(s)) return null
    val octets = s.split('.').map(String::toInt)
    if (octets.any { it > 255 }) return null
    return ByteArray(4) { octets[it].toByte() }
  }

  private fun v6Bytes(s: String): ByteArray? {
    val halves = s.split("::")
    if (halves.size > 2) return null
    fun groups(part: String): List<Int>? {
      if (part.isEmpty()) return emptyList()
      val g = part.split(':')
      if (g.any { !HEX_GROUP.matches(it) }) return null
      return g.map { it.toInt(16) }
    }
    val head = groups(halves[0]) ?: return null
    val tail = if (halves.size == 2) groups(halves[1]) ?: return null else emptyList()
    val missing = 8 - head.size - tail.size
    if ((halves.size == 1 && missing != 0) || (halves.size == 2 && missing < 1)) return null
    val all = head + List(missing) { 0 } + tail
    return ByteArray(16) { i -> (all[i / 2] shr (if (i % 2 == 0) 8 else 0)).toByte() }
  }

  /** [c] with its host bits cleared (VpnService.Builder.addRoute refuses anything else), null if it is not an IP subnet. */
  fun normalise(c: CidrAddress): CidrAddress? {
    val b = bytes(c.address) ?: return null
    if (c.prefix < 0 || c.prefix > b.size * 8) return null
    for (i in b.indices) {
      val keep = (c.prefix - i * 8).coerceIn(0, 8)
      b[i] = (b[i].toInt() and (0xff shl (8 - keep)) and 0xff).toByte()
    }
    return CidrAddress(InetAddress.getByAddress(b).hostAddress!!, c.prefix)
  }

  /** [outer] contains all of [inner] (same family). */
  fun covers(outer: CidrAddress, inner: CidrAddress): Boolean {
    if (isV6(outer) != isV6(inner) || outer.prefix > inner.prefix) return false
    val o = normalise(outer) ?: return false
    val i = normalise(CidrAddress(inner.address, outer.prefix)) ?: return false
    return o == i
  }

  /**
   * `tinc dump subnets` lines, "SUBNET owner NODE" (core/tincd/src/tincctl.c):
   * the "#weight" suffix is dropped, a subnet without a prefix is a host
   * route, and the "(broadcast)" entries and MAC subnets are skipped.
   */
  fun parse(lines: List<String>): List<Announcement> = lines.mapNotNull { line ->
    val f = line.trim().split(Regex("\\s+"))
    if (f.size < 3 || f[1] != "owner" || f[2].startsWith("(")) return@mapNotNull null
    val net = f[0].substringBefore('#')
    val address = net.substringBefore('/')
    val bytes = bytes(address) ?: return@mapNotNull null
    val prefix = if (net.contains('/')) net.substringAfter('/').toIntOrNull() ?: return@mapNotNull null else bytes.size * 8
    Announcement(CidrAddress(address, prefix), f[2])
  }

  /** The routes to add to [base]'s, in a stable order (IPv4 first, widest first). */
  fun select(announced: List<Announcement>, self: String, reachable: Set<String>, base: VpnInterfaceConfiguration): List<CidrAddress> {
    val v6 = base.addresses.any(::isV6)
    val candidates = announced.asSequence()
      .filter { it.owner != self && it.owner in reachable }
      .mapNotNull { normalise(it.subnet) }
      .filter { v6 || !isV6(it) }
      .filter { !isMulticastOrBroadcast(it) }
      .filter { c -> base.routes.none { covers(it, c) } }
      .distinct()
      .toList()
    return candidates
      .filter { c -> candidates.none { o -> o != c && covers(o, c) } }
      .sortedWith(compareBy<CidrAddress>({ isV6(it) }, { it.prefix }, { key(it) }))
  }

  private fun key(c: CidrAddress): String =
    bytes(c.address)?.joinToString("") { String.format("%02x", it.toInt() and 0xff) } ?: c.address

  private fun isMulticastOrBroadcast(c: CidrAddress): Boolean {
    val b = bytes(c.address) ?: return true
    if (b.size == 4) return (b[0].toInt() and 0xf0) == 0xe0 || (c.prefix == 32 && b.all { it == 0xff.toByte() })
    return b[0] == 0xff.toByte()
  }

  /** [base] plus the announced routes, and [FULL_TUNNEL_DNS] when they bring the default route and [base] names no resolver. */
  fun apply(base: VpnInterfaceConfiguration, announced: List<CidrAddress>): VpnInterfaceConfiguration {
    val routes = base.routes + announced.filter { a -> base.routes.none { it == a } }
    val fullTunnel = routes.any { it.prefix == 0 && !isV6(it) }
    return base.copy(
      routes = routes,
      dnsServers = if (fullTunnel && base.dnsServers.isEmpty()) FULL_TUNNEL_DNS else base.dnsServers)
  }

  /** For the per-network store: "a/p,a/p". */
  fun serialise(routes: List<CidrAddress>): String = routes.joinToString(",") { it.toSlashSeparated() }

  fun deserialise(s: String?): List<CidrAddress> =
    s.orEmpty().split(',').map(String::trim).filter(String::isNotEmpty)
      .mapNotNull { runCatching { CidrAddress.fromSlashSeparated(it) }.getOrNull() }
      .mapNotNull(::normalise)
}
