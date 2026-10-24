/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2018 Euxane P. TRAN-GIRARD
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

package org.pacien.tincapp.extensions

import android.net.VpnService
import org.pacien.tincapp.data.AnnouncedRoutes
import org.pacien.tincapp.data.CidrAddress
import org.pacien.tincapp.data.VpnInterfaceConfiguration
import org.pacien.tincapp.extensions.Java.applyIgnoringException
import java.net.InetAddress

/**
 * @author euxane
 */
object VpnServiceBuilder {
  const val DEFAULT_TUN_MTU = 1280
  private val IPV4_LITERAL = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

  /**
   * A numeric address, never a host name: the builder must not trigger a DNS
   * lookup. (The `InetAddress` overloads are used rather than the `String`
   * ones so that the same code runs under a plain JVM in unit tests.)
   */
  private fun numericAddress(s: String): InetAddress {
    if (!(IPV4_LITERAL.matches(s) || (s.contains(':') && s.all { it.isLetterOrDigit() || it == ':' || it == '.' })))
      throw IllegalArgumentException("Not a numeric address: $s")
    return InetAddress.getByName(s)
  }

  private fun <T> exceptWithCidr(cidr: CidrAddress, func: () -> T) = try {
    func()
  } catch (e: IllegalArgumentException) {
    throw IllegalArgumentException("${e.message}: $cidr")
  }

  private fun VpnService.Builder.addAddress(cidr: CidrAddress): VpnService.Builder =
    exceptWithCidr(cidr) { addAddress(numericAddress(cidr.address), cidr.prefix) }

  private fun VpnService.Builder.addRoute(cidr: CidrAddress): VpnService.Builder =
    exceptWithCidr(cidr) { addRoute(numericAddress(cidr.address), cidr.prefix) }

  private fun VpnService.Builder.allowBypass(allow: Boolean): VpnService.Builder =
    if (allow) allowBypass() else this

  private fun VpnService.Builder.overrideMtu(mtu: Int?): VpnService.Builder =
    setMtu(mtu ?: DEFAULT_TUN_MTU)

  private fun VpnService.Builder.addAddresses(cidrList: List<CidrAddress>): VpnService.Builder =
    cidrList.fold(this) { net, cidr -> net.addAddress(cidr) }

  private fun VpnService.Builder.addRoutes(cidrList: List<CidrAddress>): VpnService.Builder =
    cidrList.fold(this) { net, cidr -> net.addRoute(cidr) }

  private fun VpnService.Builder.addDnsServers(dnsList: List<String>): VpnService.Builder =
    dnsList.fold(this) { net, dns -> net.addDnsServer(numericAddress(dns)) }

  private fun VpnService.Builder.addSearchDomains(domainList: List<String>): VpnService.Builder =
    domainList.fold(this) { net, domain -> net.addSearchDomain(domain) }

  private fun VpnService.Builder.allowFamilies(familyList: List<Int>): VpnService.Builder =
    familyList.fold(this) { net, family -> net.allowFamily(family) }

  private fun VpnService.Builder.addAllowedApplications(apps: List<String>): VpnService.Builder =
    apps.fold(this) { net, app -> applyIgnoringException(net::addAllowedApplication, app, net)!! }

  private fun VpnService.Builder.addDisallowedApplications(apps: List<String>): VpnService.Builder =
    apps.fold(this) { net, app -> applyIgnoringException(net::addDisallowedApplication, app, net)!! }

  /**
   * [VpnInterfaceConfiguration] guarantees at most one of the two app lists is
   * non-empty (Android throws on mixing them, and [applyIgnoringException]
   * would otherwise hide that as a silently dropped list).
   *
   * When full-tunnel IPv4 routing is active without an explicit IPv6 address or
   * route, a ULA IPv6 sinkhole address and `2000::/3` route are added so Android
   * does not leak `AAAA` queries/connections (e.g. YouTube/GoogleVideo) over the
   * uncensored/censored ISP IPv6 underlay; `tincd` immediately replies with
   * `ICMP6_DST_UNREACH_NOROUTE`, triggering `<1 ms` Happy Eyeballs IPv4 fallback.
   */
  fun VpnService.Builder.applyCfg(cfg: VpnInterfaceConfiguration): VpnService.Builder {
    val sinkholeV6 = AnnouncedRoutes.isFullTunnelV4(cfg.routes) &&
      cfg.addresses.none { it.address.contains(':') } &&
      cfg.routes.none { it.address.contains(':') } &&
      cfg.allowedFamilies.isEmpty()
    val effectiveAddresses = if (sinkholeV6) cfg.addresses + AnnouncedRoutes.IPV6_SINKHOLE_ADDRESS else cfg.addresses
    val effectiveRoutes = if (sinkholeV6) cfg.routes + AnnouncedRoutes.IPV6_SINKHOLE_ROUTE else cfg.routes
    return this
      .addAddresses(effectiveAddresses)
      .addRoutes(effectiveRoutes)
      .addDnsServers(cfg.dnsServers)
      .addSearchDomains(cfg.searchDomains)
      .addAllowedApplications(cfg.allowedApplications)
      .addDisallowedApplications(cfg.disallowedApplications)
      .allowFamilies(cfg.allowedFamilies)
      .allowBypass(cfg.allowBypass)
      .setBlocking(cfg.blocking)
      .overrideMtu(cfg.mtu)
  }
}
