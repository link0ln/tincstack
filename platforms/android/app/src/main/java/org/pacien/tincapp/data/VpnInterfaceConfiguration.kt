/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2020 Euxane P. TRAN-GIRARD
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

import org.pacien.tincapp.extensions.Java.applyIgnoringException
import java.io.File

/**
 * What the app needs to build the Android VPN interface for a network. Every
 * field comes from the network's `tinc.yaml` `options:` (docs/config-schema.md,
 * "Android interface options"); the daemon ignores the keys it does not use.
 *
 * `InterfaceAddress` and `InterfaceRoute` are the daemon's own interface keys:
 * `tinc join` writes them from the invitation's `Ifconfig` / `Route` lines
 * (core/tincd/src/invitation.c, `finalize_join_yaml`) and the Linux built-in
 * tinc-up (core/tincd/src/autoif.c) consumes them, so a joined node needs no
 * translation and no side-file. A route is "prefix [gateway]" as in the
 * invitation; only the prefix is used on Android (the tunnel has no next hop).
 * When they are absent the address and route are derived from the node's own
 * `Subnet` host record and the network's `AddressPool`, exactly like autoif.c,
 * so a zero-config node gets a working interface without any extra key.
 *
 * @author euxane
 */
data class VpnInterfaceConfiguration(val addresses: List<CidrAddress> = emptyList(),
                                     val routes: List<CidrAddress> = emptyList(),
                                     val dnsServers: List<String> = emptyList(),
                                     val searchDomains: List<String> = emptyList(),
                                     val allowedApplications: List<String> = emptyList(),
                                     val disallowedApplications: List<String> = emptyList(),
                                     val allowedFamilies: List<Int> = emptyList(),
                                     val allowBypass: Boolean = false,
                                     val blocking: Boolean = false,
                                     val mtu: Int? = null,
                                     val reconnectOnNetworkChange: Boolean = true) {
  companion object {
    const val KEY_ADDRESSES = "InterfaceAddress"
    const val KEY_ROUTES = "InterfaceRoute"
    const val KEY_DNS_SERVERS = "DNSServer"
    const val KEY_SEARCH_DOMAINS = "SearchDomain"
    const val KEY_ALLOWED_APPLICATIONS = SplitRouting.KEY_ALLOWED_APPLICATIONS
    const val KEY_DISALLOWED_APPLICATIONS = SplitRouting.KEY_DISALLOWED_APPLICATIONS
    const val KEY_ALLOWED_FAMILIES = "AllowFamily"
    const val KEY_ALLOW_BYPASS = "AllowBypass"
    const val KEY_BLOCKING = "Blocking"
    const val KEY_MTU = "MTU"
    const val KEY_RECONNECT_ON_NETWORK_CHANGE = "ReconnectOnNetworkChange"

    private const val KEY_ADDRESS_POOL = "AddressPool"
    private const val HOST_KEY_SUBNET = "Subnet"

    /** The keys this class reads; everything else in `options:` belongs to the daemon. */
    val KEYS = listOf(KEY_ADDRESSES, KEY_ROUTES, KEY_DNS_SERVERS, KEY_SEARCH_DOMAINS,
      KEY_ALLOWED_APPLICATIONS, KEY_DISALLOWED_APPLICATIONS, KEY_ALLOWED_FAMILIES,
      KEY_ALLOW_BYPASS, KEY_BLOCKING, KEY_MTU, KEY_RECONNECT_ON_NETWORK_CHANGE)

    /** From the network's `tinc.yaml`; [netName] is the network directory name (stanza resolved as the daemon does). */
    fun fromTincYaml(f: File, netName: String): VpnInterfaceConfiguration =
      TincYaml(f).let { yaml -> fromTincYaml(yaml, yaml.resolveNetwork(netName)) }

    fun fromTincYaml(yaml: TincYaml, net: String): VpnInterfaceConfiguration {
      val allowed = yaml.optionValues(net, KEY_ALLOWED_APPLICATIONS).map(String::trim).filter(String::isNotEmpty)
      val disallowed = yaml.optionValues(net, KEY_DISALLOWED_APPLICATIONS).map(String::trim).filter(String::isNotEmpty)
      if (allowed.isNotEmpty() && disallowed.isNotEmpty())
        throw TincYaml.InvalidConfigurationException(
          "$KEY_ALLOWED_APPLICATIONS and $KEY_DISALLOWED_APPLICATIONS are mutually exclusive (Android forbids mixing them); keep one list")

      val pool = yaml.optionValue(net, KEY_ADDRESS_POOL)?.let { applyIgnoringException(CidrAddress.Companion::fromSlashSeparated, it) }

      val addresses = yaml.optionValues(net, KEY_ADDRESSES)
        .map(String::trim)
        .filter { it.isNotEmpty() && it.lowercase() !in listOf("dhcp", "dhcp6", "slaac") }
        .map { CidrAddress.fromSlashSeparated(it) }
        .ifEmpty { ownAddressesFromSubnet(yaml, net, pool) }

      val routes = yaml.optionValues(net, KEY_ROUTES)
        .map { it.trim().substringBefore(' ') } // "prefix [gateway]": the gateway is meaningless on a tun fd
        .filter(String::isNotEmpty)
        .map { CidrAddress.fromSlashSeparated(it) }
        .ifEmpty { listOfNotNull(pool) }

      return VpnInterfaceConfiguration(
        addresses,
        routes,
        yaml.optionValues(net, KEY_DNS_SERVERS),
        yaml.optionValues(net, KEY_SEARCH_DOMAINS),
        allowed,
        disallowed,
        yaml.optionValues(net, KEY_ALLOWED_FAMILIES).map { it.trim().toInt() },
        TincYaml.asTincBoolean(yaml.optionValue(net, KEY_ALLOW_BYPASS), false),
        TincYaml.asTincBoolean(yaml.optionValue(net, KEY_BLOCKING), false),
        yaml.optionValue(net, KEY_MTU)?.trim()?.toInt(),
        TincYaml.asTincBoolean(yaml.optionValue(net, KEY_RECONNECT_ON_NETWORK_CHANGE), true))
    }

    /** Own `Subnet` host lines (`10.1.0.2/32`) become interface addresses with the pool's prefix length. */
    private fun ownAddressesFromSubnet(yaml: TincYaml, net: String, pool: CidrAddress?): List<CidrAddress> =
      yaml.ownHostValues(net, HOST_KEY_SUBNET)
        .map { it.substringBefore('#').trim() }
        .filter { it.isNotEmpty() && !it.contains(':') } // IPv4 only; IPv6 subnets need an explicit InterfaceAddress
        .mapNotNull { applyIgnoringException(CidrAddress.Companion::fromSlashSeparated, it) }
        .map { if (pool != null && it.prefix == 32) CidrAddress(it.address, pool.prefix) else it }
  }
}
