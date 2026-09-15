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
 * `Ifconfig` and `Route` are the keys tinc itself uses in invitations for the
 * interface address and the routes, so a joined node needs no translation.
 * When they are absent the address and route are derived from the node's own
 * `Subnet` host record and the network's `AddressPool`, so a zero-config or
 * freshly joined node gets a working interface without any Android-specific key.
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
    const val KEY_ADDRESSES = "Ifconfig"
    const val KEY_ROUTES = "Route"
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
        .filter { it.lowercase() !in listOf("dhcp", "dhcp6", "slaac") }
        .map { CidrAddress.fromSlashSeparated(it) }
        .ifEmpty { ownAddressesFromSubnet(yaml, net, pool) }

      val routes = yaml.optionValues(net, KEY_ROUTES)
        .map { it.trim().substringBefore(' ') }
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
        .filter { it.isNotEmpty() && !it.contains(':') } // IPv4 only; IPv6 subnets need an explicit Ifconfig
        .mapNotNull { applyIgnoringException(CidrAddress.Companion::fromSlashSeparated, it) }
        .map { if (pool != null && it.prefix == 32) CidrAddress(it.address, pool.prefix) else it }

    /**
     * The `invitation-data` file `tinc join` leaves behind: tinc's own
     * `Key = value` lines (first chunk only; `#---` separates the peers' host
     * records that follow). Only `Ifconfig` / `Route` are of interest here.
     */
    fun fromInvitation(f: File): VpnInterfaceConfiguration {
      val lines = f.readLines()
        .takeWhile { !it.startsWith("#---") }
        .map { it.trim() }
        .filter { !it.startsWith("#") && it.contains('=') }
        .map { it.substringBefore('=').trim() to it.substringAfter('=').trim() }
      fun values(key: String) = lines.filter { it.first.equals(key, ignoreCase = true) }.map { it.second }
      return VpnInterfaceConfiguration(
        values(KEY_ADDRESSES)
          .mapNotNull { applyIgnoringException(CidrAddress.Companion::fromSlashSeparated, it) },
        values(KEY_ROUTES)
          .map { it.substringBefore(' ') }
          .map { CidrAddress.fromSlashSeparated(it) })
    }
  }

  /** Persist the address/route part (what an invitation carries) into the YAML options. */
  fun writeAddressing(yaml: TincYaml, net: String) {
    val changes = mutableMapOf<String, List<String>?>()
    if (addresses.isNotEmpty()) changes[KEY_ADDRESSES] = addresses.map(CidrAddress::toSlashSeparated)
    if (routes.isNotEmpty()) changes[KEY_ROUTES] = routes.map(CidrAddress::toSlashSeparated)
    yaml.setOptions(net, changes)
  }
}
