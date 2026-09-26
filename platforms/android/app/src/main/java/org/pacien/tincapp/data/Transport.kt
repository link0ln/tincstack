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
 * The carrier this node dials its peers with (docs/transports.md §2):
 * `PreferredTransports` in the network's options. The phone only ever dials
 * (a joined node has `Port: 0`), so this is the one transport knob that
 * matters on it. Absent = the core's default, `plain`.
 *
 * Which carriers make sense is decided by the node the phone dials: its host
 * record carries the accept list (`Transports = plain, sf, obfs, https, quic`),
 * copied into our `tinc.yaml` by the invitation.
 */
enum class Transport(val id: String) {
  PLAIN("plain"),
  SF("sf"),
  OBFS("obfs"),
  HTTPS("https"),
  QUIC("quic");

  companion object {
    const val KEY_PREFERRED = "PreferredTransports"
    private const val HOST_KEY_TRANSPORTS = "Transports"
    private const val OPTION_CONNECT_TO = "ConnectTo"

    fun byId(id: String?): Transport? = values().firstOrNull { it.id.equals(id?.trim(), ignoreCase = true) }

    /** The chosen carrier; null = automatic (the core's default). */
    fun preferred(yaml: TincYaml, net: String): Transport? =
      yaml.optionValues(net, KEY_PREFERRED).firstNotNullOfOrNull { v -> v.split(',', ' ').firstNotNullOfOrNull(::byId) }

    /** Write the choice (null removes the key: automatic). */
    fun setPreferred(yaml: TincYaml, net: String, transport: Transport?) =
      yaml.setOptions(net, mapOf(KEY_PREFERRED to transport?.let { listOf(it.id) }))

    /**
     * What the node(s) we dial accept, from their host records. Unknown (no
     * record, no line) = only `plain` is known to work.
     */
    fun acceptedByPeers(yaml: TincYaml, net: String): Set<Transport> {
      val peers = yaml.optionValues(net, OPTION_CONNECT_TO).map(String::trim).filter(String::isNotEmpty)
      val accepted = peers.flatMap { peer ->
        yaml.hostText(net, peer).orEmpty().lineSequence()
          .map(String::trim)
          .filter { it.substringBefore('=').trim().equals(HOST_KEY_TRANSPORTS, ignoreCase = true) && it.contains('=') }
          .flatMap { it.substringAfter('=').split(',', ' ').asSequence() }
          .mapNotNull(::byId)
          .toList()
      }.toSet()
      return accepted + PLAIN
    }
  }
}
