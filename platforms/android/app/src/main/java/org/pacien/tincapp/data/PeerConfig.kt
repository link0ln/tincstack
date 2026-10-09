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
 * The editable slice of a peer's host record (`networks.<net>.hosts.<name>`):
 * the keys an operator may want to change from the phone -- how to reach the
 * peer. Keys, Subnet and fingerprints are shown read-only; they are the
 * identity, not the dial plan.
 *
 * Parsing is line-based like [TincYaml.ownHostValues]: the record is a flat
 * `Key = value` text (the daemon's classic host-file format embedded in the
 * YAML as a literal block), so an edit is a per-key rewrite that preserves
 * everything else byte for byte (comments, key blocks, RSA PEM).
 */
data class PeerConfig(
  val name: String,
  val text: String,
) {
  /** `Key = value` pairs, in file order, without comments/blank/PEM lines. */
  val vars: List<Pair<String, String>> by lazy {
    text.lineSequence()
      .map { it.trim() }
      .filter { !it.startsWith("#") && it.contains('=') }
      .map { it.substringBefore('=').trim() to it.substringAfter('=').trim() }
      .toList()
  }

  private fun first(key: String): String? =
    vars.firstOrNull { it.first.equals(key, ignoreCase = true) }?.second

  /** Dial address: IP or DNS name, or null when the peer is dial-only. */
  val address: String? get() = first("Address")?.substringBefore(' ')?.takeIf { it.isNotBlank() }

  /** Optional port inside `Address = host port`. */
  val addressPort: String? get() =
    first("Address")?.takeIf { it.contains(' ') }?.substringAfter(' ')?.takeIf { it.isNotBlank() }

  /** Meta port (`Port`), or null when absent (the daemon defaults to 655). */
  val port: String? get() = first("Port")

  /** https/quic front ports, or null when absent. */
  val httpsPort: String? get() = first("HttpsPort")
  val quicPort: String? get() = first("QuicPort")

  val ed25519PublicKey: String? get() = first("Ed25519PublicKey")
  val subnet: List<String> get() = vars.filter { it.first.equals("Subnet", ignoreCase = true) }.map { it.second }

  class Validation private constructor() {
    companion object {
      private val HOSTNAME = Regex("""^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$""")
      private val IPV4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
      private val IPV6 = Regex("""^[0-9a-fA-F:]+$""")

      /** Null when OK, a user-presentable problem otherwise. */
      fun address(v: String?): String? = when {
        v.isNullOrBlank() -> null // addressless peers are legal (dial-only)
        v.contains(':') && !v.contains("::") && v.count { it == ':' } < 2 -> "not a valid address"
        v == "localhost" || v == "*" -> null
        IPV4.matches(v) -> v.split('.').firstOrNull { it.toInt() > 255 }?.let { "octet $it > 255" }
        IPV6.matches(v) -> null
        HOSTNAME.matches(v) -> null
        else -> "not an IP or a hostname"
      }

      /** Null when OK; a port is 1..65535 decimal. */
      fun port(v: String?): String? = when {
        v.isNullOrBlank() -> null
        v.toIntOrNull()?.let { it in 1..65535 } == true -> null
        else -> "port is 1-65535"
      }
    }
  }
}
