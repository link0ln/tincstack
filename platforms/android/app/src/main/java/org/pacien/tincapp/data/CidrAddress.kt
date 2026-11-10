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

package org.pacien.tincapp.data

/**
 * @author euxane
 */
data class CidrAddress(val address: String, val prefix: Int) {
  companion object {
    private const val SEPARATOR = "/"

    fun fromSlashSeparated(s: String): CidrAddress = try {
      val trimmed = s.trim()
      if (!trimmed.contains(SEPARATOR)) throw IllegalArgumentException("missing prefix separator")
      val addr = trimmed.substringBefore(SEPARATOR).trim()
      val prefix = Integer.parseInt(trimmed.substringAfter(SEPARATOR).trim())
      val maxPrefix = if (addr.contains(':')) 128 else 32
      if (addr.isEmpty() || prefix < 0 || prefix > maxPrefix) {
        throw IllegalArgumentException("invalid address/prefix")
      }
      CidrAddress(addr, prefix)
    } catch (e: Exception) {
      throw TincYaml.InvalidConfigurationException("not an address/prefix: '$s'")
    }

    fun fromSlashSeparatedOrHost(
      s: String,
      defaultIpv4Prefix: Int = 32,
      defaultIpv6Prefix: Int = 128,
    ): CidrAddress {
      val trimmed = s.trim()
      if (trimmed.contains(SEPARATOR)) return fromSlashSeparated(trimmed)
      if (trimmed.isEmpty()) {
        throw TincYaml.InvalidConfigurationException("not an address/prefix: '$s'")
      }
      val prefix = if (trimmed.contains(':')) defaultIpv6Prefix else defaultIpv4Prefix
      val maxPrefix = if (trimmed.contains(':')) 128 else 32
      if (prefix < 0 || prefix > maxPrefix) {
        throw TincYaml.InvalidConfigurationException("not an address/prefix: '$s'")
      }
      return CidrAddress(trimmed, prefix)
    }
  }

  fun toSlashSeparated() = address + SEPARATOR + prefix
  override fun toString(): String = "$address/$prefix"
}
