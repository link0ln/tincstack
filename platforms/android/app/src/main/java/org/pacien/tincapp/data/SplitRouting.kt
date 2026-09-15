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

/**
 * Per-app split routing of a network, as stored in its `tinc.yaml` options:
 *
 *  - [SplitRoutingMode.WHITELIST]: `AllowApplication` — only the listed apps use the tunnel;
 *  - [SplitRoutingMode.BLACKLIST]: `DisallowApplication` — every app but the listed ones does.
 *
 * Android forbids mixing `addAllowedApplication` and `addDisallowedApplication`
 * on one VpnService.Builder, so exactly one of the two keys is ever written;
 * saving one mode removes the other key. An empty selection means "all apps"
 * (no key at all) whatever the mode.
 */
enum class SplitRoutingMode { WHITELIST, BLACKLIST }

data class SplitRouting(val mode: SplitRoutingMode, val apps: Set<String>) {
  companion object {
    const val KEY_ALLOWED_APPLICATIONS = "AllowApplication"
    const val KEY_DISALLOWED_APPLICATIONS = "DisallowApplication"

    /** Reads the mode from whichever key is set; both set is refused (see [VpnInterfaceConfiguration]). */
    fun read(yaml: TincYaml, net: String): SplitRouting {
      val allowed = yaml.optionValues(net, KEY_ALLOWED_APPLICATIONS).map(String::trim).filter(String::isNotEmpty)
      val disallowed = yaml.optionValues(net, KEY_DISALLOWED_APPLICATIONS).map(String::trim).filter(String::isNotEmpty)
      if (allowed.isNotEmpty() && disallowed.isNotEmpty())
        throw TincYaml.InvalidConfigurationException("$KEY_ALLOWED_APPLICATIONS and $KEY_DISALLOWED_APPLICATIONS are mutually exclusive")
      return when {
        allowed.isNotEmpty() -> SplitRouting(SplitRoutingMode.WHITELIST, allowed.toSet())
        else -> SplitRouting(SplitRoutingMode.BLACKLIST, disallowed.toSet())
      }
    }
  }

  /** Writes exactly one list key (the other is removed), sorted for stable diffs. */
  fun write(yaml: TincYaml, net: String) {
    val list = apps.map(String::trim).filter(String::isNotEmpty).sorted()
    val (set, unset) = when (mode) {
      SplitRoutingMode.WHITELIST -> KEY_ALLOWED_APPLICATIONS to KEY_DISALLOWED_APPLICATIONS
      SplitRoutingMode.BLACKLIST -> KEY_DISALLOWED_APPLICATIONS to KEY_ALLOWED_APPLICATIONS
    }
    yaml.setOptions(net, mapOf(set to list, unset to null))
  }
}
