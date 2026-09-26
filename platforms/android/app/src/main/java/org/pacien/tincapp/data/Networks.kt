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

import org.pacien.tincapp.context.AppPaths
import org.slf4j.LoggerFactory
import java.io.File

/**
 * The networks on this device: `networks/<name>/tinc.yaml`, one per joined
 * invitation. A directory without a non-empty `tinc.yaml` is not a network
 * (it holds no keys and cannot connect): earlier versions left one behind for
 * every failed join, and it showed up in the list as a network that could
 * never start.
 */
object Networks {
  private val log by lazy { LoggerFactory.getLogger(Networks::class.java)!! }

  private fun isNetwork(dir: File) = File(dir, TincYaml.FILE_NAME).let { it.isFile && it.length() > 0 }

  fun list(root: File = AppPaths.confDir()): List<String> =
    (root.listFiles() ?: emptyArray())
      .filter { it.isDirectory && isNetwork(it) }
      .map { it.name }
      .sortedBy { it.lowercase() }

  /** Remove directories under `networks/` that are not networks (see above). */
  fun sweepBroken(root: File = AppPaths.confDir()) {
    (root.listFiles() ?: emptyArray())
      .filter { !(it.isDirectory && isNetwork(it)) }
      .forEach {
        log.warn("Removing {}: no {} in it, not a network", it.absolutePath, TincYaml.FILE_NAME)
        it.deleteRecursively()
      }
  }

  fun remove(name: String) {
    val dir = AppPaths.confDir(name)
    log.info("Removing network {}", name)
    dir.deleteRecursively()
    AppPaths.logFile(name).delete()
  }

  /** What the main screen shows about a network, read from its tinc.yaml. */
  data class Summary(val stanza: String, val nodeName: String?, val address: String?, val peers: List<String>)

  fun summary(name: String): Summary {
    val yaml = TincYaml(AppPaths.tincYamlFile(name))
    val stanza = yaml.resolveNetwork(name)
    val cfg = try {
      VpnInterfaceConfiguration.fromTincYaml(yaml, stanza)
    } catch (e: Exception) {
      null
    }
    return Summary(
      stanza,
      yaml.optionValue(stanza, "Name"),
      cfg?.addresses?.firstOrNull()?.address,
      yaml.optionValues(stanza, "ConnectTo").map(String::trim).filter(String::isNotEmpty))
  }
}
