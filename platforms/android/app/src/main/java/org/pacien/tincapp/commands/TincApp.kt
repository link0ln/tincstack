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

package org.pacien.tincapp.commands

import org.pacien.tincapp.commands.Executor.runAsyncTask
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.data.TincYaml
import org.pacien.tincapp.data.VpnInterfaceConfiguration
import java.io.File
import java.util.regex.Pattern

/**
 * Configuration housekeeping done by the app itself (not by the tinc CLI).
 *
 * @author euxane
 */
object TincApp {
  private val SCRIPT_SUFFIXES = listOf("-up", "-down", "-created", "-accepted")
  private val STATIC_SCRIPTS = listOf("tinc", "host", "subnet", "invitation").flatMap { s -> SCRIPT_SUFFIXES.map { s + it } }
  private val NODE_NAME_PATTERN: Pattern = Pattern.compile("^[A-Za-z0-9_]+$")

  private fun stanza(netName: String) = TincYaml(AppPaths.tincYamlFile(netName)).resolveNetwork(netName)

  private fun listScripts(netName: String): List<File> {
    val dirs = listOf(AppPaths.confDir(netName), AppPaths.daemonSideDir(netName, stanza(netName)))
    return dirs.flatMap { dir ->
      (dir.listFiles { f -> f.name in STATIC_SCRIPTS } ?: emptyArray()).toList() +
        (File(dir, "hosts").listFiles { f -> SCRIPT_SUFFIXES.any { f.name.endsWith(it) } } ?: emptyArray()).toList()
    }
  }

  /** Scripts cannot run on Android (no ifconfig/ip); drop whatever `tinc join` generated. */
  fun removeScripts(netName: String) = runAsyncTask {
    listScripts(netName).forEach { it.delete() }
  }

  /**
   * A new network is a `tinc.yaml` with just a `Name`; the daemon materialises
   * keys, port, address pool and own subnet into it at first start
   * (docs/config-schema.md, "Zero-config materialisation").
   */
  fun createNetwork(netName: String, nodeName: String) = runAsyncTask {
    if (!NODE_NAME_PATTERN.matcher(nodeName).matches())
      throw IllegalArgumentException("Node name must be made of letters, digits and underscores.")
    TincYaml(AppPaths.tincYamlFile(netName)).createNetwork(netName, nodeName)
  }

  /**
   * After `tinc join`: the interface address and routes an invitation carries
   * (`Ifconfig` / `Route`) go into the YAML options if the CLI left them in an
   * `invitation-data` side-file instead of the YAML itself.
   */
  fun importInvitationAddressing(netName: String) = runAsyncTask {
    val yaml = TincYaml(AppPaths.tincYamlFile(netName))
    val stanza = yaml.resolveNetwork(netName)
    val invitation = AppPaths.invitationFile(netName, stanza)
    if (!invitation.exists()) return@runAsyncTask
    if (!yaml.file.exists()) return@runAsyncTask // nothing to fold into: the core still writes a classic tree here
    VpnInterfaceConfiguration.fromInvitation(invitation).writeAddressing(yaml, stanza)
  }
}
