/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2024 Euxane P. TRAN-GIRARD
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

package org.pacien.tincapp.activities.configure.tools

import android.os.Bundle
import org.pacien.tincapp.R
import org.pacien.tincapp.commands.TincApp
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.databinding.ConfigureToolsDialogNetworkGenerateBinding
import org.pacien.tincapp.utils.makePrivate

/**
 * A new network is a `tinc.yaml` holding just the node name; the daemon
 * materialises keys, port and address pool into it on first connect.
 *
 * @author euxane
 */
class GenerateConfigToolDialogFragment : ConfigurationToolDialogFragment() {
  override fun onCreateDialog(savedInstanceState: Bundle?) =
    makeDialog(
      ConfigureToolsDialogNetworkGenerateBinding.inflate(dialogLayoutInflater),
      R.string.configure_tools_generate_config_title,
      R.string.configure_tools_generate_config_action
    ) { dialog ->
      generateConf(
        dialog.newNetName.text.toString(),
        dialog.newNodeName.text.toString()
      )
    }

  private fun generateConf(netName: String, nodeName: String) = execAction(
    R.string.configure_tools_generate_config_generating,
    validateNetName(netName)
      .thenCompose { TincApp.createNetwork(netName, nodeName) }
      .thenApply { AppPaths.confDir(netName).makePrivate() })
}
