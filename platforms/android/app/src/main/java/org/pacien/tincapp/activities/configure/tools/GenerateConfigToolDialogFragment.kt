/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2024 Euxane P. TRAN-GIRARD
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
import org.pacien.tincapp.databinding.ConfigureToolsDialogNetworkGenerateBinding
import org.pacien.tincapp.R
import org.pacien.tincapp.commands.Tinc
import org.pacien.tincapp.commands.TincApp
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.utils.makePublic

/**
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
        dialog.newNodeName.text.toString(),
        dialog.newPassphrase.text.toString()
      )
    }

  private fun generateConf(netName: String, nodeName: String, passphrase: String? = null) = execAction(
    R.string.configure_tools_generate_config_generating,
    validateNetName(netName)
      .thenCompose { Tinc.init(netName, nodeName) }
      .thenCompose { TincApp.removeScripts(netName) }
      .thenCompose { TincApp.generateIfaceCfgTemplate(netName) }
      .thenCompose { TincApp.setPassphrase(netName, newPassphrase = passphrase) }
      .thenApply { AppPaths.confDir(netName).makePublic() })
}
