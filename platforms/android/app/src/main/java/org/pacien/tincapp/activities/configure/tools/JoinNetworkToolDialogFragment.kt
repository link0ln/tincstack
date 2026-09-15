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

import android.content.Intent
import android.os.Bundle
import com.google.zxing.integration.android.IntentIntegrator
import com.google.zxing.integration.android.IntentResult
import org.pacien.tincapp.R
import org.pacien.tincapp.commands.Tinc
import org.pacien.tincapp.commands.TincApp
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.databinding.ConfigureToolsDialogNetworkJoinBinding
import org.pacien.tincapp.utils.makePublic

/**
 * @author euxane
 */
class JoinNetworkToolDialogFragment : ConfigurationToolDialogFragment() {
  private val scanner by lazy { IntentIntegrator.forSupportFragment(this) }
  private var joinDialog: ConfigureToolsDialogNetworkJoinBinding? = null

  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
      ?.let(IntentResult::getContents)
      ?.let(String::trim)
      ?.let { joinDialog?.invitationUrl?.setText(it) }
  }

  override fun onCreateDialog(savedInstanceState: Bundle?) =
    makeJoinDialog().let { newDialog ->
      joinDialog = newDialog
      makeDialog(
        newDialog,
        R.string.configure_tools_join_network_title,
        R.string.configure_tools_join_network_action
      ) { dialog ->
        joinNetwork(
          dialog.netName.text.toString(),
          dialog.invitationUrl.text.toString(),
          dialog.joinPassphrase.text.toString()
        )
      }
    }

  private fun makeJoinDialog() =
    ConfigureToolsDialogNetworkJoinBinding.inflate(dialogLayoutInflater)
      .apply { scanAction = this@JoinNetworkToolDialogFragment::scanCode }

  private fun scanCode() {
    scanner.initiateScan()
  }

  private fun joinNetwork(netName: String, url: String, passphrase: String? = null) =
    execAction(
      R.string.configure_tools_join_network_joining,
      validateNetName(netName)
        .thenCompose { Tinc.join(netName, url) }
        .thenCompose { TincApp.removeScripts(netName) }
        .thenCompose { TincApp.generateIfaceCfg(netName) }
        .thenCompose { TincApp.setPassphrase(netName, newPassphrase = passphrase) }
        .thenApply { AppPaths.confDir(netName).makePublic() }
    )
}
