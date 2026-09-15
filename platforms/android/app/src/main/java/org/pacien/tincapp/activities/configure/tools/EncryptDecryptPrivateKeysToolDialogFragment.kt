/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2018 Euxane P. TRAN-GIRARD
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
import org.pacien.tincapp.databinding.ConfigureToolsDialogEncryptDecryptKeysBinding
import org.pacien.tincapp.R
import org.pacien.tincapp.commands.TincApp

/**
 * @author euxane
 */
class EncryptDecryptPrivateKeysToolDialogFragment : ConfigurationToolDialogFragment() {
  override fun onCreateDialog(savedInstanceState: Bundle?) =
    makeDialog(
      ConfigureToolsDialogEncryptDecryptKeysBinding.inflate(dialogLayoutInflater),
      R.string.configure_tools_private_keys_encryption_title,
      R.string.configure_tools_private_keys_encryption_action
    ) { dialog ->
      encryptDecryptPrivateKeys(
        dialog.encDecNetName.text.toString(),
        dialog.encDecCurrentPassphrase.text.toString(),
        dialog.encDecNewPassphrase.text.toString()
      )
    }

  private fun encryptDecryptPrivateKeys(netName: String, currentPassphrase: String, newPassphrase: String) =
    execAction(
      R.string.configure_tools_private_keys_encryption_encrypting,
      validateNetName(netName)
        .thenCompose { TincApp.setPassphrase(netName, currentPassphrase, newPassphrase) }
    )
}
