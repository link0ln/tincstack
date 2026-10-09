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

package org.pacien.tincapp.activities.peers

import android.view.View
import androidx.appcompat.app.AlertDialog
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import org.pacien.tincapp.R
import org.pacien.tincapp.data.PeerConfig
import org.pacien.tincapp.data.TincYaml
import org.pacien.tincapp.databinding.DialogPeerEditBinding

/**
 * Edit a peer's host record from the Peers screen. UX:
 *
 *  - opens as a bottom-ish Material dialog straight from a peer's context menu;
 *  - the dial plan is five flat fields with inline validation (red box + a
 *    line of text per bad field, no toast scavenger hunt);
 *  - empty = remove the key from the record (the note says so);
 *  - Save is disabled until something changed and nothing is invalid;
 *  - the identity (keys, subnets) sits below, read-only and selectable, so
 *    the operator can compare fingerprints without leaving the dialog.
 */
class PeerEditDialog(
  private val activity: android.content.Context,
  private val yaml: TincYaml,
  private val net: String,
  private val peerName: String,
  private val onSaved: () -> Unit,
) {
  fun show() {
    val text = yaml.hostText(net, peerName)
    if (text == null) {
      MaterialAlertDialogBuilder(activity)
        .setTitle(R.string.peers_title)
        .setMessage(activity.getString(org.pacien.tincapp.R.string.peer_edit_identity) + ": $peerName")
        .setPositiveButton(R.string.action_close, null)
        .show()
      return
    }
    val cfg = PeerConfig(peerName, text)

    val binding = DialogPeerEditBinding.inflate(android.view.LayoutInflater.from(activity))
    binding.peerAddress.setText(listOfNotNull(cfg.address, cfg.addressPort).joinToString(" "))
    binding.peerPort.setText(cfg.port.orEmpty())
    binding.peerHttpsPort.setText(cfg.httpsPort.orEmpty())
    binding.peerQuicPort.setText(cfg.quicPort.orEmpty())
    binding.peerIdentity.text = listOf(
      cfg.ed25519PublicKey?.let { "ed25519  ${it.take(16)}…" },
      cfg.subnet.joinToString("\n") { "subnet  $it" },
    ).filterNotNull().joinToString("\n").ifEmpty { peerName }

    val dialog: AlertDialog = MaterialAlertDialogBuilder(activity)
      .setTitle(activity.getString(R.string.peer_edit_title, peerName))
      .setView(binding.root)
      .setPositiveButton(R.string.action_save, null)
      .setNegativeButton(R.string.action_cancel, null)
      .create()

    dialog.setOnShowListener {
      val save = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
      fun validate(): Boolean {
        var ok = true
        val aErr = PeerConfig.Validation.address(binding.peerAddress.text?.toString()?.trim())
        val pErr = PeerConfig.Validation.port(binding.peerPort.text?.toString()?.trim())
        val hErr = PeerConfig.Validation.port(binding.peerHttpsPort.text?.toString()?.trim())
        val qErr = PeerConfig.Validation.port(binding.peerQuicPort.text?.toString()?.trim())
        binding.peerAddressLayout.error = aErr
        binding.peerPortLayout.error = pErr
        binding.peerHttpsPortLayout.error = hErr
        binding.peerQuicPortLayout.error = qErr
        if (aErr != null || pErr != null || hErr != null || qErr != null) ok = false
        save.isEnabled = ok && changed(binding, cfg)
        return ok
      }
      listOf(binding.peerAddress, binding.peerPort, binding.peerHttpsPort, binding.peerQuicPort)
        .forEach { it.addTextChangedListener(SimpleWatcher { _ -> validate() }) }
      validate()

      save.setOnClickListener {
        if (!validate()) return@setOnClickListener
        val changes = buildChanges(binding, cfg)
        try {
          yaml.setHostVars(net, peerName, changes)
        } catch (e: Exception) {
          binding.peerEditNote.text = e.message ?: e.javaClass.simpleName
          return@setOnClickListener
        }
        dialog.dismiss()
        onSaved()
      }
    }
    dialog.show()
  }

  private fun changed(b: DialogPeerEditBinding, cfg: PeerConfig): Boolean {
    val addr = b.peerAddress.text?.toString()?.trim().orEmpty()
    val old = listOfNotNull(cfg.address, cfg.addressPort).joinToString(" ")
    return addr != old ||
      b.peerPort.text?.toString()?.trim().orEmpty() != cfg.port.orEmpty() ||
      b.peerHttpsPort.text?.toString()?.trim().orEmpty() != cfg.httpsPort.orEmpty() ||
      b.peerQuicPort.text?.toString()?.trim().orEmpty() != cfg.quicPort.orEmpty()
  }

  private fun buildChanges(b: DialogPeerEditBinding, cfg: PeerConfig): Map<String, String?> {
    val changes = mutableMapOf<String, String?>()
    val addr = b.peerAddress.text?.toString()?.trim().orEmpty()
    val port = b.peerPort.text?.toString()?.trim().orEmpty()
    changes["Address"] = when {
      addr.isBlank() -> null
      port.isBlank() -> addr
      else -> "$addr $port"
    }
    changes["Port"] = port.ifBlank { null }
    changes["HttpsPort"] = b.peerHttpsPort.text?.toString()?.trim()?.ifBlank { null }
    changes["QuicPort"] = b.peerQuicPort.text?.toString()?.trim()?.ifBlank { null }
    return changes
  }

  private class SimpleWatcher(private val onChange: (android.text.Editable?) -> Unit) : android.text.TextWatcher {
    override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
    override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
    override fun afterTextChanged(s: android.text.Editable?) = onChange(s)
  }
}

