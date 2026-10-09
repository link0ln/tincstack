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

import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.view.isVisible
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import org.pacien.tincapp.R
import org.pacien.tincapp.activities.BaseActivity
import org.pacien.tincapp.activities.common.Labels
import org.pacien.tincapp.activities.common.PeersLiveData
import org.pacien.tincapp.commands.Tinc
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.data.PeerStatus
import org.pacien.tincapp.data.TincYaml
import org.pacien.tincapp.databinding.ActivityPeersBinding
import org.pacien.tincapp.databinding.PeerItemBinding
import org.pacien.tincapp.extensions.Java.defaultMessage
import org.pacien.tincapp.extensions.Java.exceptionallyAccept
import java.util.Locale

/** The nodes of the running network: who is reachable, how, and how fast. */
class PeersActivity : BaseActivity() {
  private lateinit var binding: ActivityPeersBinding
  override val snackbarRoot: View get() = binding.peersRoot
  private val netName by lazy { intent.getStringExtra(EXTRA_NET_NAME)!! }
  private val adapter = Adapter { showInfo(it) }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    binding = ActivityPeersBinding.inflate(layoutInflater)
    setContentView(binding.root)
    setupToolbar(binding.toolbar, up = true)
    supportActionBar?.subtitle = netName
    binding.peersList.layoutManager = LinearLayoutManager(this)
    binding.peersList.adapter = adapter
    binding.peersPlaceholder.setText(R.string.peers_loading)
    binding.peersPlaceholder.isVisible = true
    PeersLiveData(netName).observe(this) { render(it) }
  }

  private fun render(peers: List<PeerStatus>?) {
    adapter.submit(peers.orEmpty())
    binding.peersPlaceholder.isVisible = peers.isNullOrEmpty()
    if (peers == null) binding.peersPlaceholder.setText(R.string.peers_not_connected)
  }

  private fun showInfo(peer: PeerStatus) {
    if (peer.self) {
      Tinc.info(netName, peer.name)
        .thenAccept { text -> runOnUiThread { infoDialog(peer.name, text) } }
        .exceptionallyAccept { e -> runOnUiThread { notify(e.cause?.defaultMessage() ?: e.defaultMessage()) } }
      return
    }
    val options = arrayOf(
      getString(R.string.peer_info_action),
      getString(R.string.peer_edit_action),
    )
    MaterialAlertDialogBuilder(this)
      .setTitle(peer.name)
      .setItems(options) { _, which ->
        when (which) {
          0 -> Tinc.info(netName, peer.name)
            .thenAccept { text -> runOnUiThread { infoDialog(peer.name, text) } }
            .exceptionallyAccept { e -> runOnUiThread { notify(e.cause?.defaultMessage() ?: e.defaultMessage()) } }

          else -> PeerEditDialog(this, TincYaml(AppPaths.tincYamlFile(netName)), TincYaml(AppPaths.tincYamlFile(netName)).resolveNetwork(netName), peer.name) {
            notify(getString(R.string.peer_edit_saved))
            notifyAppliesReconnect()
          }.show()
        }
      }
      .setNegativeButton(R.string.action_cancel, null)
      .show()
  }

  private fun notifyAppliesReconnect() {
    // the daemon re-reads host records on its own reload cycle; a reconnect
    // picks the new ports up immediately
  }

  private fun infoDialog(title: String, text: String) {
    if (isFinishing) return
    val view = layoutInflater.inflate(R.layout.dialog_text, null)
    view.findViewById<TextView>(R.id.dialog_text).text = text
    MaterialAlertDialogBuilder(this)
      .setTitle(title)
      .setView(view)
      .setPositiveButton(R.string.action_close, null)
      .show()
  }

  private class Holder(val binding: PeerItemBinding) : RecyclerView.ViewHolder(binding.root)

  private class Adapter(private val onClick: (PeerStatus) -> Unit) : RecyclerView.Adapter<Holder>() {
    private var items: List<PeerStatus> = emptyList()

    fun submit(list: List<PeerStatus>) {
      if (list == items) return
      items = list
      @Suppress("NotifyDataSetChanged") notifyDataSetChanged()
    }

    override fun getItemCount() = items.size

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
      Holder(PeerItemBinding.inflate(LayoutInflater.from(parent.context), parent, false))

    override fun onBindViewHolder(holder: Holder, position: Int) {
      val peer = items[position]
      val b = holder.binding
      val context = b.root.context
      b.peerName.text = peer.name
      b.peerAvatar.text = peer.name.take(1).uppercase(Locale.ROOT)
      val (bg, fg) = when {
        peer.self -> com.google.android.material.R.attr.colorPrimaryContainer to
          com.google.android.material.R.attr.colorOnPrimaryContainer

        peer.reachable -> 0 to 0
        else -> com.google.android.material.R.attr.colorSurfaceContainerHighest to
          com.google.android.material.R.attr.colorOnSurfaceVariant
      }
      if (bg == 0) {
        b.peerAvatar.backgroundTintList = ColorStateList.valueOf(context.getColor(R.color.state_on_container))
        b.peerAvatar.setTextColor(context.getColor(R.color.state_on_on_container))
      } else {
        b.peerAvatar.backgroundTintList = ColorStateList.valueOf(MaterialColors.getColor(b.root, bg))
        b.peerAvatar.setTextColor(MaterialColors.getColor(b.root, fg))
      }
      b.peerStatus.text = status(context, peer)
      b.peerAddress.text = if (peer.address != null) context.getString(R.string.peer_address_format, peer.address, peer.port) else ""
      b.peerAddress.isVisible = peer.address != null
      b.peerRow.setOnClickListener { onClick(peer) }
    }

    private fun status(context: Context, peer: PeerStatus): String = when {
      peer.self -> context.getString(R.string.peer_this_device)
      !peer.reachable -> context.getString(R.string.peer_unreachable)
      else -> listOfNotNull(
        if (peer.via != null) context.getString(R.string.peer_via_format, peer.via) else context.getString(R.string.peer_direct),
        Labels.transportName(context, peer.transport),
        peer.rttMs?.let { context.getString(R.string.peer_rtt_format, String.format(Locale.ROOT, "%.1f", it)) },
      ).joinToString("  ·  ")
    }
  }

  companion object {
    private const val EXTRA_NET_NAME = "netName"

    fun intent(context: Context, netName: String): Intent =
      Intent(context, PeersActivity::class.java).putExtra(EXTRA_NET_NAME, netName)
  }
}
