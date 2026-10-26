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
import android.widget.PopupMenu
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
import org.pacien.tincapp.activities.config.ConfigEditorActivity
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.data.PeerConfig
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
  // Row tap goes straight to that node's editor tab; the trailing ⋮ opens the
  // anchored dropdown (edit / transport / live info) -- not a centered dialog,
  // which read as "another tiny window", the owner's words, 2026-10-20.
  private val adapter = Adapter(
    onRowClick = { openConfigEditor(it.name) },
    onMenuClick = { peer, anchor -> showPeerMenu(peer, anchor) },
  )
  private val configEditLauncher = registerForActivityResult(
    androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) { renderStatic() }

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
    renderStatic()
  }

  /** The config-side list: every node the tinc.yaml holds, own node first.
      Rendered whenever the live list is empty (offline, or the daemon has
      not answered yet) and after a return from the editor. */
  private fun renderStatic() {
    val yaml = TincYaml(AppPaths.tincYamlFile(netName))
    val stanza = yaml.resolveNetwork(netName)
    val own = yaml.optionValue(stanza, "Name")
    val names = hostNames(yaml, stanza)
    val live = adapter.current.associateBy { it.name }
    val rows = names.map { n ->
      val livePeer = live[n]
      PeerStatus(
        name = n,
        self = n == own,
        address = livePeer?.address ?: run {
          val cfg = yaml.hostText(stanza, n)?.let { PeerConfig(n, it) }
          cfg?.address
        },
        port = staticPort(yaml, stanza, n, livePeer),
        reachable = livePeer?.reachable == true,
        directUdp = livePeer?.directUdp == true,
        via = livePeer?.via,
        rttMs = livePeer?.rttMs,
        transport = livePeer?.transport,
      )
    }
    adapter.submit(rows)
  }

  private fun staticPort(yaml: TincYaml, stanza: String, node: String, live: PeerStatus?): String? {
    live?.port?.let { return it }
    val cfg = PeerConfig(node, yaml.hostText(stanza, node) ?: return null)
    return cfg.port ?: cfg.addressPort
      ?: cfg.quicPort?.takeIf { it != "0" }
      ?: cfg.httpsPort?.takeIf { it != "0" }
      ?: cfg.obfsPort?.takeIf { it != "0" }
  }

  private fun staticAddressSummary(yaml: TincYaml, stanza: String, node: String, live: PeerStatus?): String? {
    val hostText = yaml.hostText(stanza, node)
    val cfg = hostText?.let { PeerConfig(node, it) }
    val addr = live?.address ?: cfg?.address
    val port = live?.port
      ?: cfg?.port
      ?: cfg?.addressPort
      ?: cfg?.quicPort?.takeIf { it != "0" }
      ?: cfg?.httpsPort?.takeIf { it != "0" }
      ?: cfg?.obfsPort?.takeIf { it != "0" }

    val base = when {
      addr != null && port != null -> getString(R.string.peer_address_format, addr, port)
      addr != null -> addr
      cfg?.subnet?.isNotEmpty() == true -> cfg.subnet.joinToString(", ")
      else -> null
    }

    val extras = mutableListOf<String>()
    cfg?.preferredTransport?.takeIf { it.isNotBlank() && !it.equals("auto", ignoreCase = true) }?.let {
      extras.add("pref: ${it.uppercase(Locale.ROOT)}")
    }
    cfg?.httpsPort?.takeIf { it != "0" }?.let { extras.add("https:$it") }
    cfg?.quicPort?.takeIf { it != "0" }?.let { extras.add("quic:$it") }
    cfg?.obfsPort?.takeIf { it != "0" }?.let { extras.add("obfs:$it") }

    return listOfNotNull(base, extras.takeIf { it.isNotEmpty() }?.joinToString(" · "))
      .takeIf { it.isNotEmpty() }
      ?.joinToString("  ·  ")
  }

  private fun hostNames(yaml: TincYaml, stanza: String): List<String> =
    yaml.hostNames(stanza)

  private fun render(peers: List<PeerStatus>?) {
    if (peers.isNullOrEmpty()) renderStatic() else adapter.submit(peers)
    binding.peersPlaceholder.isVisible = peers == null && adapter.itemCount == 0
    if (peers == null && adapter.itemCount == 0) binding.peersPlaceholder.setText(R.string.peers_not_connected)
  }

  /** The anchored dropdown on a peer's ⋮ button; the own node has no per-peer
      actions, so its button is just a shortcut to the editor. */
  private fun showPeerMenu(peer: PeerStatus, anchor: View) {
    if (peer.self) {
      openConfigEditor(peer.name)
      return
    }
    PopupMenu(this, anchor).apply {
      menu.add(0, MENU_EDIT, 0, R.string.peer_edit_action)
      menu.add(0, MENU_TRANSPORT, 1, R.string.peer_transport_action)
      menu.add(0, MENU_INFO, 2, R.string.peer_info_action)
      setOnMenuItemClickListener { item ->
        when (item.itemId) {
          MENU_EDIT -> openConfigEditor(peer.name)
          MENU_TRANSPORT -> showPeerTransportDialog(peer.name)
          else -> fetchLivePeerInfo(peer.name)
        }
        true
      }
    }.show()
  }

  private fun fetchLivePeerInfo(peerName: String) {
    Tinc.info(netName, peerName)
      .thenAccept { text -> runOnUiThread { infoDialog(peerName, text) } }
      .exceptionallyAccept { e -> runOnUiThread { notify(e.cause?.defaultMessage() ?: e.defaultMessage()) } }
  }

  private fun showPeerTransportDialog(peerName: String) {
    val yaml = TincYaml(AppPaths.tincYamlFile(netName))
    val stanza = yaml.resolveNetwork(netName)
    val currentPref = yaml.hostText(stanza, peerName)
      ?.let { PeerConfig(peerName, it).preferredTransport?.lowercase(Locale.ROOT) }
      ?.takeIf { it.isNotBlank() }
      ?: "auto"

    val codes = arrayOf("auto", "quic", "https", "obfs", "sf", "sftcp", "plain")
    val labels = arrayOf(
      getString(R.string.peer_transport_auto),
      getString(R.string.transport_quic),
      getString(R.string.transport_https),
      getString(R.string.transport_obfs),
      getString(R.string.transport_sf),
      getString(R.string.transport_sftcp),
      getString(R.string.transport_plain),
    )
    val checked = codes.indexOf(currentPref).coerceAtLeast(0)

    MaterialAlertDialogBuilder(this)
      .setTitle("$peerName — ${getString(R.string.setting_transport_title)}")
      .setSingleChoiceItems(labels, checked) { dialog, which ->
        val chosen = codes[which]
        try {
          val valToSet = if (chosen == "auto") null else listOf(chosen)
          yaml.setHostMultiVars(stanza, peerName, mapOf("PreferredTransport" to valToSet), createIfMissing = true)
          if (org.pacien.tincapp.service.TincVpnService.isDaemonRunning()) {
            org.pacien.tincapp.service.TincVpnService.connect(netName)
          }
          renderStatic()
          notify(getString(R.string.config_saved))
        } catch (e: Exception) {
          notify(e.cause?.defaultMessage() ?: e.defaultMessage())
        }
        dialog.dismiss()
      }
      .setNegativeButton(R.string.action_cancel, null)
      .show()
  }

  private fun openConfigEditor(nodeName: String?) {
    val intent = if (nodeName != null) ConfigEditorActivity.intent(this, netName, nodeName)
    else ConfigEditorActivity.intent(this, netName)
    configEditLauncher.launch(intent)
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

  private inner class Adapter(
    private val onRowClick: (PeerStatus) -> Unit,
    private val onMenuClick: (PeerStatus, View) -> Unit,
  ) : RecyclerView.Adapter<Holder>() {
    private var items: List<PeerStatus> = emptyList()

    val current: List<PeerStatus> get() = items

    fun submit(list: List<PeerStatus>) {
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
      val yaml = TincYaml(AppPaths.tincYamlFile(netName))
      val stanza = yaml.resolveNetwork(netName)
      val addrText = staticAddressSummary(yaml, stanza, peer.name, peer)
      b.peerAddress.text = addrText.orEmpty()
      b.peerAddress.isVisible = !addrText.isNullOrBlank()
      b.peerRow.setOnClickListener { onRowClick(peer) }
      val menu = b.peerMenu
      menu.setOnClickListener { onMenuClick(peer, menu) }
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
    private const val MENU_EDIT = 1
    private const val MENU_TRANSPORT = 2
    private const val MENU_INFO = 3

    fun intent(context: Context, netName: String): Intent =
      Intent(context, PeersActivity::class.java).putExtra(EXTRA_NET_NAME, netName)
  }
}
