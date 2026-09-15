/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2019 Euxane P. TRAN-GIRARD
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

package org.pacien.tincapp.activities.status.nodes

import android.os.Bundle
import androidx.appcompat.app.AlertDialog
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.lifecycle.ViewModelProvider
import org.pacien.tincapp.R
import org.pacien.tincapp.activities.BaseFragment
import org.pacien.tincapp.commands.Tinc
import org.pacien.tincapp.databinding.StatusNodeInfoDialogBinding
import org.pacien.tincapp.databinding.StatusNodeListFragmentBinding
import org.pacien.tincapp.extensions.hideBottomSeparator
import org.pacien.tincapp.extensions.hideTopSeparator
import org.pacien.tincapp.extensions.setElements
import org.pacien.tincapp.extensions.updatePlaceholderVisibility
import org.pacien.tincapp.service.TincVpnService

/**
 * @author euxane
 */
class NodeListFragment : BaseFragment() {
  private val vpnService = TincVpnService
  private val tincCtl = Tinc
  private val netName by lazy { vpnService.getCurrentNetName()!! }
  private val nodeListViewModel by lazy { ViewModelProvider(this)[NodeListViewModel::class.java] }
  private val nodeListAdapter by lazy { NodeInfoArrayAdapter(requireContext(), this::onItemClick) }
  private lateinit var statusNodeListFragmentBinding: StatusNodeListFragmentBinding

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    nodeListViewModel.nodeList.observe(this) { updateNodeList(it) }
  }

  override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
    statusNodeListFragmentBinding = StatusNodeListFragmentBinding.inflate(inflater, container, false)
    return statusNodeListFragmentBinding.root
  }

  override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
    statusNodeListFragmentBinding.statusNodeList.adapter = nodeListAdapter
    statusNodeListFragmentBinding.statusNodeList.hideTopSeparator()
    statusNodeListFragmentBinding.statusNodeList.hideBottomSeparator()
  }

  private fun updateNodeList(nodes: List<NodeInfo>) {
    statusNodeListFragmentBinding.statusNodeList.updatePlaceholderVisibility(
      statusNodeListFragmentBinding.statusNodeListPlaceholder,
      nodes.isEmpty()
    )
    nodeListAdapter.setElements(nodes)
  }

  private fun onItemClick(nodeInfo: NodeInfo) =
    showNodeInfo(nodeInfo.name)

  private fun showNodeInfo(nodeName: String) {
    val dialogTextViewBinding = StatusNodeInfoDialogBinding.inflate(layoutInflater)

    AlertDialog.Builder(requireContext())
      .setTitle(R.string.status_node_info_dialog_title)
      .setView(dialogTextViewBinding.root)
      .setPositiveButton(R.string.status_node_info_dialog_close_action) { _, _ -> }
      .show()

    tincCtl.info(netName, nodeName).thenAccept { nodeInfo ->
      view?.post { dialogTextViewBinding.dialogNodeDetails.text = nodeInfo }
    }
  }
}
