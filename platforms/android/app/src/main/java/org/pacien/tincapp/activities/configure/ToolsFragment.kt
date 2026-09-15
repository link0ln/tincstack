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

package org.pacien.tincapp.activities.configure

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AlertDialog
import org.pacien.tincapp.R
import org.pacien.tincapp.activities.BaseFragment
import org.pacien.tincapp.activities.apps.AppPickerActivity
import org.pacien.tincapp.activities.configure.tools.ConfigurationToolDialogFragment
import org.pacien.tincapp.activities.configure.tools.GenerateConfigToolDialogFragment
import org.pacien.tincapp.activities.configure.tools.JoinNetworkToolDialogFragment
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.databinding.ConfigureToolsFragmentBinding

/**
 * @author euxane
 */
class ToolsFragment : BaseFragment() {
  private val generateConfigTool by lazy { GenerateConfigToolDialogFragment() }
  private val joinNetworkTool by lazy { JoinNetworkToolDialogFragment() }

  override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
    val binding = ConfigureToolsFragmentBinding.inflate(inflater, container, false)
    binding.generateConfigAction = openDialog(generateConfigTool)
    binding.joinNetworkAction = openDialog(joinNetworkTool)
    binding.pickAppsAction = this::pickNetworkForApps
    return binding.root
  }

  private fun openDialog(tool: ConfigurationToolDialogFragment): () -> Unit =
    { if (!tool.isAdded) tool.show(parentFragmentManager, tool.javaClass.simpleName) }

  /** The app picker is per network: ask which one, then open it. */
  private fun pickNetworkForApps() {
    val networks = AppPaths.confDir().list()?.sorted() ?: emptyList()
    if (networks.isEmpty()) {
      parentActivity.notify(R.string.start_network_list_empty_none_found)
      return
    }

    if (networks.size == 1) {
      startActivity(AppPickerActivity.intent(requireContext(), networks[0]))
      return
    }

    AlertDialog.Builder(parentActivity)
      .setTitle(R.string.apps_picker_choose_network_title)
      .setItems(networks.toTypedArray()) { _, i -> startActivity(AppPickerActivity.intent(requireContext(), networks[i])) }
      .setNegativeButton(R.string.generic_action_cancel) { _, _ -> }
      .show()
  }
}
