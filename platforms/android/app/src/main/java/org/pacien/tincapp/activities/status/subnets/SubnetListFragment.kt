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

package org.pacien.tincapp.activities.status.subnets

import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModelProviders
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import org.pacien.tincapp.activities.BaseFragment
import org.pacien.tincapp.databinding.StatusSubnetListFragmentBinding
import org.pacien.tincapp.extensions.hideBottomSeparator
import org.pacien.tincapp.extensions.hideTopSeparator
import org.pacien.tincapp.extensions.setElements

/**
 * @author euxane
 */
class SubnetListFragment : BaseFragment() {
  private val subnetListViewModel by lazy { ViewModelProviders.of(this)[SubnetListViewModel::class.java] }
  private val subnetListAdapter by lazy { SubnetInfoArrayAdapter(requireContext()) }
  private val subnetListObserver by lazy { Observer<List<SubnetInfo>> { subnetListAdapter.setElements(it) } }
  private lateinit var statusSubnetListFragmentBinding: StatusSubnetListFragmentBinding

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    subnetListViewModel.nodeList.observe(this, subnetListObserver)
  }

  override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
    statusSubnetListFragmentBinding = StatusSubnetListFragmentBinding.inflate(inflater, container, false)
    return statusSubnetListFragmentBinding.root
  }

  override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
    statusSubnetListFragmentBinding.statusSubnetList.hideTopSeparator()
    statusSubnetListFragmentBinding.statusSubnetList.hideBottomSeparator()
    statusSubnetListFragmentBinding.statusSubnetList.onItemClickListener = null
    statusSubnetListFragmentBinding.statusSubnetList.adapter = subnetListAdapter
  }
}
