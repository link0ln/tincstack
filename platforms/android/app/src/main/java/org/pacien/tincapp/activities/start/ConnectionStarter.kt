/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2019 Euxane P. TRAN-GIRARD
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

package org.pacien.tincapp.activities.start

import android.net.VpnService
import org.pacien.tincapp.service.TincVpnService

/**
 * @author euxane
 */
class ConnectionStarter(private val parentActivity: StartActivity) {
  private var netName: String? = null
  private var displayStatus = false

  fun displayStatus() = displayStatus

  fun tryStart(netName: String? = null, displayStatus: Boolean? = null) {
    if (netName != null) this.netName = netName
    if (displayStatus != null) this.displayStatus = displayStatus

    val permissionRequestIntent = VpnService.prepare(parentActivity)
    if (permissionRequestIntent != null)
      return parentActivity.startActivityForResult(permissionRequestIntent, parentActivity.permissionRequestCode)

    startVpn(this.netName!!)
  }

  private fun startVpn(netName: String) {
    parentActivity.showConnectProgressDialog()
    TincVpnService.connect(netName)
  }
}
