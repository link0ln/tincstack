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

import android.Manifest
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
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
    requestNotificationPermission()
    parentActivity.showConnectProgressDialog()
    TincVpnService.connect(netName)
  }

  /**
   * The session's foreground notification (with its Disconnect action) needs
   * POST_NOTIFICATIONS from Android 13 on. Asked once the VPN consent is
   * settled, never waited for: without it the service still runs in the
   * foreground, only the notification is hidden.
   */
  private fun requestNotificationPermission() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
    if (parentActivity.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
    parentActivity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_PERMISSION_REQUEST)
  }

  companion object {
    private const val NOTIFICATION_PERMISSION_REQUEST = 1
  }
}
