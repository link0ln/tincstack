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

package org.pacien.tincapp.activities.common

import org.pacien.tincapp.commands.Tinc
import org.pacien.tincapp.data.Networks
import org.pacien.tincapp.data.PeerStatus
import org.pacien.tincapp.service.TincVpnService
import java.util.concurrent.TimeUnit

/**
 * Polled sources for the screens. Each posts only when the value changed: a
 * view re-bound every second never goes idle, which starves accessibility
 * services (and uiautomator: "could not get idle state") and costs battery.
 */
abstract class ChangeOnlyLiveData<T>(interval: Long, unit: TimeUnit) : SelfRefreshingLiveData<T>(interval, unit) {
  @Volatile private var last: Any? = UNSET

  protected fun offer(value: T) {
    if (value != last) {
      last = value
      postValue(value)
    }
  }

  private object UNSET
}

/** The networks on the device. */
class NetworkListLiveData : ChangeOnlyLiveData<List<String>>(2, TimeUnit.SECONDS) {
  override fun onRefresh() = offer(Networks.list())
}

/**
 * The nodes of [netName]'s running daemon, or null while the daemon of that
 * network is not running.
 */
class PeersLiveData(private val netName: String) : ChangeOnlyLiveData<List<PeerStatus>?>(2, TimeUnit.SECONDS) {
  override fun onRefresh() {
    if (!TincVpnService.isDaemonRunning() || TincVpnService.getCurrentNetName() != netName) return offer(null)
    try {
      val nodes = Tinc.dumpNodes(netName).get(5, TimeUnit.SECONDS)
      val connections = try {
        Tinc.dumpConnections(netName).get(5, TimeUnit.SECONDS)
      } catch (e: Exception) {
        emptyList()
      }
      offer(PeerStatus.parse(nodes, connections))
    } catch (e: Exception) {
      // the control socket is not up yet, or the daemon just went away
    }
  }
}
