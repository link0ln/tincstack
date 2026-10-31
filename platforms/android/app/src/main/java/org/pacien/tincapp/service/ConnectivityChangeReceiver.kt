/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2020 Euxane P. TRAN-GIRARD
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

package org.pacien.tincapp.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import org.pacien.tincapp.commands.Tinc
import org.slf4j.LoggerFactory
import java.lang.IllegalArgumentException
import java.net.Inet4Address

/**
 * Watches system connectivity and dual-network uplinks (Wi-Fi + Cellular) so
 * `tincd` can bind sockets to each physical Android `Network` (`net_handle`)
 * and perform zero-drop make-before-break handover when switching networks.
 *
 * @author euxane
 */
object ConnectivityChangeReceiver : BroadcastReceiver() {
  private val log by lazy { LoggerFactory.getLogger(this.javaClass)!! }
  private val tincCtl = Tinc
  private val tincVpnService = TincVpnService
  @Volatile private var wifiCallback: ConnectivityManager.NetworkCallback? = null
  @Volatile private var cellCallback: ConnectivityManager.NetworkCallback? = null

  override fun onReceive(context: Context, intent: Intent) {
    log.info("Connectivity change intent received: {}", intent.toString())
    if (isNetworkAvailable(intent)) attemptReconnect()
  }

  private fun attemptReconnect() {
    // no daemon while a session is suspended (screen locked): nothing to poke
    if (!tincVpnService.isDaemonRunning()) return
    tincVpnService.getCurrentNetName()?.let { netName ->
      log.info("Sending immediate reconnection request to the tinc daemon.")
      tincCtl.retry(netName)
    }
  }

  private fun isNetworkAvailable(intent: Intent) =
    !intent.getBooleanExtra(ConnectivityManager.EXTRA_NO_CONNECTIVITY, false)

  private fun extractSourceIp(cm: ConnectivityManager, network: Network, lp: LinkProperties? = null): String {
    return try {
      val props = lp ?: cm.getLinkProperties(network) ?: return "-"
      val v4 = props.linkAddresses.map { it.address }.firstOrNull { it is Inet4Address && !it.isLoopbackAddress }
      val addr = v4 ?: props.linkAddresses.map { it.address }.firstOrNull { !it.isLoopbackAddress && !it.isLinkLocalAddress }
      addr?.hostAddress?.substringBefore('%') ?: "-"
    } catch (_: Exception) {
      "-"
    }
  }

  private fun pushUplink(name: String, ip: String, weight: Int, backup: Boolean, netHandle: Long, up: Boolean) {
    if (!tincVpnService.isDaemonRunning()) return
    val netName = tincVpnService.getCurrentNetName() ?: return
    if (up) {
      tincCtl.multipathUplinkAdd(
        netName = netName,
        name = name,
        ip = ip,
        weight = weight,
        backup = backup,
        mark = 0,
        netHandle = netHandle,
        up = true,
      )
    } else {
      tincCtl.multipathUplinkDel(netName, name)
    }
  }

  private fun makeCallback(
    cm: ConnectivityManager,
    uplinkName: String,
    weight: Int,
    backup: Boolean,
  ): ConnectivityManager.NetworkCallback = object : ConnectivityManager.NetworkCallback() {
    override fun onAvailable(network: Network) {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        val ip = extractSourceIp(cm, network)
        log.info("Multipath uplink {} available (handle={}, ip={})", uplinkName, network.networkHandle, ip)
        pushUplink(uplinkName, ip, weight, backup, network.networkHandle, up = true)
      }
      attemptReconnect()
    }

    override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        val ip = extractSourceIp(cm, network, linkProperties)
        pushUplink(uplinkName, ip, weight, backup, network.networkHandle, up = true)
      }
    }

    override fun onLost(network: Network) {
      log.info("Multipath uplink {} lost", uplinkName)
      pushUplink(uplinkName, "-", weight, backup, 0L, up = false)
      attemptReconnect()
    }
  }

  fun registerWatcher(context: Context) {
    @Suppress("DEPRECATION")
    val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
    try {
      context.registerReceiver(this, filter)
    } catch (_: Exception) {
    }

    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
    unregisterCallbacks(cm)

    val wifiCb = makeCallback(cm, "wifi", weight = 100, backup = false)
    val wifiReq = NetworkRequest.Builder()
      .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
      .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
      .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
      .build()
    try {
      cm.registerNetworkCallback(wifiReq, wifiCb)
      wifiCallback = wifiCb
    } catch (e: Exception) {
      log.warn("Could not register Wi-Fi multipath callback: {}", e.message)
    }

    val cellCb = makeCallback(cm, "cellular", weight = 50, backup = true)
    val cellReq = NetworkRequest.Builder()
      .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
      .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
      .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
      .build()
    try {
      cm.requestNetwork(cellReq, cellCb)
      cellCallback = cellCb
    } catch (e: Exception) {
      try {
        cm.registerNetworkCallback(cellReq, cellCb)
        cellCallback = cellCb
      } catch (e2: Exception) {
        log.warn("Could not register Cellular multipath callback: {}", e2.message)
      }
    }
  }

  private fun unregisterCallbacks(cm: ConnectivityManager) {
    wifiCallback?.let {
      try {
        cm.unregisterNetworkCallback(it)
      } catch (_: Exception) {
      }
    }
    wifiCallback = null
    cellCallback?.let {
      try {
        cm.unregisterNetworkCallback(it)
      } catch (_: Exception) {
      }
    }
    cellCallback = null
  }

  fun unregisterWatcher(context: Context) {
    try {
      context.unregisterReceiver(this)
    } catch (e: IllegalArgumentException) {
      // already unregistered
    }
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    if (cm != null) unregisterCallbacks(cm)
  }
}
