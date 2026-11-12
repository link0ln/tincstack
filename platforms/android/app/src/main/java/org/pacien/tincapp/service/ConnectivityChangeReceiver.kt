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
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.data.TincYaml
import org.slf4j.LoggerFactory
import java.lang.IllegalArgumentException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

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

  private data class UplinkState(
    val netHandle: Long,
    val ip: String,
    val weight: Int,
    val backup: Boolean,
    val pushedV6: Boolean,
  )

  private val uplinkStates = ConcurrentHashMap<String, UplinkState>()

  /**
   * Dedicated single-thread FIFO executor so `uplink add`, `uplink del`, and
   * `tinc retry` control commands execute strictly in arrival order.
   */
  private val uplinkExecutor = Executors.newSingleThreadExecutor { r ->
    Thread(r, "tinc-uplink").apply { isDaemon = true }
  }

  override fun onReceive(context: Context, intent: Intent) {
    log.info("Connectivity change intent received: {}", intent.toString())
    if (isNetworkAvailable(intent)) attemptReconnect()
  }

  private fun enqueueUplinkCommand(action: () -> Unit) {
    try {
      uplinkExecutor.execute {
        try {
          action()
        } catch (e: Throwable) {
          log.warn("Uplink control action failed: {}", e.message)
        }
      }
    } catch (_: Exception) {
    }
  }

  private fun attemptReconnect() {
    enqueueUplinkCommand {
      // no daemon while a session is suspended (screen locked): nothing to poke
      if (!tincVpnService.isDaemonRunning()) return@enqueueUplinkCommand
      tincVpnService.getCurrentNetName()?.let { netName ->
        log.info("Sending immediate reconnection request to the tinc daemon.")
        try {
          tincCtl.retry(netName).get(5L, TimeUnit.SECONDS)
        } catch (_: Exception) {
        }
      }
    }
  }

  private fun isNetworkAvailable(intent: Intent) =
    !intent.getBooleanExtra(ConnectivityManager.EXTRA_NO_CONNECTIVITY, false)

  /**
   * Determine the local IP argument to pass to `tinc multipath uplink add`:
   * - Ignore loopback, link-local (`169.254.x.x` / `fe80::`), and unspecified addresses.
   * - On Android API 23+ (`netHandle != 0L`), dual-stack and IPv4 networks pass `"-"`
   *   (unless an earlier IPv6-only state already pushed a v6 literal, in which case `v4`
   *   is pushed once so both v4 and v6 UDP sockets open) so C `multipath_bind_socket`
   *   binds both `AF_INET` and `AF_INET6` sockets directly via `android_setsocknetwork`.
   * - On IPv6-only networks (`v4 == null && v6 != null`), pass the global IPv6 address
   *   so C `ensure_uplink_sockets` opens `AF_INET6` instead of `AF_INET`.
   */
  internal fun resolveUplinkLocalIp(
    addresses: List<InetAddress>,
    netHandle: Long,
    previouslyPushedV6: Boolean = false,
  ): Pair<String, Boolean> {
    val v4 = addresses.firstOrNull {
      it is Inet4Address && !it.isLoopbackAddress && !it.isLinkLocalAddress && !it.isAnyLocalAddress
    }
    val v6 = addresses.firstOrNull {
      it is Inet6Address && !it.isLoopbackAddress && !it.isLinkLocalAddress && !it.isAnyLocalAddress
    }
    if (v4 == null && v6 != null) {
      val v6Str = v6.hostAddress?.substringBefore('%') ?: "-"
      return v6Str to (v6Str != "-")
    }
    if (netHandle != 0L) {
      if (previouslyPushedV6 && v4 != null) {
        return (v4.hostAddress ?: "-") to true
      }
      return "-" to previouslyPushedV6
    }
    val fallback = (v4 ?: v6)?.hostAddress?.substringBefore('%') ?: "-"
    return fallback to (v4 == null && v6 != null && fallback != "-")
  }

  internal fun effectiveUplinkPolicy(
    baseWeight: Int,
    baseBackup: Boolean,
    validated: Boolean,
  ): Pair<Int, Boolean> {
    return if (validated) {
      baseWeight to baseBackup
    } else {
      // Unvalidated networks (e.g. Captive Portal Wi-Fi) stay backup with reduced
      // weight until NET_CAPABILITY_VALIDATED arrives so they do not hijack traffic
      // away from a working validated Cellular uplink.
      (baseWeight / 4).coerceAtLeast(1) to true
    }
  }

  internal val ACTIVE_MULTIPATH_MODES = setOf("failover", "flowhash", "redundant", "split")

  internal fun normalizeMultipathMode(raw: String?): String =
    raw?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: "off"

  internal fun isMultipathEnabled(rawMode: String?, rawMultipathFlag: String? = null): Boolean {
    val explicitMode = rawMode?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
    if (explicitMode != null) {
      return explicitMode in ACTIVE_MULTIPATH_MODES
    }
    return TincYaml.asTincBoolean(rawMultipathFlag, false)
  }

  private fun extractSourceIp(
    cm: ConnectivityManager,
    network: Network,
    netHandle: Long,
    previouslyPushedV6: Boolean,
    lp: LinkProperties? = null,
  ): Pair<String, Boolean> {
    return try {
      val props = lp ?: cm.getLinkProperties(network) ?: return "-" to previouslyPushedV6
      resolveUplinkLocalIp(props.linkAddresses.map { it.address }, netHandle, previouslyPushedV6)
    } catch (_: Exception) {
      "-" to previouslyPushedV6
    }
  }

  private fun isNetworkValidated(cm: ConnectivityManager, network: Network, caps: NetworkCapabilities? = null): Boolean {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return true
    return try {
      val nc = caps ?: cm.getNetworkCapabilities(network) ?: return false
      nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    } catch (_: Exception) {
      false
    }
  }

  private fun pushUplink(name: String, ip: String, weight: Int, backup: Boolean, netHandle: Long, up: Boolean) {
    enqueueUplinkCommand {
      if (!tincVpnService.isDaemonRunning()) return@enqueueUplinkCommand
      val netName = tincVpnService.getCurrentNetName() ?: return@enqueueUplinkCommand
      val future = if (up) {
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
      try {
        future.get(5L, TimeUnit.SECONDS)
      } catch (_: Exception) {
      }
    }
  }

  private fun syncActiveUplink(
    cm: ConnectivityManager,
    uplinkName: String,
    network: Network,
    baseWeight: Int,
    baseBackup: Boolean,
    lp: LinkProperties? = null,
    caps: NetworkCapabilities? = null,
    forcePush: Boolean = false,
  ): Boolean {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
    val handle = network.networkHandle
    val prev = uplinkStates[uplinkName]
    val prevPushedV6 = if (prev != null && prev.netHandle == handle) prev.pushedV6 else false
    val (ip, pushedV6) = extractSourceIp(cm, network, handle, prevPushedV6, lp)
    val validated = isNetworkValidated(cm, network, caps)
    val (effWeight, effBackup) = effectiveUplinkPolicy(baseWeight, baseBackup, validated)
    val next = UplinkState(handle, ip, effWeight, effBackup, pushedV6)
    if (!forcePush && prev == next) return false
    val promoted = prev != null && prev.backup && !next.backup
    uplinkStates[uplinkName] = next
    log.info(
      "Multipath uplink {} sync (handle={}, ip={}, weight={}, backup={}, validated={})",
      uplinkName, handle, ip, effWeight, effBackup, validated
    )
    pushUplink(uplinkName, ip, effWeight, effBackup, handle, up = true)
    return promoted
  }

  private fun makeCallback(
    cm: ConnectivityManager,
    uplinkName: String,
    weight: Int,
    backup: Boolean,
  ): ConnectivityManager.NetworkCallback = object : ConnectivityManager.NetworkCallback() {
    override fun onAvailable(network: Network) {
      syncActiveUplink(cm, uplinkName, network, weight, backup, forcePush = true)
      attemptReconnect()
    }

    override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
      val promoted = syncActiveUplink(cm, uplinkName, network, weight, backup, caps = networkCapabilities)
      if (promoted) {
        attemptReconnect()
      }
    }

    override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
      syncActiveUplink(cm, uplinkName, network, weight, backup, lp = linkProperties)
    }

    override fun onLost(network: Network) {
      val current = uplinkStates[uplinkName]
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && current != null && current.netHandle != network.networkHandle) {
        return
      }
      uplinkStates.remove(uplinkName)
      log.info("Multipath uplink {} lost", uplinkName)
      pushUplink(uplinkName, "-", weight, backup, 0L, up = false)
      attemptReconnect()
    }
  }

  @Synchronized
  fun registerWatcher(context: Context) {
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    if (cm != null) unregisterCallbacks(cm)
    try {
      context.unregisterReceiver(this)
    } catch (_: Exception) {
    }

    @Suppress("DEPRECATION")
    val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
    try {
      context.registerReceiver(this, filter)
    } catch (_: Exception) {
    }

    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M || cm == null) return

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
    val mpActive = try {
      val netName = tincVpnService.getCurrentNetName()
      if (netName != null) {
        val yaml = TincYaml(AppPaths.tincYamlFile(netName))
        val stanza = yaml.resolveNetwork(netName)
        isMultipathEnabled(
          yaml.optionValue(stanza, "MultipathMode"),
          yaml.optionValue(stanza, "Multipath"),
        )
      } else {
        false
      }
    } catch (_: Exception) {
      false
    }
    try {
      if (mpActive) {
        cm.requestNetwork(cellReq, cellCb)
      } else {
        cm.registerNetworkCallback(cellReq, cellCb)
      }
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
    uplinkStates.clear()
  }

  @Synchronized
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
