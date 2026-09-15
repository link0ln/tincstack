/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2023 Euxane P. TRAN-GIRARD
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

package org.pacien.tincapp.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.LocalServerSocket
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import java8.util.concurrent.CompletableFuture
import org.pacien.tincapp.BuildConfig
import org.pacien.tincapp.R
import org.pacien.tincapp.commands.Executor
import org.pacien.tincapp.commands.Tinc
import org.pacien.tincapp.commands.Tincd
import org.pacien.tincapp.context.App
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.data.TincYaml
import org.pacien.tincapp.data.VpnInterfaceConfiguration
import org.pacien.tincapp.extensions.Java.applyIgnoringException
import org.pacien.tincapp.extensions.Java.defaultMessage
import org.pacien.tincapp.extensions.VpnServiceBuilder.applyCfg
import org.pacien.tincapp.intent.Actions
import org.slf4j.LoggerFactory
import java.security.AccessControlException

/**
 * @author euxane
 */
class TincVpnService : VpnService() {
  private val log by lazy { LoggerFactory.getLogger(this.javaClass)!! }
  private val connectivityChangeReceiver = ConnectivityChangeReceiver

  override fun onDestroy() {
    stopVpn().join()
    super.onDestroy()
  }

  override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
    log.info("Intent received: {}", intent.toString())

    when {
      intent.action == Actions.ACTION_CONNECT && intent.scheme == Actions.TINC_SCHEME ->
        startVpn(intent.data!!.schemeSpecificPart)
      intent.action == Actions.ACTION_DISCONNECT ->
        stopVpn()
      intent.action == Actions.ACTION_SYSTEM_CONNECT ->
        restorePreviousConnection()
      else ->
        throw IllegalArgumentException("Invalid intent action received.")
    }

    return Service.START_NOT_STICKY
  }

  private fun restorePreviousConnection() {
    val netName = getCurrentNetName()
    if (netName == null) {
      log.info("No connection to restore.")
      return
    }

    log.info("Restoring previous connection to \"$netName\".")
    startVpn(netName)
  }

  private fun startVpn(netName: String): Unit = synchronized(this) {
    if (netName.isBlank())
      return reportError(resources.getString(R.string.notification_error_message_no_network_name_provided), docTopic = "doc.html#intent-api")

    if (!AppPaths.confDir(netName).exists())
      return reportError(resources.getString(R.string.notification_error_message_no_configuration_for_network_format, netName), docTopic = "doc.html#configuration-files")

    log.info("Starting tinc daemon for network \"$netName\".")
    if (isConnected() || getCurrentNetName() != null) stopVpn().join()

    // The one config file. A missing file is fine: the daemon materialises it
    // (name, keys, pool) at first start; the interface then gets the pool's first
    // address and route, so a fresh network is usable right away.
    val yaml = TincYaml(AppPaths.tincYamlFile(netName))
    val stanza = yaml.resolveNetwork(netName)

    val interfaceCfg = try {
      VpnInterfaceConfiguration.fromTincYaml(yaml, stanza)
    } catch (e: TincYaml.InvalidConfigurationException) {
      return reportError(
        resources.getString(R.string.notification_error_message_network_config_invalid_format, e.defaultMessage()),
        e,
        docTopic = "doc.html#network-interface",
        configDir = netName,
      )
    } catch (e: Exception) {
      return reportError(
        resources.getString(R.string.notification_error_message_could_not_read_network_configuration_format, e.defaultMessage()),
        e,
        configDir = netName,
      )
    }

    val deviceFd = try {
      Builder().setSession(netName)
        .applyCfg(interfaceCfg)
        .also { applyIgnoringException(it::addDisallowedApplication, BuildConfig.APPLICATION_ID) }
        // inherit metered property from underlying network
        .also { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) it.setMetered(false) }
        .establish()!!
    } catch (e: IllegalArgumentException) {
      return reportError(
        resources.getString(R.string.notification_error_message_network_config_invalid_format, e.defaultMessage()),
        e,
        docTopic = "doc.html#network-interface",
        configDir = netName,
      )
    } catch (e: NullPointerException) {
      return reportError(
        resources.getString(R.string.notification_error_message_could_not_bind_iface),
        e,
        proposeLogs = true,
      )
    } catch (e: Exception) {
      return reportError(
        resources.getString(R.string.notification_error_message_could_not_configure_iface, e.defaultMessage()),
        e,
        proposeLogs = true,
      )
    }

    val serverSocket = LocalServerSocket(DEVICE_FD_ABSTRACT_SOCKET)
    Executor.runAsyncTask { serveDeviceFd(serverSocket, deviceFd) }

    val daemon = Tincd.start(netName, stanza, DEVICE_FD_ABSTRACT_SOCKET)
    setState(netName, interfaceCfg, deviceFd, daemon)

    waitForDaemonStartup().whenComplete { _, exception ->
      serverSocket.close()
      deviceFd.close()

      if (exception != null) {
        reportError(
          resources.getString(R.string.notification_error_message_daemon_exited, exception.cause!!.defaultMessage()),
          exception,
          proposeLogs = true,
        )
      } else {
        log.info("tinc daemon started.")
        broadcastEvent(Actions.EVENT_CONNECTED)
      }

      if (interfaceCfg.reconnectOnNetworkChange)
        connectivityChangeReceiver.registerWatcher(this)
    }
  }

  private fun stopVpn(): CompletableFuture<Unit> = synchronized(this) {
    log.info("Stopping any running tinc daemon.")

    connectivityChangeReceiver.unregisterWatcher(this)

    getCurrentNetName()?.let {
      Tinc.stop(it).handle { _, _ ->
        log.info("All tinc daemons stopped.")
        broadcastEvent(Actions.EVENT_DISCONNECTED)
        setState(null, null, null, null)
      }
    } ?: CompletableFuture.completedFuture(Unit)
  }

  private fun reportError(
    msg: String,
    e: Throwable? = null,
    docTopic: String? = null,
    configDir: String? = null,
    proposeLogs: Boolean = false,
  ) {
    if (e != null)
      log.error(msg, e)
    else
      log.error(msg)

    broadcastEvent(Actions.EVENT_ABORTED)
    App.alert(
      R.string.notification_error_title_unable_to_start_tinc,
      msg,
      if (docTopic != null) resources.getString(R.string.app_doc_url_format, docTopic) else null,
      configDir,
      proposeLogs,
    )
  }

  private fun broadcastEvent(event: String) {
    LocalBroadcastManager.getInstance(this).sendBroadcast(Intent(event))
  }

  private fun serveDeviceFd(serverSocket: LocalServerSocket, deviceFd: ParcelFileDescriptor) =
    serverSocket.accept().let { socket ->
      try {
        if (socket.peerCredentials.uid != App.getApplicationInfo().uid)
          throw AccessControlException("Peer UID mismatch.")

        socket.setFileDescriptorsForSend(arrayOf(deviceFd.fileDescriptor))
        socket.outputStream.write(0) // dummy write
        socket.outputStream.flush()
      } catch (e: Exception) {
        log.error("Error while serving device fd", e)
      } finally {
        socket.close()
      }
    }

  private fun waitForDaemonStartup() =
    Executor
      .runAsyncTask { Thread.sleep(SETUP_DELAY) }
      .thenCompose { if (daemon!!.isDone) daemon!! else Executor.runAsyncTask { Unit } }

  companion object {
    private const val SETUP_DELAY = 500L // ms
    private const val DEVICE_FD_ABSTRACT_SOCKET = "${BuildConfig.APPLICATION_ID}.daemon.socket"

    private val STORE_NAME = this::class.java.`package`!!.name
    private const val STORE_KEY_NETNAME = "netname"

    private val context by lazy { App.getContext() }
    private val store by lazy { context.getSharedPreferences(STORE_NAME, Context.MODE_PRIVATE)!! }

    private var interfaceCfg: VpnInterfaceConfiguration? = null
    private var fd: ParcelFileDescriptor? = null
    private var daemon: CompletableFuture<Unit>? = null

    private fun saveConnection(netName: String?) =
      store.edit()
        .putString(STORE_KEY_NETNAME, netName)
        .apply()

    private fun setState(netName: String?, interfaceCfg: VpnInterfaceConfiguration?,
                         fd: ParcelFileDescriptor?, daemon: CompletableFuture<Unit>?) {
      saveConnection(netName)
      TincVpnService.interfaceCfg = interfaceCfg
      TincVpnService.fd = fd
      TincVpnService.daemon = daemon
    }

    fun getCurrentNetName(): String? = store.getString(STORE_KEY_NETNAME, null)

    fun getCurrentInterfaceCfg() = interfaceCfg
    fun isConnected() = !(daemon?.isDone ?: true)

    fun connect(netName: String) {
      App.notificationManager.dismissAll()

      App.getContext().startService(
        Intent(App.getContext(), TincVpnService::class.java)
          .setAction(Actions.ACTION_CONNECT)
          .setData(Actions.buildNetworkUri(netName)))
    }

    fun disconnect() {
      App.getContext().startService(
        Intent(App.getContext(), TincVpnService::class.java)
          .setAction(Actions.ACTION_DISCONNECT))
    }
  }
}
