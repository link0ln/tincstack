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

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.LocalServerSocket
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import java8.util.concurrent.CompletableFuture
import org.pacien.tincapp.BuildConfig
import org.pacien.tincapp.R
import org.pacien.tincapp.activities.start.StartActivity
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
import org.pacien.tincapp.service.SessionStateMachine.Action
import org.pacien.tincapp.service.SessionStateMachine.DaemonRun
import org.pacien.tincapp.service.SessionStateMachine.Event
import org.pacien.tincapp.service.SessionStateMachine.State
import org.pacien.tincapp.service.SessionStateMachine.TearDownReason
import org.pacien.tincapp.utils.PendingIntentUtils
import org.slf4j.LoggerFactory
import java.security.AccessControlException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * The VPN session.
 *
 * The service owns the tun fd for the whole session and runs in the foreground
 * while connected (notification with a Disconnect action). tincd receives a
 * duplicate of the fd over an abstract Unix socket (SCM_RIGHTS, see
 * core/tincd/src/fd_device.c) at every launch; the service never closes its
 * own copy before the session ends. That is what lets `DisconnectOnScreenOff`
 * stop tincd while the screen is locked and relaunch it on unlock without the
 * VPN ever going down (see [SessionStateMachine]).
 *
 * All session work (establish, daemon start/stop, tear-down) runs on one
 * worker thread, in the order it was asked for.
 *
 * @author euxane
 */
class TincVpnService : VpnService() {
  private val log by lazy { LoggerFactory.getLogger(this.javaClass)!! }
  private val connectivityChangeReceiver = ConnectivityChangeReceiver

  override fun onCreate() {
    super.onCreate()
    instance = this
  }

  override fun onDestroy() {
    // stopSelf after a tear-down lands here with no session; anything else (the
    // system stopping us) ends whatever session is left, without resurrection.
    if (state !is State.Idle) {
      log.warn("Service destroyed with a live session ({}): ending it.", state)
      setState(State.Idle)
      worker.submit { endSession(null, TearDownReason.REVOKED, stopService = false, anySession = true) }.get(STOP_TIMEOUT_S, TimeUnit.SECONDS)
    }
    if (instance === this) instance = null
    super.onDestroy()
  }

  override fun onRevoke() {
    // another VPN app took over, or the consent was withdrawn: final
    log.info("VPN revoked.")
    dispatch(Event.Revoked)
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    log.info("Intent received: {}", intent.toString())

    when {
      intent == null -> Unit
      intent.action == Actions.ACTION_CONNECT && intent.scheme == Actions.TINC_SCHEME ->
        intent.data!!.schemeSpecificPart.let { netName -> worker.submit { startVpn(netName) } }

      intent.action == Actions.ACTION_DISCONNECT ->
        dispatch(Event.UserDisconnect)

      intent.action == Actions.ACTION_SYSTEM_CONNECT ->
        worker.submit { restorePreviousConnection() }

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

  // ---- session start (worker thread) ---------------------------------------

  private fun startVpn(netName: String) {
    if (netName.isBlank())
      return reportError(resources.getString(R.string.notification_error_message_no_network_name_provided), docTopic = "doc.html#intent-api")

    if (!AppPaths.confDir(netName).exists())
      return reportError(resources.getString(R.string.notification_error_message_no_configuration_for_network_format, netName), docTopic = "doc.html#configuration-files")

    log.info("Starting tinc daemon for network \"$netName\".")
    if (state !is State.Idle || tunFd != null || getCurrentNetName() != null) {
      setState(State.Idle)
      endSession(null, TearDownReason.USER, stopService = false, anySession = true)
    }

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

    val run = DaemonRun(++sessionCounter, 0)
    saveConnection(netName)
    TincVpnService.interfaceCfg = interfaceCfg
    TincVpnService.stanza = stanza
    tunFd = deviceFd
    session = run.session
    dispatch(Event.SessionStarted(netName, run, interfaceCfg.disconnectOnScreenOff))

    enterForeground(netName, suspended = false)
    if (interfaceCfg.disconnectOnScreenOff) screenStateReceiver.register(applicationContext)

    val startup = launchDaemon(netName, stanza, run)
    startup.whenComplete { _, exception ->
      if (exception != null) {
        reportError(
          resources.getString(R.string.notification_error_message_daemon_exited, (exception.cause ?: exception).defaultMessage()),
          exception,
          proposeLogs = true,
        )
      } else {
        log.info("tinc daemon started.")
        broadcastEvent(Actions.EVENT_CONNECTED)
        if (interfaceCfg.reconnectOnNetworkChange)
          connectivityChangeReceiver.registerWatcher(this)
      }
    }
    try {
      startup.get(STOP_TIMEOUT_S, TimeUnit.SECONDS)
    } catch (e: Exception) {
      // reported above; the daemon's exit ends the session through the state machine
    }
  }

  /**
   * Launch tincd as [run] on the kept tun fd. The future completes once the
   * daemon survived its startup delay (exceptionally if it did not).
   */
  private fun launchDaemon(netName: String, stanza: String, run: DaemonRun): CompletableFuture<Unit> {
    val fd = tunFd ?: return CompletableFuture.failedFuture(IllegalStateException("no tun fd"))
    val serverSocket = LocalServerSocket(DEVICE_FD_ABSTRACT_SOCKET)
    Executor.runAsyncTask { serveDeviceFd(serverSocket, fd) }

    val process = Tincd.start(netName, stanza, DEVICE_FD_ABSTRACT_SOCKET)
    daemon = process
    process.whenComplete { _, e ->
      log.info("tinc daemon {} exited{}.", run, if (e != null) ": ${(e.cause ?: e).defaultMessage()}" else "")
      dispatch(Event.DaemonExited(run))
    }

    return waitForDaemonStartup(process).whenComplete { _, _ -> serverSocket.close() }
  }

  // ---- state machine plumbing ----------------------------------------------

  private fun perform(action: Action) {
    log.info("Session action: {}", action)
    when (action) {
      is Action.StopDaemon -> suspendSession(action.netName)
      is Action.StartDaemon -> resumeSession(action.netName, action.run)
      is Action.TearDown -> endSession(action.session, action.reason, stopService = true)
    }
  }

  /** Screen off: stop tincd, keep the tun (worker thread). */
  private fun suspendSession(netName: String) {
    connectivityChangeReceiver.unregisterWatcher(this)
    stopDaemon(netName)
    updateNotification(netName, suspended = true)
    log.info("Session suspended: tinc daemon stopped, VPN interface kept.")
  }

  /** Unlocked: relaunch tincd on the kept tun (worker thread). */
  private fun resumeSession(netName: String, run: DaemonRun) {
    if (session != run.session || tunFd == null) return
    // a stop that did not take (control socket gone?) must not leave two daemons
    if (daemon?.isDone == false) stopDaemon(netName)

    val cfg = interfaceCfg
    try {
      launchDaemon(netName, stanza ?: netName, run).get(STOP_TIMEOUT_S, TimeUnit.SECONDS)
    } catch (e: Exception) {
      log.error("Could not relaunch the tinc daemon after unlock.", e)
      reportError(
        resources.getString(R.string.notification_error_message_daemon_exited, (e.cause ?: e).defaultMessage()),
        e,
        proposeLogs = true,
      )
      dispatch(Event.ResumeFailed(run))
      return
    }
    if (cfg?.reconnectOnNetworkChange == true) connectivityChangeReceiver.registerWatcher(this)
    updateNotification(netName, suspended = false)
    log.info("Session resumed: tinc daemon relaunched ({}).", run)
  }

  private fun stopDaemon(netName: String) {
    val running = daemon ?: return
    if (running.isDone) return
    try {
      Tinc.stop(netName).get(STOP_TIMEOUT_S, TimeUnit.SECONDS)
    } catch (e: Exception) {
      log.warn("tinc stop failed: {}", (e.cause ?: e).defaultMessage())
    }
    try {
      running.get(STOP_TIMEOUT_S, TimeUnit.SECONDS)
    } catch (e: Exception) {
      if (!running.isDone) log.warn("tinc daemon still running after stop.")
    }
  }

  /**
   * End session [forSession] (worker thread): stop tincd, close the tun, leave
   * the foreground. A tear-down queued for a session that has since been
   * replaced does nothing, unless [anySession]. A null [forSession] was asked
   * for with no session up; the worker runs in order, so it applies to
   * whatever was started before it was queued (a connect still starting).
   */
  private fun endSession(forSession: Long?, reason: TearDownReason, stopService: Boolean, anySession: Boolean = false) {
    if (!anySession && forSession != null && forSession != session) {
      log.info("Stale tear-down for session {} ignored (current {}).", forSession, session)
      return
    }
    log.info("Ending session {} ({}).", session, reason)
    screenStateReceiver.unregister(applicationContext)
    connectivityChangeReceiver.unregisterWatcher(this)

    getCurrentNetName()?.let { stopDaemon(it) }
    try {
      tunFd?.close()
    } catch (e: Exception) {
      log.warn("Closing the tun fd: {}", e.defaultMessage())
    }
    tunFd = null
    daemon = null
    interfaceCfg = null
    stanza = null
    session = null
    saveConnection(null)
    log.info("All tinc daemons stopped.")
    broadcastEvent(Actions.EVENT_DISCONNECTED)

    leaveForeground()
    if (stopService) stopSelf()
  }

  // ---- foreground notification ---------------------------------------------

  private fun buildNotification(netName: String, suspended: Boolean): Notification {
    val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && manager.getNotificationChannel(NOTIFICATION_CHANNEL) == null)
      manager.createNotificationChannel(
        NotificationChannel(NOTIFICATION_CHANNEL, getString(R.string.notification_vpn_channel_name), NotificationManager.IMPORTANCE_LOW))

    val open = PendingIntentUtils.getActivity(this, 0, Intent(this, StartActivity::class.java), PendingIntent.FLAG_UPDATE_CURRENT)
    val disconnect = PendingIntent.getService(
      this, 1,
      Intent(this, TincVpnService::class.java).setAction(Actions.ACTION_DISCONNECT),
      PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0))

    return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL)
      .setSmallIcon(R.drawable.ic_launcher_foreground)
      .setContentTitle(getString(R.string.status_activity_state_connected_to_format, netName))
      .setContentText(getString(if (suspended) R.string.notification_vpn_suspended else R.string.notification_vpn_running))
      .setContentIntent(open)
      .addAction(0, getString(R.string.status_activity_menu_disconnect), disconnect)
      .setOngoing(true)
      .setOnlyAlertOnce(true)
      .setShowWhen(false)
      .setCategory(NotificationCompat.CATEGORY_SERVICE)
      .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
      .build()
  }

  /**
   * Foreground for the session. A VpnService is exempt from the foreground-type
   * restrictions only as `systemExempted` ("VPN apps configured in Settings >
   * VPN", Android 14); `specialUse` is the declared fallback. Failing both, the
   * session still runs: the system's own binding to an established VpnService
   * keeps the process at foreground-service importance.
   */
  private fun enterForeground(netName: String, suspended: Boolean) {
    val notification = buildNotification(netName, suspended)
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      try {
        startForeground(NOTIFICATION_ID, notification)
        log.info("Running in the foreground.")
      } catch (e: Exception) {
        log.warn("Could not enter the foreground: {}", e.defaultMessage())
      }
      return
    }
    for ((type, label) in listOf(
      ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED to "systemExempted",
      ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE to "specialUse",
    )) {
      try {
        startForeground(NOTIFICATION_ID, notification, type)
        log.info("Running in the foreground ({}).", label)
        return
      } catch (e: Exception) {
        log.warn("Foreground type {} refused: {}", label, e.defaultMessage())
      }
    }
  }

  private fun updateNotification(netName: String, suspended: Boolean) {
    try {
      (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
        .notify(NOTIFICATION_ID, buildNotification(netName, suspended))
    } catch (e: Exception) {
      log.warn("Could not update the notification: {}", e.defaultMessage())
    }
  }

  private fun leaveForeground() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(Service.STOP_FOREGROUND_REMOVE)
    else @Suppress("DEPRECATION") stopForeground(true)
  }

  // ---- misc ----------------------------------------------------------------

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

  private fun serveDeviceFd(serverSocket: LocalServerSocket, deviceFd: ParcelFileDescriptor) {
    val socket = try {
      serverSocket.accept()
    } catch (e: Exception) {
      return // closed before the daemon connected (it died during startup)
    }
    try {
      if (socket.peerCredentials.uid != App.getApplicationInfo().uid)
        throw AccessControlException("Peer UID mismatch.")

      // SCM_RIGHTS installs a new descriptor in the daemon; ours stays open
      socket.setFileDescriptorsForSend(arrayOf(deviceFd.fileDescriptor))
      socket.outputStream.write(0) // dummy write
      socket.outputStream.flush()
    } catch (e: Exception) {
      log.error("Error while serving device fd", e)
    } finally {
      socket.close()
    }
  }

  private fun waitForDaemonStartup(process: CompletableFuture<Unit>) =
    Executor
      .runAsyncTask { Thread.sleep(SETUP_DELAY) }
      .thenCompose { if (process.isDone) process else Executor.runAsyncTask { Unit } }

  companion object {
    private val log by lazy { LoggerFactory.getLogger(TincVpnService::class.java)!! }

    private const val SETUP_DELAY = 500L // ms
    private const val STOP_TIMEOUT_S = 15L
    private const val DEVICE_FD_ABSTRACT_SOCKET = "${BuildConfig.APPLICATION_ID}.daemon.socket"
    private const val NOTIFICATION_CHANNEL = "vpn"
    private const val NOTIFICATION_ID = 1

    private val STORE_NAME = this::class.java.`package`!!.name
    private const val STORE_KEY_NETNAME = "netname"

    private val context by lazy { App.getContext() }
    private val store by lazy { context.getSharedPreferences(STORE_NAME, Context.MODE_PRIVATE)!! }

    /** Session work, one at a time, in order. Process-wide: the state below is. */
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "tinc-session") }

    @Volatile private var instance: TincVpnService? = null
    @Volatile private var state: State = State.Idle
    private var sessionCounter = 0L

    // owned by the worker thread
    @Volatile private var session: Long? = null
    @Volatile private var interfaceCfg: VpnInterfaceConfiguration? = null
    @Volatile private var stanza: String? = null
    @Volatile private var tunFd: ParcelFileDescriptor? = null
    @Volatile private var daemon: CompletableFuture<Unit>? = null

    private val screenStateReceiver = ScreenStateReceiver { event -> dispatch(event) }

    private fun setState(s: State) = synchronized(this) { state = s }

    /**
     * Feed [event] to the state machine and queue the resulting actions on the
     * worker. The future completes when they have run.
     */
    private fun dispatch(event: Event): CompletableFuture<Unit> {
      val transition = synchronized(this) {
        SessionStateMachine.next(state, event).also { state = it.state }
      }
      if (transition.actions.isEmpty()) {
        if (event !is Event.DaemonExited) log.info("Session event {}: {} (no action)", event, transition.state)
        return CompletableFuture.completedFuture(Unit)
      }
      log.info("Session event {}: -> {} {}", event, transition.state, transition.actions)
      val done = CompletableFuture<Unit>()
      worker.submit {
        try {
          val service = instance
          transition.actions.forEach { action ->
            if (service != null) service.perform(action)
            else log.warn("No service instance for {}", action)
          }
          done.complete(Unit)
        } catch (e: Throwable) {
          log.error("Session action failed", e)
          done.completeExceptionally(e)
        }
      }
      return done
    }

    private fun saveConnection(netName: String?) =
      store.edit()
        .putString(STORE_KEY_NETNAME, netName)
        .apply()

    fun getCurrentNetName(): String? = store.getString(STORE_KEY_NETNAME, null)

    fun getCurrentInterfaceCfg() = interfaceCfg

    /** A session is up (tincd running, or stopped while the screen is locked). */
    fun isConnected() = state !is State.Idle

    /** tincd itself is running (false while a session is suspended). */
    fun isDaemonRunning() = !(daemon?.isDone ?: true)

    fun isSuspended() = state is State.Suspended

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
