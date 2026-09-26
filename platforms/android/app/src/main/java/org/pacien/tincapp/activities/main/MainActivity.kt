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

package org.pacien.tincapp.activities.main

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.PopupMenu
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.AttrRes
import androidx.annotation.ColorInt
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import com.google.android.material.color.MaterialColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import org.pacien.tincapp.R
import org.pacien.tincapp.activities.BaseActivity
import org.pacien.tincapp.activities.apps.AppPickerActivity
import org.pacien.tincapp.activities.common.Labels
import org.pacien.tincapp.activities.common.NetworkListLiveData
import org.pacien.tincapp.activities.common.PeersLiveData
import org.pacien.tincapp.activities.join.JoinActivity
import org.pacien.tincapp.activities.join.JoinPanel
import org.pacien.tincapp.activities.log.LogActivity
import org.pacien.tincapp.activities.peers.PeersActivity
import org.pacien.tincapp.commands.Executor
import org.pacien.tincapp.commands.Join
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.context.CrashRecorder
import org.pacien.tincapp.data.Networks
import org.pacien.tincapp.data.PeerStatus
import org.pacien.tincapp.data.SplitRouting
import org.pacien.tincapp.data.SplitRoutingMode
import org.pacien.tincapp.data.TincYaml
import org.pacien.tincapp.data.Transport
import org.pacien.tincapp.data.VpnInterfaceConfiguration
import org.pacien.tincapp.databinding.ActivityMainBinding
import org.pacien.tincapp.databinding.RowItemBinding
import org.pacien.tincapp.databinding.TransportItemBinding
import org.pacien.tincapp.extensions.Java.defaultMessage
import org.pacien.tincapp.extensions.Java.exceptionallyAccept
import org.pacien.tincapp.intent.Actions
import org.pacien.tincapp.service.ConnectionState
import org.pacien.tincapp.service.TincVpnService
import org.pacien.tincapp.service.VpnStatus
import org.slf4j.LoggerFactory

/**
 * The one screen: no network yet -> the join form; otherwise the selected
 * network with one big button, what the connection is doing in words, and a
 * handful of settings.
 *
 * "Connected" means a peer answers, not merely that tincd runs: until the node
 * we dial is reachable the screen says whom it is looking for, and after
 * [Join.CONNECT_DEADLINE_S] seconds that it is not answering, with the log one
 * tap away. Every failure the service reports ([VpnStatus]) stays on screen,
 * in words, until dismissed or replaced by the next attempt.
 */
class MainActivity : BaseActivity() {
  private val log by lazy { LoggerFactory.getLogger(MainActivity::class.java)!! }
  private lateinit var binding: ActivityMainBinding
  private lateinit var joinPanel: JoinPanel
  override val snackbarRoot: View get() = binding.mainRoot

  private val prefs by lazy { getSharedPreferences(PREFS, Context.MODE_PRIVATE) }
  private val handler = Handler(Looper.getMainLooper())
  private val tick = Runnable { renderStatus() }

  private val networkList = NetworkListLiveData()
  private var networks: List<String>? = null
  private var selected: String? = null
  private var summary: NetworkSettings? = null
  private var peersSource: PeersLiveData? = null
  private var peers: List<PeerStatus>? = null
  private var status: ConnectionState = ConnectionState.Disconnected

  /** Waiting for the notification / VPN permission dialogs before connecting it. */
  private var pendingConnect: String? = null

  /** Remove once its session is down. */
  private var pendingRemoval: String? = null

  private val notificationPermission =
    registerForActivityResult(ActivityResultContracts.RequestPermission()) { askVpnConsent() }

  private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
    val net = pendingConnect ?: return@registerForActivityResult
    pendingConnect = null
    if (result.resultCode == RESULT_OK) TincVpnService.connect(net)
    else VpnStatus.set(ConnectionState.Failed(net, getString(R.string.error_vpn_permission)))
  }

  private val appPicker = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
    if (result.resultCode == RESULT_OK) {
      loadSettings()
      notifyApplies(R.string.apps_saved)
    }
  }

  /** What the settings rows show, read from the network's tinc.yaml. */
  private data class NetworkSettings(
    val summary: Networks.Summary,
    val transport: Transport?,
    val accepted: Set<Transport>,
    val routing: SplitRouting?,
    val pauseOnLock: Boolean,
  )

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    binding = ActivityMainBinding.inflate(layoutInflater)
    setContentView(binding.root)
    setupToolbar(binding.toolbar, up = false)
    status = VpnStatus.current()
    pendingConnect = savedInstanceState?.getString(STATE_PENDING_CONNECT)

    joinPanel = JoinPanel(this, binding.joinPanel, this) { net -> onJoined(net) }
    setupRows()
    binding.connectButton.setOnClickListener { onPrimaryAction() }
    binding.networkSelector.setOnClickListener { showNetworkMenu() }
    binding.stateLogButton.setOnClickListener { openLog() }
    binding.stateDismissButton.setOnClickListener { VpnStatus.dismissFailure() }

    VpnStatus.state.observe(this) { onStatus(it) }
    networkList.observe(this) { onNetworks(it) }

    if (savedInstanceState == null) {
      handleIntent(intent)
      if (CrashRecorder.hasPreviouslyCrashed()) showCrashDialog()
    }
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    handleIntent(intent)
  }

  override fun onSaveInstanceState(outState: Bundle) {
    super.onSaveInstanceState(outState)
    outState.putString(STATE_PENDING_CONNECT, pendingConnect)
  }

  override fun onResume() {
    super.onResume()
    loadSettings()
  }

  override fun onPause() {
    handler.removeCallbacks(tick)
    super.onPause()
  }

  override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    joinPanel.onWindowFocusChanged(hasFocus)
  }

  @Deprecated("zxing's IntentIntegrator still reports through onActivityResult")
  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    if (!joinPanel.onActivityResult(requestCode, resultCode, data))
      @Suppress("DEPRECATION") super.onActivityResult(requestCode, resultCode, data)
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.menu_main, menu)
    return true
  }

  override fun onPrepareOptionsMenu(menu: Menu): Boolean {
    val hasNetworks = !networks.isNullOrEmpty()
    menu.findItem(R.id.menu_add_network).isVisible = hasNetworks
    menu.findItem(R.id.menu_remove_network).isVisible = hasNetworks
    return super.onPrepareOptionsMenu(menu)
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean = when (item.itemId) {
    R.id.menu_add_network -> {
      startActivity(Intent(this, JoinActivity::class.java)); true
    }

    R.id.menu_log -> {
      openLog(); true
    }

    R.id.menu_remove_network -> {
      selected?.let { confirmRemove(it) }; true
    }

    R.id.menu_about -> {
      showAbout(); true
    }

    else -> super.onOptionsItemSelected(item)
  }

  // ---- intents --------------------------------------------------------------

  private fun handleIntent(intent: Intent?) {
    when (intent?.action) {
      Actions.ACTION_CONNECT -> intent.data?.takeIf { it.scheme == Actions.TINC_SCHEME }?.schemeSpecificPart?.let { net ->
        if (net in Networks.list()) {
          select(net)
          if (!(status.active && status.netName == net)) connect(net)
        } else {
          notify(getString(R.string.error_no_config_format, net))
        }
      }

      Actions.ACTION_DISCONNECT -> TincVpnService.disconnect()
    }
  }

  private fun onJoined(net: String) {
    notify(getString(R.string.joined_format, net))
    select(net)
    connect(net)
  }

  // ---- networks and selection -----------------------------------------------

  private fun onNetworks(list: List<String>) {
    networks = list
    pendingRemoval?.let { if (it !in list) pendingRemoval = null }
    val keep = selected?.takeIf { it in list }
    val next = keep ?: activeNet()?.takeIf { it in list } ?: prefs.getString(PREF_SELECTED, null)?.takeIf { it in list }
    ?: list.firstOrNull()
    if (next != selected) select(next) else render()
    invalidateOptionsMenu()
  }

  /** The network of the session in progress, if any. */
  private fun activeNet(): String? = status.takeIf { it.active }?.netName ?: TincVpnService.getCurrentNetName()

  private fun select(net: String?) {
    if (net != null && net != selected) prefs.edit().putString(PREF_SELECTED, net).apply()
    val changed = net != selected
    selected = net
    if (changed) {
      peersSource?.removeObservers(this)
      peers = null
      peersSource = net?.let { PeersLiveData(it) }?.also { source -> source.observe(this) { onPeers(it) } }
      loadSettings()
    }
    render()
  }

  private fun showNetworkMenu() {
    val list = networks ?: return
    if (status.active) return notify(R.string.main_switch_locked)
    PopupMenu(this, binding.networkSelector).apply {
      list.forEachIndexed { i, net -> menu.add(0, i, i, net).isCheckable = true }
      menu.setGroupCheckable(0, true, true)
      list.indexOf(selected).takeIf { it >= 0 }?.let { menu.getItem(it).isChecked = true }
      menu.add(1, list.size, list.size, R.string.menu_add_network)
      setOnMenuItemClickListener { item ->
        if (item.itemId < list.size) select(list[item.itemId])
        else startActivity(Intent(this@MainActivity, JoinActivity::class.java))
        true
      }
    }.show()
  }

  private fun confirmRemove(net: String) {
    MaterialAlertDialogBuilder(this)
      .setIcon(R.drawable.ic_delete)
      .setTitle(getString(R.string.remove_title_format, net))
      .setMessage(R.string.remove_message)
      .setNegativeButton(R.string.action_cancel, null)
      .setPositiveButton(R.string.action_remove) { _, _ ->
        if (status.active && status.netName == net) {
          pendingRemoval = net
          TincVpnService.disconnect()
        } else {
          remove(net)
        }
      }
      .show()
  }

  private fun remove(net: String) {
    pendingRemoval = null
    if ((status as? ConnectionState.Failed)?.net == net) VpnStatus.dismissFailure()
    Executor.runAsyncTask { Networks.remove(net) }
      .thenAccept { runOnUiThread { notify(getString(R.string.removed_format, net)); selected = null } }
      .exceptionallyAccept { e -> runOnUiThread { notify(e.cause?.defaultMessage() ?: e.defaultMessage()) } }
  }

  // ---- connecting ----------------------------------------------------------

  private fun onPrimaryAction() {
    val net = selected ?: return
    if (status.active) TincVpnService.disconnect()
    else connect(net)
  }

  /**
   * Notification permission first (Android 13+, asked once), then the VPN
   * consent, then the service: one system dialog at a time, and the outcome
   * always ends up in [VpnStatus] -- never an endless spinner.
   */
  private fun connect(net: String) {
    pendingConnect = net
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
      ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
      !prefs.getBoolean(PREF_ASKED_NOTIFICATIONS, false)) {
      prefs.edit().putBoolean(PREF_ASKED_NOTIFICATIONS, true).apply()
      notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
    } else {
      askVpnConsent()
    }
  }

  private fun askVpnConsent() {
    val net = pendingConnect ?: return
    val consent = try {
      VpnService.prepare(this)
    } catch (e: Exception) {
      log.error("VpnService.prepare failed", e)
      pendingConnect = null
      VpnStatus.set(ConnectionState.Failed(net, getString(R.string.error_vpn_busy)))
      return
    }
    if (consent == null) {
      pendingConnect = null
      TincVpnService.connect(net)
      return
    }
    try {
      vpnConsent.launch(consent)
    } catch (e: ActivityNotFoundException) {
      pendingConnect = null
      VpnStatus.set(ConnectionState.Failed(net, getString(R.string.error_vpn_busy)))
    }
  }

  private fun onStatus(s: ConnectionState) {
    status = s
    if (s.active) s.netName?.takeIf { it != selected && networks?.contains(it) != false }?.let { select(it) }
    pendingRemoval?.let { if (!s.active) remove(it) }
    render()
  }

  private fun onPeers(list: List<PeerStatus>?) {
    peers = list
    render()
  }

  // ---- rendering -----------------------------------------------------------

  private fun render() {
    val list = networks ?: return
    val hasNetworks = list.isNotEmpty()
    binding.joinPanel.root.isVisible = !hasNetworks
    binding.networkPanel.isVisible = hasNetworks
    if (!hasNetworks) {
      handler.removeCallbacks(tick)
      return
    }
    val net = selected ?: return
    binding.networkSelector.text = net
    // locked to the running network: no switching mid-session
    binding.networkSelector.icon = if (status.active) null else ContextCompat.getDrawable(this, R.drawable.ic_expand_more)
    renderStatus()
    renderRows()
  }

  private enum class Tone { OFF, BUSY, ON, PAUSED, ERROR }

  private data class Hero(
    val title: String,
    val detail: String,
    val tone: Tone,
    val action: Int,
    val showLog: Boolean = false,
    val showDismiss: Boolean = false,
  )

  private fun renderStatus() {
    handler.removeCallbacks(tick)
    val net = selected ?: return
    val s = status.takeIf { it.netName == null || it.netName == net } ?: ConnectionState.Disconnected
    val hero = when (s) {
      ConnectionState.Disconnected ->
        Hero(getString(R.string.state_disconnected), getString(R.string.state_disconnected_detail), Tone.OFF, R.string.main_connect)

      is ConnectionState.Connecting ->
        Hero(getString(R.string.state_connecting), getString(R.string.state_connecting_detail), Tone.BUSY, R.string.main_disconnect)

      is ConnectionState.Connected -> connectedHero(net)

      is ConnectionState.Paused ->
        Hero(getString(R.string.state_paused), getString(R.string.state_paused_detail), Tone.PAUSED, R.string.main_disconnect)

      is ConnectionState.Failed ->
        Hero(getString(if (s.lost) R.string.state_lost else R.string.state_failed), s.message, Tone.ERROR, R.string.main_connect,
          showLog = true, showDismiss = true)
    }

    binding.stateTitle.text = hero.title
    binding.stateDetail.text = hero.detail
    binding.stateActions.isVisible = hero.showLog || hero.showDismiss
    binding.stateLogButton.isVisible = hero.showLog
    binding.stateDismissButton.isVisible = hero.showDismiss
    binding.connectButton.contentDescription = getString(hero.action)
    binding.connectProgress.visibility = if (hero.tone == Tone.BUSY) View.VISIBLE else View.INVISIBLE

    val (background, content) = when (hero.tone) {
      Tone.OFF -> attr(com.google.android.material.R.attr.colorPrimary) to attr(com.google.android.material.R.attr.colorOnPrimary)
      Tone.BUSY -> attr(com.google.android.material.R.attr.colorSecondaryContainer) to
        attr(com.google.android.material.R.attr.colorOnSecondaryContainer)

      Tone.ON -> getColor(R.color.state_on) to getColor(R.color.state_on_content)
      Tone.PAUSED -> attr(com.google.android.material.R.attr.colorTertiaryContainer) to
        attr(com.google.android.material.R.attr.colorOnTertiaryContainer)

      Tone.ERROR -> attr(com.google.android.material.R.attr.colorErrorContainer) to
        attr(com.google.android.material.R.attr.colorOnErrorContainer)
    }
    binding.connectButton.backgroundTintList = ColorStateList.valueOf(background)
    binding.connectButton.iconTint = ColorStateList.valueOf(content)
    binding.stateTitle.setTextColor(
      if (hero.tone == Tone.ON) getColor(R.color.state_on) else attr(com.google.android.material.R.attr.colorOnSurface))
  }

  /**
   * tincd is up; whether we are really connected depends on the peers. The
   * node(s) of `ConnectTo` are the ones that matter: through them the rest of
   * the mesh is reached.
   */
  private fun connectedHero(net: String): Hero {
    val list = peers
      ?: return Hero(getString(R.string.state_connecting), getString(R.string.state_connecting_detail), Tone.BUSY,
        R.string.main_disconnect)
    val targets = summary?.summary?.peers.orEmpty()
    val others = list.filter { !it.self }
    val linked = others.filter { it.reachable }
    if (linked.isNotEmpty()) {
      val main = linked.firstOrNull { it.name in targets } ?: linked.first()
      val transport = Labels.transportName(this, main.transport)
      val detail = if (transport != null) getString(R.string.state_connected_transport_format, main.name, transport)
      else getString(R.string.state_connected_detail_format, main.name)
      return Hero(getString(R.string.state_connected), detail, Tone.ON, R.string.main_disconnect)
    }
    val who = targets.firstOrNull() ?: others.firstOrNull()?.name ?: net
    val waited = SystemClock.elapsedRealtime() - VpnStatus.since()
    val slow = waited >= Join.CONNECT_DEADLINE_S * 1000
    if (!slow) handler.postDelayed(tick, Join.CONNECT_DEADLINE_S * 1000 - waited + 50)
    return Hero(getString(R.string.state_connecting),
      getString(if (slow) R.string.state_searching_slow_format else R.string.state_searching_format, who),
      Tone.BUSY, R.string.main_disconnect, showLog = slow)
  }

  @ColorInt
  private fun attr(@AttrRes id: Int): Int = MaterialColors.getColor(binding.root, id)

  // ---- settings rows ---------------------------------------------------------

  private fun setupRows() {
    binding.addressRow.setup(R.drawable.ic_phone, R.string.main_address_label, chevron = false) { copyAddress() }
    binding.peersRow.setup(R.drawable.ic_peers, R.string.main_peers_label) {
      selected?.let { startActivity(PeersActivity.intent(this, it)) }
    }
    binding.transportRow.setup(R.drawable.ic_transport, R.string.setting_transport_title) { showTransportDialog() }
    binding.appsRow.setup(R.drawable.ic_apps, R.string.setting_apps_title) {
      selected?.let { appPicker.launch(AppPickerActivity.intent(this, it)) }
    }
    binding.screenOffRow.setup(R.drawable.ic_lock, R.string.setting_screen_off_title, chevron = false) { togglePauseOnLock() }
    binding.screenOffRow.rowSwitch.isVisible = true
    binding.screenOffRow.rowSummary.setText(R.string.setting_screen_off_summary)
    binding.logRow.setup(R.drawable.ic_log, R.string.setting_log_title) { openLog() }
    binding.logRow.rowSummary.setText(R.string.setting_log_summary)
  }

  private fun RowItemBinding.setup(icon: Int, title: Int, chevron: Boolean = true, onClick: () -> Unit) {
    rowIcon.setImageResource(icon)
    rowTitle.setText(title)
    rowChevron.isVisible = chevron
    root.setOnClickListener { onClick() }
  }

  private fun loadSettings() {
    val net = selected ?: return
    summary = try {
      val yaml = TincYaml(AppPaths.tincYamlFile(net))
      val s = Networks.summary(net)
      NetworkSettings(
        summary = s,
        transport = Transport.preferred(yaml, s.stanza),
        accepted = Transport.acceptedByPeers(yaml, s.stanza),
        routing = try {
          SplitRouting.read(yaml, s.stanza)
        } catch (e: Exception) {
          null
        },
        pauseOnLock = TincYaml.asTincBoolean(yaml.optionValue(s.stanza, VpnInterfaceConfiguration.KEY_DISCONNECT_ON_SCREEN_OFF), false),
      )
    } catch (e: Exception) {
      log.warn("Could not read the settings of {}: {}", net, e.defaultMessage())
      null
    }
    render()
  }

  private fun renderRows() {
    val s = summary
    val address = s?.summary?.address
    binding.addressRow.rowSummary.text = listOfNotNull(s?.summary?.nodeName, address ?: getString(R.string.main_address_none))
      .joinToString("  ·  ")

    val list = peers?.filter { !it.self }
    binding.peersRow.rowSummary.text = when {
      list != null && list.isNotEmpty() -> getString(R.string.main_peers_count_format, list.count { it.reachable }, list.size)
      !s?.summary?.peers.isNullOrEmpty() -> s!!.summary.peers.joinToString(", ")
      else -> getString(R.string.peers_not_connected)
    }

    binding.transportRow.rowSummary.setText(Labels.transportName(s?.transport ?: Transport.PLAIN))

    val routing = s?.routing
    binding.appsRow.rowSummary.text = when {
      routing == null || routing.apps.isEmpty() -> getString(R.string.apps_summary_all)
      routing.mode == SplitRoutingMode.WHITELIST ->
        resources.getQuantityString(R.plurals.apps_summary_only, routing.apps.size, routing.apps.size)

      else -> resources.getQuantityString(R.plurals.apps_summary_except, routing.apps.size, routing.apps.size)
    }

    binding.screenOffRow.rowSwitch.isChecked = s?.pauseOnLock == true
  }

  private fun copyAddress() {
    val address = summary?.summary?.address ?: return
    (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText(address, address))
    // Android 13+ shows its own confirmation
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) notify(getString(R.string.address_copied_format, address))
  }

  /** A setting of the running network changed: it applies from the next connection. */
  private fun notifyApplies(message: String) {
    val net = selected ?: return
    if (status.active && status.netName == net)
      notify(message + " " + getString(R.string.applies_on_reconnect), R.string.action_reconnect) { TincVpnService.connect(net) }
    else notify(message)
  }

  private fun notifyApplies(message: Int) = notifyApplies(getString(message))

  private fun writeOption(apply: (TincYaml, String) -> Unit, message: String) {
    val net = selected ?: return
    val stanza = summary?.summary?.stanza ?: return
    Executor.runAsyncTask { apply(TincYaml(AppPaths.tincYamlFile(net)), stanza) }
      .thenAccept { runOnUiThread { loadSettings(); notifyApplies(message) } }
      .exceptionallyAccept { e ->
        runOnUiThread { notify(getString(R.string.apps_error_write_format, e.cause?.defaultMessage() ?: e.defaultMessage())) }
      }
  }

  private fun togglePauseOnLock() {
    val on = summary?.pauseOnLock != true
    binding.screenOffRow.rowSwitch.isChecked = on
    writeOption({ yaml, stanza ->
      // absent means off: the key is written only when on
      yaml.setOptions(stanza, mapOf(VpnInterfaceConfiguration.KEY_DISCONNECT_ON_SCREEN_OFF to if (on) listOf("yes") else null))
    }, getString(R.string.apps_saved))
  }

  private fun showTransportDialog() {
    val s = summary ?: return
    val current = s.transport ?: Transport.PLAIN
    val offeredBy = s.summary.peers.joinToString(", ").ifEmpty { selected.orEmpty() }
    val content = layoutInflater.inflate(R.layout.dialog_transport, null) as android.view.ViewGroup
    val list = content.findViewById<android.widget.LinearLayout>(R.id.transport_list)
    lateinit var dialog: androidx.appcompat.app.AlertDialog
    Transport.values().forEach { t ->
      val item = TransportItemBinding.inflate(layoutInflater, list, false)
      val offered = t in s.accepted
      item.transportRadio.isChecked = t == current
      item.transportName.setText(Labels.transportName(t))
      item.transportDesc.text = if (offered) getString(Labels.transportDescription(t))
      else getString(R.string.transport_not_offered_format, offeredBy)
      item.root.isEnabled = offered
      item.transportRadio.isEnabled = offered
      item.transportName.isEnabled = offered
      item.transportDesc.isEnabled = offered
      item.root.alpha = if (offered) 1f else 0.5f
      if (offered) item.root.setOnClickListener {
        dialog.dismiss()
        if (t != current) writeOption({ yaml, stanza -> Transport.setPreferred(yaml, stanza, t.takeIf { it != Transport.PLAIN }) },
          getString(R.string.transport_set_format, getString(Labels.transportName(t))))
      }
      list.addView(item.root)
    }
    dialog = MaterialAlertDialogBuilder(this)
      .setTitle(R.string.setting_transport_title)
      .setView(content)
      .setNegativeButton(R.string.action_cancel, null)
      .show()
  }

  private fun openLog() {
    startActivity(LogActivity.intent(this, selected))
  }

  private fun showCrashDialog() {
    MaterialAlertDialogBuilder(this)
      .setIcon(R.drawable.ic_error)
      .setTitle(R.string.crash_title)
      .setMessage(R.string.crash_message)
      .setNegativeButton(R.string.action_dismiss) { _, _ -> CrashRecorder.dismissPreviousCrash() }
      .setPositiveButton(R.string.action_view_log) { _, _ ->
        CrashRecorder.dismissPreviousCrash()
        startActivity(LogActivity.intent(this, null, app = true))
      }
      .setCancelable(false)
      .show()
  }

  companion object {
    private const val PREFS = "ui"
    private const val PREF_SELECTED = "selected_network"
    private const val PREF_ASKED_NOTIFICATIONS = "asked_notifications"
    private const val STATE_PENDING_CONNECT = "pending_connect"
  }
}
