/*
 * Tinc Mesh VPN: Android client and user interface
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

package org.pacien.tincapp.activities.apps

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import androidx.core.widget.doAfterTextChanged
import org.pacien.tincapp.BuildConfig
import org.pacien.tincapp.R
import org.pacien.tincapp.activities.BaseActivity
import org.pacien.tincapp.commands.Executor
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.data.SplitRouting
import org.pacien.tincapp.data.SplitRoutingMode
import org.pacien.tincapp.data.TincYaml
import org.pacien.tincapp.data.VpnInterfaceConfiguration
import org.pacien.tincapp.databinding.AppsPickerActivityBinding
import org.pacien.tincapp.extensions.Java.defaultMessage
import org.pacien.tincapp.extensions.Java.exceptionallyAccept
import org.pacien.tincapp.service.TincVpnService

/**
 * Per-app split routing of one network: which installed apps use the tunnel.
 *
 * One mode switch (whitelist: only the ticked apps use the VPN / blacklist: every
 * app except the ticked ones), a search box and a multi-select list. Saving
 * writes exactly one of `AllowApplication` / `DisallowApplication` into the
 * network's `tinc.yaml` (see [SplitRouting]); the change applies at the next
 * connection of that network.
 */
class AppPickerActivity : BaseActivity() {
  private val netName by lazy { intent.getStringExtra(EXTRA_NET_NAME)!! }
  private val yaml by lazy { TincYaml(AppPaths.tincYamlFile(netName)) }
  private val stanza by lazy { yaml.resolveNetwork(netName) }
  private val binding by lazy { AppsPickerActivityBinding.inflate(layoutInflater) }
  private val adapter by lazy { InstalledAppsAdapter(this) }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    supportActionBar.setDisplayHomeAsUpEnabled(true)
    supportActionBar.subtitle = netName
    setContentView(binding.root)

    binding.appsList.adapter = adapter
    binding.appsList.setOnItemClickListener { _, _, position, _ -> adapter.toggle(position) }
    binding.appsSearch.doAfterTextChanged { adapter.filter.filter(it?.toString()) }
    binding.appsMode.setOnCheckedChangeListener { _, id -> updateModeHint(id) }

    load()
  }

  override fun onCreateOptionsMenu(m: Menu): Boolean {
    menuInflater.inflate(R.menu.menu_apps_picker, m)
    return super.onCreateOptionsMenu(m)
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean = when (item.itemId) {
    android.R.id.home -> { finish(); true }
    else -> super.onOptionsItemSelected(item)
  }

  private fun currentMode() =
    if (binding.appsMode.checkedRadioButtonId == R.id.apps_mode_whitelist) SplitRoutingMode.WHITELIST
    else SplitRoutingMode.BLACKLIST

  private fun updateModeHint(checkedId: Int) {
    binding.appsModeHint.setText(
      if (checkedId == R.id.apps_mode_whitelist) R.string.apps_picker_mode_whitelist_hint
      else R.string.apps_picker_mode_blacklist_hint)
  }

  private fun load() {
    binding.appsProgress.visibility = android.view.View.VISIBLE
    Executor.supplyAsyncTask {
      val current = SplitRouting.read(yaml, stanza)
      val lockPause = TincYaml.asTincBoolean(yaml.optionValue(stanza, VpnInterfaceConfiguration.KEY_DISCONNECT_ON_SCREEN_OFF), false)
      val apps = installedApps()
      Triple(current, lockPause, apps)
    }.thenAccept { (current, lockPause, apps) ->
      runOnUiThread {
        binding.appsDisconnectOnScreenOff.isChecked = lockPause
        binding.appsProgress.visibility = android.view.View.GONE
        binding.appsMode.check(
          if (current.mode == SplitRoutingMode.WHITELIST) R.id.apps_mode_whitelist else R.id.apps_mode_blacklist)
        updateModeHint(binding.appsMode.checkedRadioButtonId)
        adapter.setApps(apps, current.apps)
      }
    }.exceptionallyAccept { e ->
      runOnUiThread {
        binding.appsProgress.visibility = android.view.View.GONE
        showErrorDialog(getString(R.string.apps_picker_error_read_format, e.cause?.defaultMessage() ?: e.defaultMessage()))
      }
    }
  }

  /** Every launchable-or-not installed app but this one (the VPN app always bypasses its own tunnel). */
  private fun installedApps(): List<InstalledApp> {
    val pm = packageManager
    return pm.getInstalledApplications(0)
      .filter { it.packageName != BuildConfig.APPLICATION_ID }
      .map { InstalledApp(it.packageName, pm.getApplicationLabel(it).toString(), it.flags and ApplicationInfo.FLAG_SYSTEM != 0) }
      .sortedWith(compareBy({ it.system }, { it.label.lowercase() }))
  }

  @Suppress("UNUSED_PARAMETER")
  fun save(m: MenuItem) {
    val selection = SplitRouting(currentMode(), adapter.selected())
    // absent means off: the key is written only when on
    val lockPause = if (binding.appsDisconnectOnScreenOff.isChecked) listOf("yes") else null
    Executor.runAsyncTask {
      selection.write(yaml, stanza)
      yaml.setOptions(stanza, mapOf(VpnInterfaceConfiguration.KEY_DISCONNECT_ON_SCREEN_OFF to lockPause))
    }
      .thenAccept {
        runOnUiThread {
          notify(if (TincVpnService.getCurrentNetName() == netName && TincVpnService.isConnected())
            R.string.apps_picker_saved_reconnect else R.string.apps_picker_saved)
          finish()
        }
      }
      .exceptionallyAccept { e ->
        runOnUiThread { showErrorDialog(getString(R.string.apps_picker_error_write_format, e.cause?.defaultMessage() ?: e.defaultMessage())) }
      }
  }

  companion object {
    private const val EXTRA_NET_NAME = "netName"

    fun intent(context: Context, netName: String): Intent =
      Intent(context, AppPickerActivity::class.java).putExtra(EXTRA_NET_NAME, netName)
  }
}
