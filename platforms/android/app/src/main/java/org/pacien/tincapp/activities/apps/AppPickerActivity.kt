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

package org.pacien.tincapp.activities.apps

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.core.view.isVisible
import androidx.core.widget.doAfterTextChanged
import org.pacien.tincapp.BuildConfig
import org.pacien.tincapp.R
import org.pacien.tincapp.activities.BaseActivity
import org.pacien.tincapp.commands.Executor
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.data.SplitRouting
import org.pacien.tincapp.data.SplitRoutingMode
import org.pacien.tincapp.data.TincYaml
import org.pacien.tincapp.databinding.AppsPickerActivityBinding
import org.pacien.tincapp.extensions.Java.defaultMessage
import org.pacien.tincapp.extensions.Java.exceptionallyAccept

/**
 * Per-app split routing of one network: all apps (no key), only the ticked
 * ones (`AllowApplication`), or all but the ticked ones
 * (`DisallowApplication`). Exactly one key is ever written ([SplitRouting]);
 * the ticks are kept while switching modes. Save writes the network's
 * tinc.yaml and returns RESULT_OK; the change applies at the next connection.
 */
class AppPickerActivity : BaseActivity() {
  private val netName by lazy { intent.getStringExtra(EXTRA_NET_NAME)!! }
  private val yaml by lazy { TincYaml(AppPaths.tincYamlFile(netName)) }
  private lateinit var binding: AppsPickerActivityBinding
  private val adapter by lazy { InstalledAppsAdapter(this) }
  private var loaded = false
  override val snackbarRoot: View get() = binding.appsRoot

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    binding = AppsPickerActivityBinding.inflate(layoutInflater)
    setContentView(binding.root)
    setupToolbar(binding.toolbar, up = true)
    supportActionBar?.subtitle = netName

    binding.appsList.adapter = adapter
    binding.appsList.setOnItemClickListener { _, _, position, _ -> adapter.toggle(position) }
    binding.appsSearch.doAfterTextChanged { adapter.filter.filter(it?.toString()) }
    binding.appsMode.setOnCheckedChangeListener { _, _ -> renderMode() }
    load()
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.menu_apps_picker, menu)
    return true
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean = when (item.itemId) {
    R.id.apps_picker_save -> {
      save(); true
    }

    else -> super.onOptionsItemSelected(item)
  }

  private fun mode(): SplitRoutingMode? = when (binding.appsMode.checkedRadioButtonId) {
    R.id.apps_mode_whitelist -> SplitRoutingMode.WHITELIST
    R.id.apps_mode_blacklist -> SplitRoutingMode.BLACKLIST
    else -> null
  }

  private fun renderMode() {
    val mode = mode()
    binding.appsModeHint.setText(when (mode) {
      SplitRoutingMode.WHITELIST -> R.string.apps_mode_whitelist_hint
      SplitRoutingMode.BLACKLIST -> R.string.apps_mode_blacklist_hint
      null -> R.string.apps_mode_all_hint
    })
    binding.appsSearchLayout.isVisible = mode != null
    binding.appsList.isVisible = mode != null && loaded
  }

  private fun load() {
    binding.appsProgress.isVisible = true
    Executor.supplyAsyncTask {
      val current = try {
        SplitRouting.read(yaml, yaml.resolveNetwork(netName))
      } catch (e: TincYaml.InvalidConfigurationException) {
        // both keys set: the service refuses such a network; saving here repairs it
        runOnUiThread { notify(getString(R.string.apps_error_read_format, e.defaultMessage())) }
        null
      }
      current to installedApps()
    }.thenAccept { (current, apps) ->
      runOnUiThread {
        loaded = true
        binding.appsProgress.isVisible = false
        binding.appsMode.check(when {
          current == null || current.apps.isEmpty() -> R.id.apps_mode_all
          current.mode == SplitRoutingMode.WHITELIST -> R.id.apps_mode_whitelist
          else -> R.id.apps_mode_blacklist
        })
        adapter.setApps(apps, current?.apps.orEmpty())
        renderMode()
      }
    }.exceptionallyAccept { e ->
      runOnUiThread {
        binding.appsProgress.isVisible = false
        notify(getString(R.string.apps_error_read_format, e.cause?.defaultMessage() ?: e.defaultMessage()))
      }
    }
  }

  /** Every installed app but this one (the VPN app always bypasses its own tunnel). */
  private fun installedApps(): List<InstalledApp> {
    val pm = packageManager
    return pm.getInstalledApplications(0)
      .filter { it.packageName != BuildConfig.APPLICATION_ID }
      .map { InstalledApp(it.packageName, pm.getApplicationLabel(it).toString(), it.flags and ApplicationInfo.FLAG_SYSTEM != 0) }
      .sortedWith(compareBy({ it.system }, { it.label.lowercase() }))
  }

  private fun save() {
    if (!loaded) return
    // "all apps" is no key at all: an empty selection in either mode
    val selection = SplitRouting(mode() ?: SplitRoutingMode.WHITELIST, if (mode() == null) emptySet() else adapter.selected())
    Executor.runAsyncTask { selection.write(yaml, yaml.resolveNetwork(netName)) }
      .thenAccept { runOnUiThread { setResult(RESULT_OK); finish() } }
      .exceptionallyAccept { e ->
        runOnUiThread { notify(getString(R.string.apps_error_write_format, e.cause?.defaultMessage() ?: e.defaultMessage())) }
      }
  }

  companion object {
    private const val EXTRA_NET_NAME = "netName"

    fun intent(context: Context, netName: String): Intent =
      Intent(context, AppPickerActivity::class.java).putExtra(EXTRA_NET_NAME, netName)
  }
}
