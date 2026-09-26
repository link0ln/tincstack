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

package org.pacien.tincapp.activities.log

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.core.view.isVisible
import org.pacien.tincapp.R
import org.pacien.tincapp.activities.BaseActivity
import org.pacien.tincapp.activities.common.ChangeOnlyLiveData
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.databinding.ActivityLogBinding
import org.pacien.tincapp.utils.lastLines
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * The log, read from its file: tincd's own log of the network (what it
 * tried, which peer refused what) and the app's. Re-read only when the file
 * changed; follows the tail unless the user scrolled up.
 */
class LogActivity : BaseActivity() {
  private lateinit var binding: ActivityLogBinding
  override val snackbarRoot: View get() = binding.logRoot
  private val netName by lazy { intent.getStringExtra(EXTRA_NET_NAME) }
  private var source: LogFileLiveData? = null
  private var text: String = ""

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    binding = ActivityLogBinding.inflate(layoutInflater)
    setContentView(binding.root)
    setupToolbar(binding.toolbar, up = true)

    val net = netName
    binding.logSourceConnection.isVisible = net != null
    binding.logSource.addOnButtonCheckedListener { _, id, checked -> if (checked) show(id) }
    val initial = when {
      net == null || intent.getBooleanExtra(EXTRA_APP, false) -> R.id.log_source_app
      else -> R.id.log_source_connection
    }
    binding.logSource.check(savedInstanceState?.getInt(STATE_SOURCE)?.takeIf { it != View.NO_ID } ?: initial)
    // restored already checked: no change, no callback
    if (source == null) show(binding.logSource.checkedButtonId)
  }

  override fun onSaveInstanceState(outState: Bundle) {
    super.onSaveInstanceState(outState)
    outState.putInt(STATE_SOURCE, binding.logSource.checkedButtonId)
  }

  private fun show(id: Int) {
    val file = if (id == R.id.log_source_connection && netName != null) AppPaths.logFile(netName!!) else AppPaths.appLogFile()
    supportActionBar?.subtitle = if (id == R.id.log_source_connection) netName else getString(R.string.log_tab_app)
    source?.removeObservers(this)
    text = ""
    source = LogFileLiveData(file).also { it.observe(this) { t -> render(t) } }
  }

  private fun render(t: String) {
    val atBottom = !binding.logScroll.canScrollVertically(1)
    text = t
    binding.logText.text = t.ifEmpty { getString(R.string.log_empty) }
    if (atBottom) binding.logScroll.post { binding.logScroll.fullScroll(View.FOCUS_DOWN) }
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.menu_log, menu)
    return true
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean = when (item.itemId) {
    R.id.menu_log_copy -> {
      (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText(getString(R.string.log_title), text))
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) notify(R.string.log_copied)
      true
    }

    R.id.menu_log_share -> {
      startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND)
        .setType("text/plain")
        .putExtra(Intent.EXTRA_SUBJECT, "tincstack log" + (supportActionBar?.subtitle?.let { " ($it)" } ?: ""))
        .putExtra(Intent.EXTRA_TEXT, text), null))
      true
    }

    else -> super.onOptionsItemSelected(item)
  }

  private class LogFileLiveData(private val file: File) : ChangeOnlyLiveData<String>(2, TimeUnit.SECONDS) {
    @Volatile private var stamp: Pair<Long, Long>? = null

    override fun onRefresh() {
      val now = file.length() to file.lastModified()
      if (now == stamp) return
      stamp = now
      offer(file.lastLines(MAX_LINES).joinToString("\n"))
    }
  }

  companion object {
    private const val EXTRA_NET_NAME = "netName"
    private const val EXTRA_APP = "app"
    private const val STATE_SOURCE = "source"
    private const val MAX_LINES = 1000

    fun intent(context: Context, netName: String?, app: Boolean = false): Intent =
      Intent(context, LogActivity::class.java).putExtra(EXTRA_NET_NAME, netName).putExtra(EXTRA_APP, app)
  }
}
