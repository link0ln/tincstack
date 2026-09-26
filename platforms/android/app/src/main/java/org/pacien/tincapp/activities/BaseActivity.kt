/*
 * tincstack for Android
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

package org.pacien.tincapp.activities

import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import org.pacien.tincapp.BuildConfig
import org.pacien.tincapp.R

/**
 * Common plumbing: the Material toolbar as the action bar, snackbars, the
 * about dialog.
 *
 * @author euxane
 */
abstract class BaseActivity : AppCompatActivity() {
  /** The view snackbars attach to (the screen's CoordinatorLayout). */
  protected abstract val snackbarRoot: View

  protected fun setupToolbar(toolbar: MaterialToolbar, up: Boolean) {
    setSupportActionBar(toolbar)
    supportActionBar?.setDisplayHomeAsUpEnabled(up)
    if (up) toolbar.setNavigationOnClickListener { onBackPressedDispatcher.onBackPressed() }
  }

  fun notify(msg: CharSequence, actionLabel: Int? = null, action: (() -> Unit)? = null) {
    Snackbar.make(snackbarRoot, msg, Snackbar.LENGTH_LONG)
      .apply { if (actionLabel != null && action != null) setAction(actionLabel) { action() } }
      .show()
  }

  fun notify(msg: Int, actionLabel: Int? = null, action: (() -> Unit)? = null) =
    notify(getString(msg), actionLabel, action)

  fun showAbout() {
    MaterialAlertDialogBuilder(this)
      .setIcon(R.drawable.ic_mark)
      .setTitle(R.string.app_name)
      .setMessage(getString(R.string.about_text_format, "${BuildConfig.VERSION_NAME} (${BuildConfig.BUILD_TYPE})"))
      .setPositiveButton(R.string.action_close, null)
      .show()
  }
}
