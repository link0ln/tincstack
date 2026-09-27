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

package org.pacien.tincapp.activities.join

import android.content.Intent
import android.os.Bundle
import android.view.View
import org.pacien.tincapp.activities.BaseActivity
import org.pacien.tincapp.activities.main.MainActivity
import org.pacien.tincapp.databinding.ActivityJoinBinding
import org.pacien.tincapp.intent.Actions

/**
 * "Add a network" once there is one already (the first one is joined from
 * the main screen itself). Also the target of text shared to the app: an
 * invitation sent in a messenger can be shared straight here.
 *
 * On success the main screen takes over and connects the new network.
 */
class JoinActivity : BaseActivity() {
  private lateinit var binding: ActivityJoinBinding
  private lateinit var panel: JoinPanel
  override val snackbarRoot: View get() = binding.joinRoot

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    binding = ActivityJoinBinding.inflate(layoutInflater)
    setContentView(binding.root)
    setupToolbar(binding.toolbar, up = true)
    binding.joinPanel.joinTitle.visibility = View.GONE
    panel = JoinPanel(this, binding.joinPanel, this) { net ->
      startActivity(Intent(this, MainActivity::class.java)
        .setAction(Actions.ACTION_CONNECT)
        .setData(Actions.buildNetworkUri(net))
        .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
      finish()
    }
    if (savedInstanceState == null && intent?.action == Intent.ACTION_SEND)
      panel.prefill(intent.getStringExtra(Intent.EXTRA_TEXT))
  }

  override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    panel.onWindowFocusChanged(hasFocus)
  }

  @Deprecated("zxing's IntentIntegrator still reports through onActivityResult")
  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    if (!panel.onActivityResult(requestCode, resultCode, data))
      @Suppress("DEPRECATION") super.onActivityResult(requestCode, resultCode, data)
  }
}
