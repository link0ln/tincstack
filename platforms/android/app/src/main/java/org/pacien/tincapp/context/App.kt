/*
 * tincstack for Android
 * Copyright (C) 2017-2020 Euxane P. TRAN-GIRARD
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

package org.pacien.tincapp.context

import android.app.Application
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import com.google.android.material.color.DynamicColors
import org.pacien.tincapp.BuildConfig
import org.pacien.tincapp.R
import org.pacien.tincapp.commands.Join
import org.pacien.tincapp.data.Networks
import org.pacien.tincapp.service.ConnectionState
import org.pacien.tincapp.service.TincVpnService
import org.pacien.tincapp.service.VpnStatus
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * @author euxane
 */
class App : Application() {
  override fun onCreate() {
    super.onCreate()
    appContext = applicationContext
    AppLogger.configure()

    val logger = LoggerFactory.getLogger(this.javaClass)
    setupCrashHandler(logger)

    logger.info("Starting tincstack {} ({} build), running on Android {} (API {})",
      BuildConfig.VERSION_NAME, BuildConfig.BUILD_TYPE, Build.VERSION.RELEASE, Build.VERSION.SDK_INT)

    // Material You: the wallpaper's palette on Android 12+, the app's own below.
    DynamicColors.applyToActivitiesIfAvailable(this)

    // A join the process did not live to finish, and network directories left
    // behind by earlier versions without a tinc.yaml, are not networks.
    Join.sweepStaging()
    Networks.sweepBroken()

    // A session is recorded until it ends; one still recorded in a fresh
    // process ended with the process (a crash, or Android killing the app).
    // Say so instead of showing a plain "Disconnected". An always-on restart
    // replaces this with Connecting a moment later.
    TincVpnService.getCurrentNetName()?.let { net ->
      if (VpnStatus.current() !is ConnectionState.Failed)
        VpnStatus.set(ConnectionState.Failed(net, getString(R.string.error_process_died), lost = true))
    }
  }

  private fun setupCrashHandler(logger: Logger) {
    val systemCrashHandler = Thread.getDefaultUncaughtExceptionHandler()!!
    val crashRecorder = CrashRecorder(logger, systemCrashHandler)
    Thread.setDefaultUncaughtExceptionHandler(crashRecorder)
  }

  companion object {
    private var appContext: Context? = null

    fun getContext() = appContext!!
    fun getResources() = getContext().resources!!

    fun getApplicationInfo(): ApplicationInfo =
      getContext()
        .packageManager
        .getApplicationInfo(BuildConfig.APPLICATION_ID, 0)
  }
}
