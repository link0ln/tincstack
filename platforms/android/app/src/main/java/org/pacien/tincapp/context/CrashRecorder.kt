/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2018 Euxane P. TRAN-GIRARD
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

import org.slf4j.Logger
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * @author euxane
 */
class CrashRecorder(
  private val logger: Logger,
  private val upstreamCrashHandler: Thread.UncaughtExceptionHandler?,
) : Thread.UncaughtExceptionHandler {

  companion object {
    private const val MAX_CRASH_LOG_BYTES = 512L * 1024L

    private fun flagFile() = AppPaths.crashFlagFile()
    private fun crashLogFile() = AppPaths.crashLogFile()

    fun hasPreviouslyCrashed() = try {
      flagFile().exists()
    } catch (_: Exception) {
      false
    }

    fun flagCrash() {
      try {
        flagFile().apply { if (!exists()) createNewFile() }
      } catch (_: Exception) {
      }
    }

    fun dismissPreviousCrash() {
      try {
        flagFile().delete()
      } catch (_: Exception) {
      }
    }

    fun clearCrashLog() {
      dismissPreviousCrash()
      try {
        crashLogFile().delete()
      } catch (_: Exception) {
      }
    }

    private fun appendCrashDetails(thread: Thread, throwable: Throwable) {
      try {
        val file = crashLogFile()
        file.parentFile?.mkdirs()
        val append = file.isFile && file.length() < MAX_CRASH_LOG_BYTES
        val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(Date())
        val entry = "$ts [${thread.name}] Fatal application error:\n${throwable.stackTraceToString()}\n"
        FileOutputStream(file, append).use { out ->
          out.write(entry.toByteArray(StandardCharsets.UTF_8))
        }
      } catch (_: Exception) {
      }
    }
  }

  override fun uncaughtException(thread: Thread, throwable: Throwable) {
    logger.error("Fatal application error.", throwable)
    appendCrashDetails(thread, throwable)
    flagCrash()
    upstreamCrashHandler?.uncaughtException(thread, throwable)
  }
}
