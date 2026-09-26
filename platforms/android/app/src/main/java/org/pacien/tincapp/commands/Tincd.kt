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

package org.pacien.tincapp.commands

import java8.util.concurrent.CompletableFuture
import org.pacien.tincapp.context.AppPaths
import java.io.File
import java.io.RandomAccessFile

/**
 * The daemon, started in YAML mode (`-c <net>/tinc.yaml -n <stanza>`): it reads
 * and writes the one config file itself, including materialising keys and
 * defaults into it on first start.
 *
 * @author euxane
 */
object Tincd {
  /**
   * Connections, errors and status messages from peers (DEBUG_STATUS): what
   * the in-app log needs to explain a connection that does not come up,
   * without the per-packet chatter of higher levels.
   */
  private const val LOG_LEVEL = 2

  /** The log file is appended to by every launch; above this it is cut back to its tail. */
  private const val LOG_MAX_BYTES = 1L shl 20

  fun start(netName: String, stanza: String, device: String): CompletableFuture<Unit> {
    trimLog(AppPaths.logFile(netName))
    return Executor.call(Command(AppPaths.tincd().absolutePath)
      .withOption("no-detach")
      .withOption("debug", LOG_LEVEL.toString())
      .withOption("config", AppPaths.tincYamlFile(netName).absolutePath)
      .withOption("net", stanza)
      .withOption("pidfile", AppPaths.pidFile(netName).absolutePath)
      .withOption("logfile", AppPaths.logFile(netName).absolutePath)
      .withOption("option", "DeviceType=fd")
      .withOption("option", "Device=@$device")
    ).thenApply { }
  }

  private fun trimLog(log: File) {
    try {
      if (log.length() <= LOG_MAX_BYTES) return
      val keep = RandomAccessFile(log, "r").use { f ->
        f.seek(log.length() - LOG_MAX_BYTES / 2)
        ByteArray((LOG_MAX_BYTES / 2).toInt()).also { f.readFully(it) }
      }
      log.writeBytes(keep)
    } catch (e: Exception) {
      log.delete()
    }
  }
}
