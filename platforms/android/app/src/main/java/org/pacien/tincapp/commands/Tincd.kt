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

import android.os.Process as AndroidProcess
import java8.util.concurrent.CompletableFuture
import org.pacien.tincapp.context.AppPaths
import org.slf4j.LoggerFactory
import java.io.File
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets

/**
 * The daemon, started in YAML mode (`-c <net>/tinc.yaml -n <stanza>`): it reads
 * and writes the one config file itself, including materialising keys and
 * defaults into it on first start.
 *
 * @author euxane
 */
object Tincd {
  private val log by lazy { LoggerFactory.getLogger(Tincd::class.java)!! }

  /**
   * Connections, errors and status messages from peers (DEBUG_STATUS): what
   * the in-app log needs to explain a connection that does not come up,
   * without the per-packet chatter of higher levels.
   */
  private const val LOG_LEVEL = 2

  /** The log file is appended to by every launch; above this it is cut back to its tail. */
  private const val LOG_MAX_BYTES = 1L shl 20
  private const val STDERR_RING_CAPACITY = 20

  @Volatile
  private var activeProcess: Process? = null

  /**
   * Terminate any orphaned `libtincd.so` process left running by a previous JVM
   * crash/kill before starting a new daemon for [netName]. Verifies `/proc/<pid>/cmdline`
   * contains both `libtincd.so` and the target network/stanza name to avoid PID-reuse hazards.
   */
  fun terminateOrphanedDaemon(netName: String, stanza: String = netName) {
    val pidFile = try {
      AppPaths.pidFile(netName)
    } catch (_: Exception) {
      return
    }
    if (!pidFile.isFile) return
    val pid = try {
      pidFile.readText(StandardCharsets.UTF_8)
        .lineSequence()
        .firstOrNull()
        ?.trim()
        ?.split(Regex("\\s+"))
        ?.firstOrNull()
        ?.toIntOrNull()
    } catch (_: Exception) {
      null
    }
    if (pid == null || pid <= 1 || pid == AndroidProcess.myPid()) {
      try {
        pidFile.delete()
      } catch (_: Exception) {
      }
      return
    }
    val procDir = File("/proc/$pid")
    val cmdlineFile = File(procDir, "cmdline")
    if (!cmdlineFile.exists()) {
      try {
        pidFile.delete()
      } catch (_: Exception) {
      }
      return
    }
    val cmdline = try {
      val raw = cmdlineFile.readBytes()
      for (i in raw.indices) {
        if (raw[i] == 0.toByte()) raw[i] = ' '.code.toByte()
      }
      String(raw, StandardCharsets.UTF_8)
    } catch (_: Exception) {
      ""
    }
    val matchesTincd = cmdline.contains("libtincd.so") &&
      (cmdline.contains(netName) || cmdline.contains(stanza))
    if (matchesTincd) {
      log.warn("Terminating orphaned libtincd.so process {} for network {}", pid, netName)
      try {
        AndroidProcess.sendSignal(pid, 15 /* SIGTERM */)
      } catch (_: Throwable) {
      }
      val termDeadline = System.nanoTime() + 1_000_000_000L
      while (procDir.exists() && System.nanoTime() < termDeadline) {
        Thread.sleep(25L)
      }
      if (procDir.exists()) {
        try {
          AndroidProcess.killProcess(pid)
        } catch (_: Throwable) {
        }
        val killDeadline = System.nanoTime() + 500_000_000L
        while (procDir.exists() && System.nanoTime() < killDeadline) {
          Thread.sleep(25L)
        }
      }
    }
    if (!procDir.exists()) {
      try {
        pidFile.delete()
      } catch (_: Exception) {
      }
    }
  }

  fun start(netName: String, stanza: String, device: String): CompletableFuture<Unit> {
    terminateOrphanedDaemon(netName, stanza)
    trimLog(AppPaths.logFile(netName))
    val cmd = Command(AppPaths.tincd().absolutePath)
      .withOption("no-detach")
      .withOption("debug", LOG_LEVEL.toString())
      .withOption("config", AppPaths.tincYamlFile(netName).absolutePath)
      .withOption("net", stanza)
      .withOption("pidfile", AppPaths.pidFile(netName).absolutePath)
      .withOption("logfile", AppPaths.logFile(netName).absolutePath)
      .withOption("option", "DeviceType=fd")
      .withOption("option", "Device=@$device")
    val process = Executor.run(cmd)
    activeProcess = process
    try {
      process.outputStream.close()
    } catch (_: Exception) {
    }
    Thread({
      try {
        process.inputStream.use { ins ->
          val buf = ByteArray(1024)
          while (ins.read(buf) >= 0) {
            // drain stdout so pipe never blocks
          }
        }
      } catch (_: Exception) {
      }
    }, "tincd-stdout").apply { isDaemon = true; start() }

    val stderrRing = ArrayDeque<String>(STDERR_RING_CAPACITY)
    val stderrThread = Thread({
      try {
        process.errorStream.bufferedReader().useLines { lines ->
          lines.forEach { line ->
            synchronized(stderrRing) {
              if (stderrRing.size >= STDERR_RING_CAPACITY) stderrRing.removeFirst()
              stderrRing.addLast(line)
            }
          }
        }
      } catch (_: Exception) {
      }
    }, "tincd-stderr").apply { isDaemon = true; start() }

    val exitFuture = CompletableFuture<Unit>()
    Thread({
      try {
        val exitCode = process.waitFor()
        stderrThread.join(1_000L)
        if (exitCode == 0) {
          exitFuture.complete(Unit)
        } else {
          val lastErr = synchronized(stderrRing) { stderrRing.lastOrNull() }
          exitFuture.completeExceptionally(
            Executor.CommandExecutionException(lastErr ?: "Non-zero exit status ($exitCode).")
          )
        }
      } catch (t: Throwable) {
        exitFuture.completeExceptionally(t)
      } finally {
        try {
          process.inputStream.close()
        } catch (_: Exception) {
        }
        try {
          process.errorStream.close()
        } catch (_: Exception) {
        }
        if (activeProcess === process) activeProcess = null
      }
    }, "tincd-wait").apply { isDaemon = true; start() }
    return exitFuture
  }

  fun killForcefully() {
    val p = activeProcess ?: return
    Executor.destroyProcessForcibly(p)
  }

  internal fun trimLog(log: File, maxBytes: Long = LOG_MAX_BYTES) {
    try {
      val len = log.length()
      if (len <= maxBytes) return
      val tailLen = (maxBytes / 2).toInt()
      if (tailLen <= 0) return
      val keep = RandomAccessFile(log, "r").use { f ->
        f.seek(len - tailLen)
        ByteArray(tailLen).also { f.readFully(it) }
      }
      val nlIdx = keep.indexOf('\n'.code.toByte())
      val aligned = if (nlIdx in 0 until keep.size - 1) {
        keep.copyOfRange(nlIdx + 1, keep.size)
      } else {
        var start = 0
        while (start < keep.size && (keep[start].toInt() and 0xC0) == 0x80) start++
        keep.copyOfRange(start, keep.size)
      }
      log.writeBytes(aligned)
    } catch (e: Exception) {
      log.delete()
    }
  }
}
