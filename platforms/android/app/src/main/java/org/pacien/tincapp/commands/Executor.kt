/*
 * Tinc Mesh VPN: Android client and user interface
 * Copyright (C) 2017-2020 Euxane P. TRAN-GIRARD
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

import android.os.Build
import java8.util.concurrent.CompletableFuture
import java8.util.function.Supplier
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.pacien.tincapp.context.AppPaths

/**
 * @author euxane
 */
internal object Executor {
  class CommandExecutionException(msg: String) : Exception(msg)

  private const val CONTROL_TIMEOUT_MS = 10_000L

  private val ioThreadSeq = AtomicInteger(0)
  private val cmdThreadSeq = AtomicInteger(0)

  private val ioPool = ThreadPoolExecutor(
    2,
    16,
    60L,
    TimeUnit.SECONDS,
    LinkedBlockingQueue(256),
  ) { r ->
    Thread(r, "tinc-io-${ioThreadSeq.incrementAndGet()}").apply { isDaemon = true }
  }.apply { allowCoreThreadTimeOut(true) }

  private val cmdPool = ThreadPoolExecutor(
    2,
    8,
    30L,
    TimeUnit.SECONDS,
    ArrayBlockingQueue(64),
  ) { r ->
    Thread(r, "tinc-ctl-${cmdThreadSeq.incrementAndGet()}").apply { isDaemon = true }
  }.apply { allowCoreThreadTimeOut(true) }

  private fun read(stream: InputStream): List<String> =
    stream.bufferedReader().use { it.readLines() }

  /**
   * API 21–25 compatible replacement for [Process.waitFor] with timeout
   * (`Process.waitFor(long, TimeUnit)` was added in Android API 26).
   */
  fun waitForProcess(process: Process, timeoutMs: Long): Boolean {
    val safeTimeoutMs = timeoutMs.coerceAtLeast(0L)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      return process.waitFor(safeTimeoutMs, TimeUnit.MILLISECONDS)
    }
    val deadlineNs = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(safeTimeoutMs)
    while (true) {
      try {
        process.exitValue()
        return true
      } catch (_: IllegalThreadStateException) {
        val remNs = deadlineNs - System.nanoTime()
        if (remNs <= 0L) return false
        val sleepMs = (remNs / 1_000_000L).coerceIn(1L, 25L)
        Thread.sleep(sleepMs)
      }
    }
  }

  /**
   * API 21–25 compatible replacement for [Process.destroyForcibly]
   * (`Process.destroyForcibly()` was added in Android API 26).
   */
  fun destroyProcessForcibly(process: Process) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      try {
        process.destroyForcibly()
        return
      } catch (_: Throwable) {
      }
    }
    try {
      process.destroy()
    } catch (_: Throwable) {
    }
  }

  /**
   * The core calls tmpfile(3) when it serialises keys into the YAML (see
   * zeroconf.c / yamlconf_content_fp). Bionic's tmpfile() honours $TMPDIR and
   * otherwise falls back to /data/local/tmp, which an app sandbox cannot
   * write: without this the very first `tinc join` dies with "Could not
   * serialise Ed25519 private key". Point it at our own runtime dir instead.
   */
  fun run(cmd: Command): Process = try {
    ProcessBuilder(cmd.asList())
      .also { it.environment()["TMPDIR"] = AppPaths.runtimeDir().absolutePath }
      .start()
  } catch (e: IOException) {
    throw CommandExecutionException(e.message ?: "Could not start process.")
  }

  fun call(cmd: Command): CompletableFuture<List<String>> =
    CompletableFuture.supplyAsync(Supplier {
      val process = run(cmd)
      try {
        try {
          process.outputStream.close()
        } catch (_: Exception) {
        }
        var outLines: List<String> = emptyList()
        var errLines: List<String> = emptyList()
        val outThread = Thread({
          try {
            outLines = read(process.inputStream)
          } catch (_: Exception) {
          }
        }, "tinc-ctl-out").apply { isDaemon = true; start() }
        val errThread = Thread({
          try {
            errLines = read(process.errorStream)
          } catch (_: Exception) {
          }
        }, "tinc-ctl-err").apply { isDaemon = true; start() }

        val finished = waitForProcess(process, CONTROL_TIMEOUT_MS)
        if (!finished) {
          destroyProcessForcibly(process)
          closeStreamsQuietly(process)
          outThread.join(500L)
          errThread.join(500L)
          throw CommandExecutionException("Control command timed out after ${CONTROL_TIMEOUT_MS / 1000}s.")
        }
        outThread.join(1_000L)
        errThread.join(1_000L)
        val exitCode = process.exitValue()
        if (exitCode == 0) outLines
        else throw CommandExecutionException(errLines.lastOrNull() ?: "Non-zero exit status ($exitCode).")
      } finally {
        closeStreamsQuietly(process)
      }
    }, cmdPool)!!

  private fun closeStreamsQuietly(process: Process) {
    try {
      process.inputStream.close()
    } catch (_: Exception) {
    }
    try {
      process.errorStream.close()
    } catch (_: Exception) {
    }
    try {
      process.outputStream.close()
    } catch (_: Exception) {
    }
  }

  fun runAsyncTask(r: () -> Unit) = CompletableFuture.supplyAsync(Supplier(r), ioPool)!!
  fun <U> supplyAsyncTask(s: () -> U) = CompletableFuture.supplyAsync(Supplier(s), ioPool)!!
}
