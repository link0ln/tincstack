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

import android.os.AsyncTask
import java8.util.concurrent.CompletableFuture
import java8.util.function.Supplier
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import org.pacien.tincapp.context.AppPaths

/**
 * @author euxane
 */
internal object Executor {
  class CommandExecutionException(msg: String) : Exception(msg)

  private fun read(stream: InputStream) = BufferedReader(InputStreamReader(stream)).readLines()

  /**
   * The core calls tmpfile(3) when it serialises keys into the YAML (see
   * zeroconf.c / yamlconf_content_fp). Bionic's tmpfile() honours $TMPDIR and
   * otherwise falls back to /data/local/tmp, which an app sandbox cannot
   * write: without this the very first `tinc join` dies with "Could not
   * serialise Ed25519 private key". Point it at our own cache instead.
   */
  fun run(cmd: Command): Process = try {
    ProcessBuilder(cmd.asList())
      .also { it.environment()["TMPDIR"] = AppPaths.runtimeDir().absolutePath }
      .start()
  } catch (e: IOException) {
    throw CommandExecutionException(e.message ?: "Could not start process.")
  }

  fun call(cmd: Command): CompletableFuture<List<String>> = run(cmd).let { process ->
    supplyAsyncTask<List<String>> {
      val exitCode = process.waitFor()
      if (exitCode == 0) read(process.inputStream)
      else throw CommandExecutionException(read(process.errorStream).lastOrNull() ?: "Non-zero exit status ($exitCode).")
    }
  }

  fun runAsyncTask(r: () -> Unit) = CompletableFuture.supplyAsync(Supplier(r), AsyncTask.THREAD_POOL_EXECUTOR)!!
  fun <U> supplyAsyncTask(s: () -> U) = CompletableFuture.supplyAsync(Supplier(s), AsyncTask.THREAD_POOL_EXECUTOR)!!
}
