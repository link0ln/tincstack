/*
 * tincstack for Android
 * Copyright (C) 2017-2018 Euxane P. TRAN-GIRARD
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
import org.pacien.tincapp.data.TincYaml

/**
 * The `tinc` CLI against the network's `tinc.yaml` (YAML mode, same file the
 * daemon uses). Control commands find the running daemon through the pidfile.
 *
 * @author euxane
 */
object Tinc {
  private fun stanza(netName: String) = TincYaml(AppPaths.tincYamlFile(netName)).resolveNetwork(netName)

  private fun configCommand(netName: String): Command =
    Command(AppPaths.tinc().absolutePath)
      .withOption("config", AppPaths.tincYamlFile(netName).absolutePath)
      .withOption("net", stanza(netName))

  private fun newCommand(netName: String): Command =
    configCommand(netName)
      .withOption("pidfile", AppPaths.pidFile(netName).absolutePath)

  fun stop(netName: String): CompletableFuture<Unit> =
    Executor.call(newCommand(netName).withArguments("stop"))
      .thenApply { }

  fun retry(netName: String): CompletableFuture<Unit> =
    Executor.call(newCommand(netName).withArguments("retry"))
      .thenApply { }

  fun reload(netName: String): CompletableFuture<Unit> =
    Executor.call(newCommand(netName).withArguments("reload"))
      .thenApply { }

  fun disconnectPeer(netName: String, node: String): CompletableFuture<Unit> =
    Executor.call(newCommand(netName).withArguments("disconnect", node))
      .thenApply { }

  fun connectPeer(netName: String, node: String): CompletableFuture<Unit> =
    Executor.call(newCommand(netName).withArguments("connect", node))
      .thenApply { }

  fun purge(netName: String): CompletableFuture<Unit> =
    Executor.call(newCommand(netName).withArguments("purge"))
      .thenApply { }

  fun debug(netName: String, level: Int): CompletableFuture<String> =
    Executor.call(newCommand(netName).withArguments("debug", level.coerceIn(0, 5).toString()))
      .thenApply { it.joinToString("\n") }

  fun pid(netName: String): CompletableFuture<Int> =
    Executor.call(newCommand(netName).withArguments("pid"))
      .thenApply { Integer.parseInt(it.first()) }

  fun dumpNodes(netName: String, reachable: Boolean = false): CompletableFuture<List<String>> =
    Executor.call(
      if (reachable) newCommand(netName).withArguments("dump", "reachable", "nodes")
      else newCommand(netName).withArguments("dump", "nodes"))

  fun dumpEdges(netName: String): CompletableFuture<List<String>> =
    Executor.call(newCommand(netName).withArguments("dump", "edges"))

  fun dumpConnections(netName: String): CompletableFuture<List<String>> =
    Executor.call(newCommand(netName).withArguments("dump", "connections"))

  fun dumpSubnets(netName: String): CompletableFuture<List<String>> =
    Executor.call(
      newCommand(netName).withArguments("dump", "subnets"))

  fun dumpRaw(netName: String, kind: String): CompletableFuture<String> {
    val cmd = newCommand(netName).withArguments("dump")
    kind.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }.forEach { cmd.withArguments(it) }
    return Executor.call(cmd).thenApply { it.joinToString("\n") }
  }

  fun info(netName: String, node: String): CompletableFuture<String> =
    Executor.call(newCommand(netName).withArguments("info", node))
      .thenApply { it.joinToString("\n") }

  fun fsck(netName: String): CompletableFuture<String> =
    Executor.call(newCommand(netName).withArguments("fsck"))
      .thenApply { it.joinToString("\n") }

  fun invite(netName: String, node: String): CompletableFuture<String> =
    Executor.call(newCommand(netName).withArguments("invite", node))
      .thenApply { it.joinToString("\n").trim() }

  fun diagPort(netName: String, port: Int? = null): CompletableFuture<Int> {
    val cmd = newCommand(netName).withArguments("diag-port")
    if (port != null) cmd.withArguments(port.coerceIn(0, 65535).toString())
    return Executor.call(cmd).thenApply { it.lastOrNull()?.trim()?.toIntOrNull() ?: 0 }
  }

  fun diagPing(
    netName: String,
    dstIp: String,
    size: Int = 56,
    ttl: Int = 64,
    df: Boolean = false,
    timeoutMs: Int = 2000,
  ): CompletableFuture<List<String>> =
    Executor.call(
      newCommand(netName).withArguments(
        "diag-ping",
        dstIp.trim(),
        size.coerceIn(0, 1472).toString(),
        ttl.coerceIn(1, 255).toString(),
        if (df) "1" else "0",
        timeoutMs.coerceIn(100, 15000).toString(),
      )
    )

  fun log(netName: String, level: Int? = null): Process =
    Executor.run(newCommand(netName)
      .withArguments("log")
      .apply { if (level != null) withArguments(level.toString()) })
}
