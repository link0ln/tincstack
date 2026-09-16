/*
 * Tinc Mesh VPN: Android client and user interface
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

  fun pid(netName: String): CompletableFuture<Int> =
    Executor.call(newCommand(netName).withArguments("pid"))
      .thenApply { Integer.parseInt(it.first()) }

  fun dumpNodes(netName: String, reachable: Boolean = false): CompletableFuture<List<String>> =
    Executor.call(
      if (reachable) newCommand(netName).withArguments("dump", "reachable", "nodes")
      else newCommand(netName).withArguments("dump", "nodes"))

  fun dumpSubnets(netName: String): CompletableFuture<List<String>> =
    Executor.call(
      newCommand(netName).withArguments("dump", "subnets"))

  fun info(netName: String, node: String): CompletableFuture<String> =
    Executor.call(newCommand(netName).withArguments("info", node))
      .thenApply { it.joinToString("\n") }

  /**
   * `tinc -c <net>/tinc.yaml -n <net> join <invitation>`. The stanza is the
   * directory name, so the joined network lands where the app expects it.
   */
  fun join(netName: String, invitationUrl: String): CompletableFuture<String> =
    if (netName.isBlank())
      CompletableFuture.failedFuture(IllegalArgumentException("Network name cannot be blank."))
    else
    // the core writes tinc.yaml into networks/<net>/ but does not create that
    // directory: without it the join dies with "Could not lock ...tinc.yaml".
    // A failed join leaves it empty, so it is taken back out again.
      AppPaths.confDir(netName).let { dir ->
        dir.mkdirs()
        Executor.call(Command(AppPaths.tinc().absolutePath)
          .withOption("config", AppPaths.tincYamlFile(netName).absolutePath)
          .withOption("net", netName)
          .withArguments("join", invitationUrl))
          .thenApply { it.joinToString("\n") }
          .whenComplete { _, _ -> if (dir.list()?.isEmpty() == true) dir.delete() }
      }

  fun log(netName: String, level: Int? = null): Process =
    Executor.run(newCommand(netName)
      .withArguments("log")
      .apply { if (level != null) withArguments(level.toString()) })
}
