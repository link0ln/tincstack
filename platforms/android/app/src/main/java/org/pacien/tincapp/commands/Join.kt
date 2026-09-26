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

package org.pacien.tincapp.commands

import java8.util.concurrent.CompletableFuture
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.data.Invitation
import org.pacien.tincapp.data.TincYaml
import org.pacien.tincapp.utils.makePrivate
import org.slf4j.LoggerFactory
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Joining a network by invitation, all or nothing.
 *
 * `tinc join` runs against a `tinc.yaml` in a private staging directory
 * (`files/joining/<id>/`), never under `networks/`: a join that fails at any
 * point -- a malformed invitation, an unreachable inviter, a spent invitation,
 * a write error half-way, the app killed mid-join -- leaves nothing in the
 * network list, because the staging directory is deleted (and stale ones are
 * swept at the next start). Only a join the core reported as accepted is moved
 * into `networks/<name>/`, in one rename.
 *
 * The core itself creates `<dir of tinc.yaml>/<netname>/` as soon as the CLI
 * starts (names.c, make_names), before it has even parsed the invitation; with
 * the join pointed at `networks/<name>/tinc.yaml` (what the app did until
 * 2026-09-27) every failure left that directory behind, and it showed up as a
 * network that could never connect.
 *
 * No `--net` is passed: the core then names the network after the
 * invitation's `NetName` (what the inviter calls it), falling back to
 * `tincstack`, and the directory takes that name (see [pickName]). The user
 * never has to invent a network name.
 */
object Join {
  private val log by lazy { LoggerFactory.getLogger(Join::class.java)!! }

  /** Without "Connected to" on stderr by then, the inviter is treated as unreachable. */
  const val CONNECT_DEADLINE_S = 20L

  /** The whole join: connection, key generation, the exchange. */
  private const val JOIN_DEADLINE_S = 90L

  private const val STAGING_DIR = "joining"

  /** The core's name for a network when the invitation carries no NetName. */
  private const val CORE_DEFAULT_NETNAME = "tincstack"

  private val NAME_UNSAFE = Regex("[^A-Za-z0-9_.\\-]")

  enum class Stage { CONTACTING, EXCHANGING }

  fun stagingRoot() = File(AppPaths.confDir().parentFile, STAGING_DIR)

  /** Leftovers of a join the app did not live to finish. */
  fun sweepStaging() {
    stagingRoot().takeIf { it.exists() }?.deleteRecursively()
  }

  /**
   * The directory name of a freshly joined network: the network's own name
   * (its YAML stanza), or, when the inviter gave it none, the name of the node
   * we dial -- "node_a" says more than the core's placeholder. Made
   * filesystem-safe and unique among [taken]. Pure: unit-tested.
   */
  fun pickName(stanza: String?, connectTo: String?, taken: Set<String>): String {
    val raw = stanza?.takeIf { it.isNotBlank() && it != CORE_DEFAULT_NETNAME }
      ?: connectTo?.takeIf { it.isNotBlank() }
      ?: CORE_DEFAULT_NETNAME
    val base = NAME_UNSAFE.replace(raw, "_").trim('.').ifEmpty { CORE_DEFAULT_NETNAME }
    if (base !in taken) return base
    return generateSequence(2) { it + 1 }.map { "$base-$it" }.first { it !in taken }
  }

  /**
   * Completes with the new network's directory name, or exceptionally with a
   * [JoinFailure]. [onStage] is called from a worker thread.
   */
  fun join(invitation: Invitation, onStage: (Stage) -> Unit = {}): CompletableFuture<String> = Executor.supplyAsyncTask {
    val staging = File(stagingRoot(), "join-${System.nanoTime()}").apply { mkdirs() }
    try {
      runJoin(staging, invitation, onStage)
      val yaml = TincYaml(File(staging, TincYaml.FILE_NAME))
      val stanza = yaml.networkNames().firstOrNull()
        ?: throw JoinFailure(JoinFailureKind.OTHER, listOf("tinc join reported success but wrote no network"))
      val connectTo = yaml.optionValue(stanza, "ConnectTo")
      val name = synchronized(this) {
        val target = pickName(stanza, connectTo, AppPaths.confDir().list()?.toSet() ?: emptySet())
          .let { AppPaths.confDir(it) }
        if (!staging.renameTo(target))
          throw JoinFailure(JoinFailureKind.OTHER, listOf("Could not move the joined network into ${target.absolutePath}"))
        target.makePrivate()
        target.name
      }
      log.info("Joined network \"{}\" (stanza \"{}\") via {}", name, stanza, invitation.endpoint())
      name
    } finally {
      if (staging.exists()) staging.deleteRecursively()
    }
  }

  /** Process.isAlive / waitFor(timeout) are API 26; minSdk is 21. */
  private fun Process.exitCodeOrNull(): Int? = try {
    exitValue()
  } catch (e: IllegalThreadStateException) {
    null
  }

  private fun runJoin(staging: File, invitation: Invitation, onStage: (Stage) -> Unit) {
    val cmd = Command(AppPaths.tinc().absolutePath)
      .withOption("config", File(staging, TincYaml.FILE_NAME).absolutePath)
      .withArguments("join", invitation.toString())
    log.info("Joining via {} ({})", invitation.endpoint(), staging.name)
    onStage(Stage.CONTACTING)
    val process = Executor.run(cmd)
    val stderr = mutableListOf<String>()
    val reader = Thread {
      process.errorStream.bufferedReader().forEachLine { line -> synchronized(stderr) { stderr.add(line) } }
    }.apply { isDaemon = true; start() }
    // drained, not closed: a closed pipe would kill the CLI with SIGPIPE on its first printf
    Thread { process.inputStream.bufferedReader().forEachLine { log.info("tinc join (stdout): {}", it) } }
      .apply { isDaemon = true; start() }

    val started = System.nanoTime()
    var connected = false
    var timedOut = false
    while (process.exitCodeOrNull() == null) {
      Thread.sleep(200)
      val elapsed = TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - started)
      if (!connected && synchronized(stderr) { stderr.any { it.startsWith("Connected to ") } }) {
        connected = true
        onStage(Stage.EXCHANGING)
      }
      if ((!connected && elapsed >= CONNECT_DEADLINE_S) || elapsed >= JOIN_DEADLINE_S) {
        timedOut = true
        process.destroy()
        break
      }
    }
    reader.join(2000)
    val lines = synchronized(stderr) { stderr.toList() }
    lines.forEach { log.info("tinc join: {}", it) }

    val accepted = lines.any { it.contains("Invitation successfully accepted") }
    val exit = process.exitCodeOrNull() ?: -1
    if (exit == 0 && accepted && !timedOut) return
    val timedOutConnecting = timedOut && !lines.any { it.startsWith("Connected to ") }
    val details = when {
      timedOutConnecting -> lines + "No answer from ${invitation.endpoint()} within ${CONNECT_DEADLINE_S} s."
      timedOut -> lines + "The inviter did not finish the exchange within ${JOIN_DEADLINE_S} s."
      else -> lines.ifEmpty { listOf("tinc join exited with status $exit") }
    }
    throw JoinFailure(JoinFailure.classify(lines, timedOutConnecting), details)
  }
}
