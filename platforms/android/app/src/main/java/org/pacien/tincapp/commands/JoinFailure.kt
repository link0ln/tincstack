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

/**
 * Why a `tinc join` failed, in the user's terms. Classified from the core's
 * own stderr (core/tincd/src/invitation.c and names/net code); the raw lines
 * are kept for the "details" part of the message and the log.
 */
enum class JoinFailureKind {
  /** Name did not resolve. */
  HOST_NOT_FOUND,

  /** No TCP connection to the inviter (refused, unreachable, or our connect deadline). */
  UNREACHABLE,

  /** Connected, but what answered is not the node that issued this invitation (hash mismatch, no tinc greeting). */
  WRONG_NODE,

  /** The inviter took the connection but did not complete the exchange: invitation used, expired or unknown. */
  REJECTED,

  /** The network already exists (only with an explicit name). */
  ALREADY_JOINED,

  /** Anything else: local write errors, key generation, ... */
  OTHER,
}

class JoinFailure(val kind: JoinFailureKind, val details: List<String>) : Exception(details.lastOrNull() ?: kind.name) {
  companion object {
    /** Map the core's stderr (all lines, in order) to a [JoinFailureKind]. Pure: unit-tested. */
    fun classify(stderr: List<String>, timedOutConnecting: Boolean = false): JoinFailureKind {
      if (timedOutConnecting) return JoinFailureKind.UNREACHABLE
      val text = stderr.joinToString("\n")
      fun has(vararg needles: String) = needles.any { text.contains(it, ignoreCase = true) }
      val connected = has("Connected to ")
      return when {
        // str2addrinfo: "Error looking up <host> port <port>: <gai error>"
        has("Error looking up") -> JoinFailureKind.HOST_NOT_FOUND
        !connected && has("Could not connect to", "Could not open socket") -> JoinFailureKind.UNREACHABLE
        has("Peer has an invalid key", "Cannot read greeting") -> JoinFailureKind.WRONG_NODE
        has("already exists") -> JoinFailureKind.ALREADY_JOINED
        // connected, then the inviter hung up or never finished: the invitation
        // is spent, expired or not one of its own
        connected && has("Timed out waiting for the server", "Invitation cancelled", "Error reading data",
          "Connection reset", "Broken pipe", "was not completed") -> JoinFailureKind.REJECTED
        connected && !has("Could not write", "Could not serialise", "Could not lock", "Could not create") ->
          JoinFailureKind.REJECTED
        else -> JoinFailureKind.OTHER
      }
    }
  }
}
