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

import org.junit.Assert.assertEquals
import org.junit.Test

/** What the user is told about a failed join, from the core's own stderr. */
class JoinFailureTest {
  private fun kind(vararg lines: String, timedOut: Boolean = false) = JoinFailure.classify(lines.toList(), timedOut)

  @Test
  fun nameThatDoesNotResolve() {
    assertEquals(JoinFailureKind.HOST_NOT_FOUND,
      kind("Error looking up vpn.example.invalid port 655: No address associated with hostname"))
  }

  @Test
  fun nobodyListening() {
    assertEquals(JoinFailureKind.UNREACHABLE, kind("Could not connect to 203.0.113.7 port 655: Connection refused"))
    assertEquals(JoinFailureKind.UNREACHABLE, kind(timedOut = true))
  }

  @Test
  fun somethingElseAnswered() {
    assertEquals(JoinFailureKind.WRONG_NODE, kind("Connected to 203.0.113.7 port 655...", "Cannot read greeting from peer"))
    assertEquals(JoinFailureKind.WRONG_NODE, kind("Connected to 203.0.113.7 port 655...", "Peer has an invalid key!"))
  }

  @Test
  fun spentOrUnknownInvitation() {
    assertEquals(JoinFailureKind.REJECTED, kind("Connected to 203.0.113.7 port 655...", "Error reading data from 203.0.113.7 port 655: Connection reset by peer"))
    assertEquals(JoinFailureKind.REJECTED, kind("Connected to 203.0.113.7 port 655...", "Invitation cancelled."))
    assertEquals(JoinFailureKind.REJECTED, kind("Connected to 203.0.113.7 port 655..."))
  }

  @Test
  fun localProblemsAreNotBlamedOnTheInviter() {
    assertEquals(JoinFailureKind.OTHER, kind("Connected to 203.0.113.7 port 655...", "Could not serialise Ed25519 private key"))
    assertEquals(JoinFailureKind.OTHER, kind("Invalid invitation URL."))
  }
}
