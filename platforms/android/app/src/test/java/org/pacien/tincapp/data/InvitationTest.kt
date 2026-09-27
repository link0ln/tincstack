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

package org.pacien.tincapp.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The owner's first join failed because the pasted invitation ended with a
 * newline and the core took it verbatim ("Invalid invitation URL."): every
 * shape an invitation arrives in must come out as the exact string the core
 * parses.
 */
class InvitationTest {
  private val token = "Qx3kL9mZpR2vT8wYbN4cF6hJ1sD5gA7eU0iO-_KqWrXtYzMn"
  private val plain = "203.0.113.7:655/$token"

  private fun parsed(text: String?) = Invitation.find(text)?.toString()

  @Test
  fun exactInvitationIsKept() {
    assertEquals(plain, parsed(plain))
    assertEquals(Invitation("203.0.113.7", 655, token), Invitation.find(plain))
  }

  @Test
  fun surroundingBlanksAndNewlinesAreDropped() {
    assertEquals(plain, parsed("  $plain\n"))
    assertEquals(plain, parsed("\n\t$plain \r\n"))
    assertEquals(plain, parsed("$plain\u200B"))
  }

  @Test
  fun sentenceAroundItDoesNotMatter() {
    assertEquals(plain, parsed("Here is your invitation: $plain (valid for a week)."))
    assertEquals(plain, parsed("\"$plain\""))
    assertEquals(plain, parsed("<$plain>"))
  }

  @Test
  fun tokenWrappedOverTwoLinesIsJoined() {
    assertEquals(plain, parsed("203.0.113.7:655/${token.take(20)}\n${token.drop(20)}"))
  }

  @Test
  fun schemeAddedByALinkifierIsIgnored() {
    assertEquals(plain, parsed("http://$plain"))
    assertEquals(plain, parsed("tinc://$plain"))
  }

  @Test
  fun portDefaultsTo655AndHostNamesWork() {
    assertEquals("vpn.example.com:655/$token", parsed("vpn.example.com/$token"))
    assertEquals("vpn.example.com:7000/$token", parsed("vpn.example.com:7000/$token"))
    assertEquals("vpn.example.com:7000", Invitation.find("vpn.example.com:7000/$token")!!.endpoint())
  }

  @Test
  fun ipv6LiteralKeepsItsBrackets() {
    val inv = Invitation.find("[2001:db8::1]:655/$token")!!
    assertEquals("2001:db8::1", inv.host)
    assertEquals("[2001:db8::1]:655/$token", inv.toString())
  }

  @Test
  fun garbageIsNotAnInvitation() {
    assertNull(Invitation.find(null))
    assertNull(Invitation.find(""))
    assertNull(Invitation.find("   \n"))
    assertNull(Invitation.find("hello world"))
    assertNull(Invitation.find("203.0.113.7:655/tooshort"))
    assertNull(Invitation.find("203.0.113.7:655/${token}X")) // 49 characters
    assertNull(Invitation.find("203.0.113.7:99999/$token")) // no such port, and "99999" is no host
    assertNull(Invitation.find("2001:db8::1:655/$token")) // IPv6 needs its brackets
  }

  @Test
  fun twoInvitationsPastedTogetherAreNotOne() {
    // measured on the emulator (2026-09-27): the field held both, and the app
    // offered to join a host named "<first token>203.0.113.7"
    val other = token.reversed()
    assertNull(Invitation.find("$plain$plain"))
    assertNull(Invitation.find("203.0.113.7:655/$token" + "203.0.113.7:655/$other"))
    // separated, the first one wins
    assertEquals(plain, parsed("$plain 203.0.113.7:655/$other"))
  }
}
