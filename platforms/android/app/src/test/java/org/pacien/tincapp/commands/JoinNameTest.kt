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

/** The user never names a network: it is named after what the invitation says. */
class JoinNameTest {
  @Test
  fun theNetworksOwnNameWins() {
    assertEquals("home", Join.pickName("home", "node_a", emptySet()))
  }

  @Test
  fun theCorePlaceholderGivesWayToTheInviter() {
    assertEquals("node_a", Join.pickName("tincstack", "node_a", emptySet()))
    assertEquals("node_a", Join.pickName(null, "node_a", emptySet()))
    assertEquals("tincstack", Join.pickName("tincstack", null, emptySet()))
    assertEquals("tincstack", Join.pickName(null, "  ", emptySet()))
  }

  @Test
  fun unsafeCharactersAreReplaced() {
    assertEquals("my_net", Join.pickName("my net", null, emptySet()))
    assertEquals("a_b", Join.pickName("a/b", null, emptySet()))
    assertEquals("tincstack", Join.pickName("..", null, emptySet()))
  }

  @Test
  fun takenNamesGetASuffix() {
    assertEquals("home-2", Join.pickName("home", null, setOf("home")))
    assertEquals("home-3", Join.pickName("home", null, setOf("home", "home-2")))
  }
}
