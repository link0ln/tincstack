/*
 * Tinc Mesh VPN: Android client and user interface
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class SplitRoutingTest {
  @get:Rule
  val tmp = TemporaryFolder()

  private fun freshYaml() = TincYaml(tmp.newFile("tinc.yaml").apply { writeText(TincYamlTest.DAEMON_DOC) })

  @Test
  fun defaultIsAnEmptyBlacklistMeaningAllApps() {
    val r = SplitRouting.read(freshYaml(), "mynet")
    assertEquals(SplitRoutingMode.BLACKLIST, r.mode)
    assertTrue(r.apps.isEmpty())
  }

  @Test
  fun whitelistRoundTripsAndWritesExactlyOneKey() {
    val y = freshYaml()
    SplitRouting(SplitRoutingMode.WHITELIST, setOf("org.example.b", "org.example.a")).write(y, "mynet")

    val r = SplitRouting.read(y, "mynet")
    assertEquals(SplitRoutingMode.WHITELIST, r.mode)
    assertEquals(setOf("org.example.a", "org.example.b"), r.apps)
    assertEquals(listOf("org.example.a", "org.example.b"), y.optionValues("mynet", "AllowApplication"))
    assertTrue(y.optionValues("mynet", "DisallowApplication").isEmpty())
    assertFalse(y.file.readText().contains("DisallowApplication"))
  }

  @Test
  fun switchingModeRemovesTheOtherList() {
    val y = freshYaml()
    SplitRouting(SplitRoutingMode.WHITELIST, setOf("org.example.a")).write(y, "mynet")
    SplitRouting(SplitRoutingMode.BLACKLIST, setOf("org.example.z")).write(y, "mynet")

    val text = y.file.readText()
    assertFalse(text.contains("AllowApplication"))
    assertTrue(text.contains("      DisallowApplication: org.example.z\n"))
    val r = SplitRouting.read(y, "mynet")
    assertEquals(SplitRoutingMode.BLACKLIST, r.mode)
    assertEquals(setOf("org.example.z"), r.apps)
  }

  @Test
  fun emptySelectionRemovesBothKeys() {
    val y = freshYaml()
    SplitRouting(SplitRoutingMode.WHITELIST, setOf("org.example.a")).write(y, "mynet")
    SplitRouting(SplitRoutingMode.WHITELIST, emptySet()).write(y, "mynet")
    val text = y.file.readText()
    assertFalse(text.contains("AllowApplication"))
    assertFalse(text.contains("DisallowApplication"))
  }

  @Test(expected = TincYaml.InvalidConfigurationException::class)
  fun bothListsPresentIsRefused() {
    val y = freshYaml()
    y.setOptions("mynet", mapOf("AllowApplication" to listOf("a"), "DisallowApplication" to listOf("b")))
    SplitRouting.read(y, "mynet")
  }
}
