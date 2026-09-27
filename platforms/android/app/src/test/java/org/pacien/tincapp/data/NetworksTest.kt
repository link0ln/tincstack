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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * A directory under networks/ without a tinc.yaml is what a failed join used
 * to leave behind (the owner's phantom "home" network): it is not listed and
 * is swept away.
 */
class NetworksTest {
  @get:Rule
  val tmp = TemporaryFolder()

  private fun network(root: File, name: String, yaml: String?) = File(root, name).apply {
    mkdirs()
    if (yaml != null) File(this, TincYaml.FILE_NAME).writeText(yaml)
  }

  @Test
  fun onlyDirectoriesWithAConfigAreNetworks() {
    val root = tmp.newFolder("networks")
    network(root, "work", "networks:\n  work:\n    options:\n      Name: phone\n")
    network(root, "Alpha", "networks:\n  alpha:\n    options:\n      Name: phone\n")
    network(root, "home", null).also { File(it, "home").mkdirs() } // the phantom: networks/home/home/
    network(root, "empty", "")
    File(root, "stray.txt").writeText("x")

    assertEquals(listOf("Alpha", "work"), Networks.list(root))
  }

  @Test
  fun sweepRemovesWhatIsNotANetwork() {
    val root = tmp.newFolder("networks")
    val work = network(root, "work", "networks:\n  work:\n    options:\n      Name: phone\n")
    val phantom = network(root, "home", null).also { File(it, "home").mkdirs() }
    val empty = network(root, "empty", "")

    Networks.sweepBroken(root)

    assertTrue(File(work, TincYaml.FILE_NAME).isFile)
    assertFalse(phantom.exists())
    assertFalse(empty.exists())
  }
}
