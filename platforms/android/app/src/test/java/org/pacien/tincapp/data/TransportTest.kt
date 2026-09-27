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
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class TransportTest {
  @get:Rule
  val tmp = TemporaryFolder()

  private fun joined() = TincYaml(tmp.newFile("tinc.yaml").apply {
    writeText(TransportTest::class.java.getResource("/joined-tinc.yaml")!!.readText())
  })

  @Test
  fun absentMeansTheCoreDefault() {
    assertNull(Transport.preferred(joined(), "phonenet"))
  }

  @Test
  fun choiceRoundTripsAndNullRemovesIt() {
    val y = joined()
    Transport.setPreferred(y, "phonenet", Transport.HTTPS)
    assertEquals(Transport.HTTPS, Transport.preferred(y, "phonenet"))
    assertEquals(listOf("https"), y.optionValues("phonenet", Transport.KEY_PREFERRED))
    Transport.setPreferred(y, "phonenet", null)
    assertNull(Transport.preferred(y, "phonenet"))
  }

  @Test
  fun offeredCarriersComeFromTheDialledNodesHostRecord() {
    // node_a's record says "Transports = plain, sf"
    assertEquals(setOf(Transport.PLAIN, Transport.SF), Transport.acceptedByPeers(joined(), "phonenet"))
  }

  @Test
  fun unknownAcceptListMeansPlainOnly() {
    val y = TincYaml(tmp.newFile("bare.yaml").apply { writeText("networks:\n  n:\n    options:\n      ConnectTo: x\n") })
    assertEquals(setOf(Transport.PLAIN), Transport.acceptedByPeers(y, "n"))
  }
}
