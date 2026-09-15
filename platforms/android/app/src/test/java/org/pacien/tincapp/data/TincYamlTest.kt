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
import java.io.File

/**
 * The splice writer against a document shaped exactly like the daemon's own
 * emitter output (core/tincd/src/yamlconf.c, zeroconf materialisation).
 */
class TincYamlTest {
  @get:Rule
  val tmp = TemporaryFolder()

  private fun yamlFile(text: String): File = tmp.newFile("tinc.yaml").apply { writeText(text) }

  @Test
  fun readsScalarsListsAndBooleansAsTincValues() {
    val y = TincYaml(yamlFile(DAEMON_DOC))
    assertEquals(listOf("mynet"), y.networkNames())
    assertEquals("nodeA", y.optionValue("mynet", "Name"))
    assertEquals("655", y.optionValue("mynet", "Port"))
    assertEquals(listOf("hub", "relay"), y.optionValues("mynet", "ConnectTo"))
    assertEquals("yes", y.optionValue("mynet", "UDPRebindOnWake"))
    assertEquals(emptyList<String>(), y.optionValues("mynet", "Absent"))
    assertEquals(listOf("10.165.0.1/32"), y.ownHostValues("mynet", "Subnet"))
    assertTrue(y.hostText("mynet", "nodeA")!!.contains("Ed25519PublicKey = FP/bEG"))
  }

  @Test
  fun resolvesTheStanzaLikeTheDaemon() {
    val y = TincYaml(yamlFile(DAEMON_DOC))
    assertEquals("mynet", y.resolveNetwork("mynet"))
    assertEquals("mynet", y.resolveNetwork("other-dir-name")) // first stanza when the preferred one is absent
    assertEquals("fresh", TincYaml(File(tmp.root, "absent.yaml")).resolveNetwork("fresh"))
  }

  @Test
  fun spliceAddsListKeysAndLeavesTheRestByteForByte() {
    val f = yamlFile(DAEMON_DOC)
    val y = TincYaml(f)
    y.setOptions("mynet", mapOf("AllowApplication" to listOf("com.b", "com.a"), "Route" to listOf("10.165.0.0/24")))
    val out = f.readText()

    val expected = DAEMON_DOC.replace(
      "      AddressPool: 10.165.0.0/24\n",
      "      AddressPool: 10.165.0.0/24\n" +
        "      AllowApplication:\n        - com.b\n        - com.a\n" +
        "      Route: 10.165.0.0/24\n")
    assertEquals(expected, out)

    assertEquals(listOf("com.b", "com.a"), y.optionValues("mynet", "AllowApplication"))
    assertEquals(listOf("10.165.0.0/24"), y.optionValues("mynet", "Route"))
    // untouched sections survive
    assertEquals("nodeA", y.optionValue("mynet", "Name"))
    assertTrue(out.contains("    keys:\n      ed25519_priv: |\n        -----BEGIN ED25519 PRIVATE KEY-----\n"))
    assertTrue(out.contains("# a comment the daemon would drop but we keep\n"))
  }

  @Test
  fun spliceReplacesInPlaceAndRemovesWithNull() {
    val f = yamlFile(DAEMON_DOC)
    val y = TincYaml(f)
    y.setOptions("mynet", mapOf("Route" to listOf("10.1.0.0/24", "10.2.0.0/24"), "AllowApplication" to listOf("com.x")))
    y.setOptions("mynet", mapOf("Route" to listOf("192.168.0.0/16"), "AllowApplication" to null, "DisallowApplication" to listOf("com.y")))
    val out = f.readText()

    assertEquals(listOf("192.168.0.0/16"), y.optionValues("mynet", "Route"))
    assertEquals(emptyList<String>(), y.optionValues("mynet", "AllowApplication"))
    assertEquals(listOf("com.y"), y.optionValues("mynet", "DisallowApplication"))
    assertFalse(out.contains("AllowApplication"))
    assertFalse(out.contains("10.1.0.0/24"))
    // replaced where the old entry stood, i.e. still inside options, before hosts:
    assertTrue(out.indexOf("      Route: 192.168.0.0/16") < out.indexOf("    hosts:"))
    assertEquals(1, out.split("Route:").size - 1)
  }

  @Test
  fun spliceCreatesScaffoldingForAnEmptyOrAbsentFile() {
    val f = File(tmp.root, "new.yaml")
    TincYaml(f).createNetwork("net1", "phone")
    assertEquals("networks:\n  net1:\n    options:\n      Name: phone\n", f.readText())

    TincYaml(f).setOptions("net1", mapOf("DNSServer" to listOf("10.0.0.1")))
    assertEquals("networks:\n  net1:\n    options:\n      Name: phone\n      DNSServer: 10.0.0.1\n", f.readText())

    // a second stanza in the same file
    TincYaml(f).setOptions("net2", mapOf("Route" to listOf("0.0.0.0/0")))
    assertEquals(
      "networks:\n  net1:\n    options:\n      Name: phone\n      DNSServer: 10.0.0.1\n  net2:\n    options:\n      Route: 0.0.0.0/0\n",
      f.readText())
    assertEquals(listOf("net1", "net2"), TincYaml(f).networkNames())
  }

  @Test
  fun spliceCreatesOptionsWhenTheStanzaHasNone() {
    val f = yamlFile("networks:\n  mynet:\n    hosts:\n      a: |\n        Subnet = 10.0.0.1/32\n")
    TincYaml(f).setOptions("mynet", mapOf("Route" to listOf("10.0.0.0/24")))
    assertEquals("networks:\n  mynet:\n    options:\n      Route: 10.0.0.0/24\n    hosts:\n      a: |\n        Subnet = 10.0.0.1/32\n", f.readText())
  }

  @Test
  fun writeIsANoOpWhenNothingChanges() {
    val f = yamlFile(DAEMON_DOC)
    val before = f.lastModified()
    Thread.sleep(5)
    TincYaml(f).setOptions("mynet", mapOf("Absent" to null))
    assertEquals(DAEMON_DOC, f.readText())
    assertEquals(before, f.lastModified())
  }

  @Test
  fun writeLeavesNoTempFileBehind() {
    val f = yamlFile(DAEMON_DOC)
    TincYaml(f).setOptions("mynet", mapOf("MTU" to listOf("1400")))
    assertEquals(listOf("tinc.yaml"), tmp.root.list()!!.toList())
  }

  @Test(expected = TincYaml.InvalidConfigurationException::class)
  fun refusesADocumentThatIsNotAMapping() {
    TincYaml(yamlFile("- just\n- a list\n")).networkNames()
  }

  companion object {
    /** What `tincd -c tinc.yaml -n mynet` materialises from `Name: nodeA` (keys shortened). */
    val DAEMON_DOC = """
      |networks:
      |  mynet:
      |    options:
      |      Name: nodeA
      |      Mode: router
      |      Port: 655
      |      # a comment the daemon would drop but we keep
      |      ConnectTo: [hub, relay]
      |      UDPRebindOnWake: yes
      |      AddressPool: 10.165.0.0/24
      |    hosts:
      |      nodeA: |
      |        Subnet = 10.165.0.1/32
      |        Ed25519PublicKey = FP/bEGx2wj3svGRwyX9VzOgVIg3aaX8SmN2d7RTOz7H
      |        -----BEGIN RSA PUBLIC KEY-----
      |        MIIBCgKCAQEA0Zx
      |        -----END RSA PUBLIC KEY-----
      |
      |    keys:
      |      ed25519_priv: |
      |        -----BEGIN ED25519 PRIVATE KEY-----
      |        c2VjcmV0
      |        -----END ED25519 PRIVATE KEY-----
      |
      |      rsa_priv: |
      |        -----BEGIN RSA PRIVATE KEY-----
      |        c2VjcmV0
      |        -----END RSA PRIVATE KEY-----
      |
      |""".trimMargin()
  }
}
