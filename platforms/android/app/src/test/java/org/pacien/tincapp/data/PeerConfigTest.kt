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
import org.junit.Assert.assertTrue
import org.junit.Test

/** The host-record editor: per-key rewrites preserve everything else byte for byte. */
class PeerConfigTest {
  private val yaml = TincYaml(java.io.File("/tmp/tinc-peer-edit-test.yaml"))
  private val record = """
    # a comment that must survive
    Subnet = 10.8.179.2/32
    Address = 80.87.200.39
    HttpsPort = 8443
    QuicPort = 8443
    Ed25519PublicKey = xa8MEcJIfEGQmRsqIogq0DDNxmoHVfUqM1avMSIaVvM
    -----BEGIN RSA PUBLIC KEY-----
    MIIBCgKCAQEAqDZrTkpS
    -----END RSA PUBLIC KEY-----
  """.trimIndent()

  @Test
  fun parsesTheEditableSlice() {
    val cfg = PeerConfig("ruvds2", record)
    assertEquals("80.87.200.39", cfg.address)
    assertNull(cfg.addressPort)
    assertNull(cfg.port)
    assertEquals("8443", cfg.httpsPort)
    assertEquals("8443", cfg.quicPort)
    assertEquals("xa8MEcJIfEGQmRsqIogq0DDNxmoHVfUqM1avMSIaVvM", cfg.ed25519PublicKey)
    assertEquals(listOf("10.8.179.2/32"), cfg.subnet)
  }

  @Test
  fun parsesAddressWithPort() {
    val cfg = PeerConfig("euvds", "Address = example.net 465\n")
    assertEquals("example.net", cfg.address)
    assertEquals("465", cfg.addressPort)
  }

  @Test
  fun replaceKeepsNeighborsByteForByte() {
    val out = yaml.spliceHostVars(record, mapOf("Port" to "113", "HttpsPort" to "465", "QuicPort" to "465"))
    assertTrue(out.contains("# a comment that must survive"))
    assertTrue(out.contains("Subnet = 10.8.179.2/32"))
    assertTrue(out.contains("-----BEGIN RSA PUBLIC KEY-----"))
    assertTrue(out.contains("Port = 113"))
    assertTrue(out.contains("HttpsPort = 465"))
    assertTrue(out.contains("QuicPort = 465"))
    assertTrue(!out.contains("8443"))
  }

  @Test
  fun addressRewriteKeepsTheKeyLine() {
    val out = yaml.spliceHostVars(record, mapOf("Address" to "vpn.example.net 465"))
    assertTrue(out.contains("Address = vpn.example.net 465"))
    assertTrue(!out.contains("80.87.200.39"))
  }

  @Test
  fun removalLeavesNoHole() {
    val out = yaml.spliceHostVars(record, mapOf("HttpsPort" to null, "QuicPort" to null))
    assertTrue(!out.contains("HttpsPort"))
    assertTrue(!out.contains("QuicPort"))
    assertTrue(!out.contains("\n\n\n"))
  }

  @Test
  fun appendAddsAfterTheLastVarLine() {
    val out = yaml.spliceHostVars("Address = 1.2.3.4\n", mapOf("Port" to "113"))
    val lines = out.trim().lines()
    assertEquals("Address = 1.2.3.4", lines[0])
    assertEquals("Port = 113", lines[1])
  }
  @Test
  fun validation() {
    assertNull(PeerConfig.Validation.address("80.87.200.39"))
    assertNull(PeerConfig.Validation.address("vpn.example.net"))
    assertNull(PeerConfig.Validation.address("::1"))
    assertNull(PeerConfig.Validation.address(""))
    assertEquals(true, PeerConfig.Validation.address("not a host!") != null)
    assertEquals(true, PeerConfig.Validation.address("999.1.1.1") != null)
    assertNull(PeerConfig.Validation.port("113"))
    assertNull(PeerConfig.Validation.port(""))
    assertEquals(true, PeerConfig.Validation.port("0") != null)
    assertEquals(true, PeerConfig.Validation.port("70000") != null)
    assertEquals(true, PeerConfig.Validation.port("abc") != null)
  }
}
