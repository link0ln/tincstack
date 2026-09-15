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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class VpnInterfaceConfigurationTest {
  @get:Rule
  val tmp = TemporaryFolder()

  private fun file(text: String): File = tmp.newFile("tinc.yaml").apply { writeText(text) }

  @Test
  fun explicitAndroidKeysAreRead() {
    val cfg = VpnInterfaceConfiguration.fromTincYaml(file("""
      |networks:
      |  mynet:
      |    options:
      |      Name: phone
      |      Ifconfig: 10.210.0.3/24
      |      Route:
      |        - 10.210.0.0/24
      |        - 192.168.1.0/24 via 10.210.0.1
      |      DNSServer: [10.210.0.1, 10.210.0.2]
      |      SearchDomain: mesh.internal
      |      AllowApplication:
      |        - org.example.browser
      |        - org.example.mail
      |      AllowFamily: 2
      |      AllowBypass: yes
      |      Blocking: true
      |      MTU: 1400
      |      ReconnectOnNetworkChange: no
      |""".trimMargin()), "mynet")

    assertEquals(listOf(CidrAddress("10.210.0.3", 24)), cfg.addresses)
    assertEquals(listOf(CidrAddress("10.210.0.0", 24), CidrAddress("192.168.1.0", 24)), cfg.routes)
    assertEquals(listOf("10.210.0.1", "10.210.0.2"), cfg.dnsServers)
    assertEquals(listOf("mesh.internal"), cfg.searchDomains)
    assertEquals(listOf("org.example.browser", "org.example.mail"), cfg.allowedApplications)
    assertTrue(cfg.disallowedApplications.isEmpty())
    assertEquals(listOf(2), cfg.allowedFamilies)
    assertTrue(cfg.allowBypass)
    assertTrue(cfg.blocking)
    assertEquals(1400, cfg.mtu)
    assertFalse(cfg.reconnectOnNetworkChange)
  }

  @Test
  fun zeroConfigNodeDerivesAddressAndRouteFromSubnetAndPool() {
    // exactly what the daemon materialises from an empty file: no Android key at all
    val cfg = VpnInterfaceConfiguration.fromTincYaml(file(TincYamlTest.DAEMON_DOC), "mynet")
    assertEquals(listOf(CidrAddress("10.165.0.1", 24)), cfg.addresses)
    assertEquals(listOf(CidrAddress("10.165.0.0", 24)), cfg.routes)
    assertTrue(cfg.dnsServers.isEmpty())
    assertTrue(cfg.allowedApplications.isEmpty())
    assertTrue(cfg.disallowedApplications.isEmpty())
    assertFalse(cfg.allowBypass)
    assertNull(cfg.mtu)
    assertTrue(cfg.reconnectOnNetworkChange)
  }

  @Test
  fun stanzaIsResolvedFromTheDirectoryNameOrTheFirstOne() {
    val f = file(TincYamlTest.DAEMON_DOC.replace("Mode: router", "Mode: router\n      DisallowApplication: org.example.x"))
    assertEquals(listOf("org.example.x"), VpnInterfaceConfiguration.fromTincYaml(f, "mynet").disallowedApplications)
    assertEquals(listOf("org.example.x"), VpnInterfaceConfiguration.fromTincYaml(f, "dir-named-differently").disallowedApplications)
  }

  @Test(expected = TincYaml.InvalidConfigurationException::class)
  fun mixingAllowAndDisallowIsRefused() {
    VpnInterfaceConfiguration.fromTincYaml(file("""
      |networks:
      |  n:
      |    options:
      |      AllowApplication: a
      |      DisallowApplication: b
      |""".trimMargin()), "n")
  }

  @Test
  fun invitationDataAddressingIsFoldedIntoTheYaml() {
    val inv = tmp.newFile("invitation-data").apply {
      writeText("Name = phone\nNetName = mynet\nConnectTo = nodeA\nIfconfig = 10.165.0.2/24\nRoute = 10.165.0.0/24\nRoute = 172.16.0.0/12 10.165.0.1\n")
    }
    val yaml = TincYaml(file(TincYamlTest.DAEMON_DOC))
    VpnInterfaceConfiguration.fromInvitation(inv).writeAddressing(yaml, "mynet")

    assertEquals(listOf("10.165.0.2/24"), yaml.optionValues("mynet", "Ifconfig"))
    assertEquals(listOf("10.165.0.0/24", "172.16.0.0/12"), yaml.optionValues("mynet", "Route"))
    val cfg = VpnInterfaceConfiguration.fromTincYaml(yaml.file, "mynet")
    assertEquals(listOf(CidrAddress("10.165.0.2", 24)), cfg.addresses)
    assertEquals(listOf(CidrAddress("10.165.0.0", 24), CidrAddress("172.16.0.0", 12)), cfg.routes)
  }
}
