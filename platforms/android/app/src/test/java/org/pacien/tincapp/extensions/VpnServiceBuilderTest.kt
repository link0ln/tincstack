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

package org.pacien.tincapp.extensions

import android.net.VpnService
import android.os.IInterface
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.pacien.tincapp.data.SplitRouting
import org.pacien.tincapp.data.SplitRoutingMode
import org.pacien.tincapp.data.TincYaml
import org.pacien.tincapp.data.VpnInterfaceConfiguration
import org.pacien.tincapp.extensions.VpnServiceBuilder.applyCfg
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowServiceManager
import java.io.File

/**
 * A network directory holding only `tinc.yaml` yields a VpnService.Builder with
 * the expected addresses, routes, DNS and app lists. The builder's private
 * VpnConfig is read back by reflection (the framework offers no getters).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class) // not the app's App: it installs a crash handler
class VpnServiceBuilderTest {
  @get:Rule
  val tmp = TemporaryFolder()

  private class TestVpnService : VpnService()

  /**
   * `Builder.addAllowedApplication` / `addDisallowedApplication` verify the
   * package through the `package` system service, which Robolectric does not
   * register by default. Register its stub `IPackageManager` (every call
   * returns null, which `verifyApp` accepts), so the builder path under test is
   * the real framework one. `addBinderService` is protected, hence reflection.
   */
  @Before
  fun stubPackageService() {
    @Suppress("UNCHECKED_CAST")
    val ipm = Class.forName("android.content.pm.IPackageManager") as Class<out IInterface>
    ShadowServiceManager::class.java
      .getDeclaredMethod("addBinderService", String::class.java, Class::class.java)
      .apply { isAccessible = true }
      .invoke(null, "package", ipm)
  }

  private fun builderFor(yaml: String, netDir: String = "mynet"): VpnService.Builder {
    val dir = tmp.newFolder(netDir)
    val file = File(dir, TincYaml.FILE_NAME).apply { writeText(yaml) }
    assertEquals(listOf(TincYaml.FILE_NAME), dir.list()!!.toList()) // one file, no network.conf
    val cfg = VpnInterfaceConfiguration.fromTincYaml(file, netDir)
    return TestVpnService().Builder().setSession(netDir).applyCfg(cfg)
  }

  /**
   * The builder keeps addresses and routes in its own `mAddresses` / `mRoutes`
   * until establish() copies them into the VpnConfig; everything else goes
   * straight into `mConfig`. Both are read here without establishing.
   */
  private class Built(val builder: VpnService.Builder) {
    private val config: Any =
      VpnService.Builder::class.java.getDeclaredField("mConfig").apply { isAccessible = true }.get(builder)!!

    @Suppress("UNCHECKED_CAST")
    fun <T> field(name: String): T = when (name) {
      "addresses" -> VpnService.Builder::class.java.getDeclaredField("mAddresses").apply { isAccessible = true }.get(builder) as T
      "routes" -> VpnService.Builder::class.java.getDeclaredField("mRoutes").apply { isAccessible = true }.get(builder) as T
      else -> config.javaClass.getField(name).get(config) as T
    }
  }

  private fun config(b: VpnService.Builder) = Built(b)

  private fun <T> field(cfg: Built, name: String): T = cfg.field(name)

  private fun strings(cfg: Built, name: String): List<String> =
    field<List<Any>?>(cfg, name)?.map { it.toString() } ?: emptyList()

  @Test
  fun explicitOptionsWithWhitelist() {
    val b = builderFor("""
      |networks:
      |  mynet:
      |    options:
      |      Name: phone
      |      Ifconfig: 10.210.0.3/24
      |      Route:
      |        - 10.210.0.0/24
      |        - 192.168.1.0/24
      |      DNSServer: 10.210.0.1
      |      SearchDomain: mesh.internal
      |      AllowApplication:
      |        - org.example.browser
      |        - org.example.mail
      |      MTU: 1400
      |""".trimMargin())
    val cfg = config(b)

    assertEquals(listOf("10.210.0.3/24"), strings(cfg, "addresses"))
    assertEquals(listOf("10.210.0.0/24", "192.168.1.0/24"), strings(cfg, "routes").map { it.substringBefore(" ") })
    assertEquals(listOf("10.210.0.1"), strings(cfg, "dnsServers"))
    assertEquals(listOf("mesh.internal"), strings(cfg, "searchDomains"))
    assertEquals(listOf("org.example.browser", "org.example.mail"), strings(cfg, "allowedApplications"))
    assertNull(field<List<Any>?>(cfg, "disallowedApplications"))
    assertEquals(1400, field<Int>(cfg, "mtu"))
    assertEquals("mynet", field<String>(cfg, "session"))
  }

  @Test
  fun blacklistWrittenByThePickerIsApplied() {
    val dir = tmp.newFolder("net2")
    val file = File(dir, TincYaml.FILE_NAME).apply { writeText("networks:\n  net2:\n    options:\n      Name: phone\n      Ifconfig: 10.1.0.2/24\n") }
    SplitRouting(SplitRoutingMode.BLACKLIST, setOf("org.example.bank")).write(TincYaml(file), "net2")

    val cfg = config(TestVpnService().Builder().applyCfg(VpnInterfaceConfiguration.fromTincYaml(file, "net2")))
    assertEquals(listOf("org.example.bank"), strings(cfg, "disallowedApplications"))
    assertNull(field<List<Any>?>(cfg, "allowedApplications"))
  }

  @Test
  fun zeroConfigDocumentGetsPoolAddressAndRoute() {
    val cfg = config(builderFor("""
      |networks:
      |  mynet:
      |    options:
      |      Name: nodeA
      |      Mode: router
      |      Port: 655
      |      AddressPool: 10.165.0.0/24
      |    hosts:
      |      nodeA: |
      |        Subnet = 10.165.0.1/32
      |        Ed25519PublicKey = FP/bEGx2wj3svGRwyX9VzOgVIg3aaX8SmN2d7RTOz7H
      |""".trimMargin()))
    assertEquals(listOf("10.165.0.1/24"), strings(cfg, "addresses"))
    assertEquals(listOf("10.165.0.0/24"), strings(cfg, "routes").map { it.substringBefore(" ") })
    assertTrue(strings(cfg, "dnsServers").isEmpty())
  }

  @Test(expected = TincYaml.InvalidConfigurationException::class)
  fun mixedListsNeverReachTheBuilder() {
    builderFor("networks:\n  mynet:\n    options:\n      AllowApplication: a\n      DisallowApplication: b\n")
  }
}
