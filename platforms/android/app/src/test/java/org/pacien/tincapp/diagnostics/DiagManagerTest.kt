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

package org.pacien.tincapp.diagnostics

import android.content.ContextWrapper
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.lang.reflect.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale

class DiagManagerTest {
  @get:Rule
  val tmp = TemporaryFolder()

  private val selfLine =
    "phone id 0a0b0c at MYSELF port 0 cipher 0 digest 0 maclength 0 compression 0 options 700000c " +
      "status 0018 nexthop phone via phone distance 0 pmtu 1518 (min 0 max 1518) rx 0 0 tx 0 0 transports plain,sf"
  private val ruvdsUdpLine =
    "ruvds id 010203 at 198.51.100.10 port 443 cipher 0 digest 0 maclength 0 compression 0 options 700000c " +
      "status 00d6 nexthop ruvds via ruvds distance 1 pmtu 1420 (min 1420 max 1420) rx 100 50000 tx 120 60000 transports plain,sf,obfs,https,quic rtt 35.5"
  private val ruvdsTcpFallbackLine =
    "ruvds id 010203 at 198.51.100.10 port 443 cipher 0 digest 0 maclength 0 compression 0 options 700000c " +
      "status 0056 nexthop ruvds via ruvds distance 1 pmtu 1250 (min 1250 max 1420) rx 100 50000 tx 150 90000 transports plain,sf,obfs,https,quic rtt 480.0"

  @Test
  fun parseSnapshotAndDiagPingOutput() {
    val snap = DiagManager.buildSnapshotFromLines(
      net = "mynet",
      nodeLines = listOf(selfLine, ruvdsUdpLine),
      edgeLines = listOf("phone to ruvds at 198.51.100.10 port 443 local 10.0.0.2 port 51234 options 700000c weight 71"),
      subnetLines = listOf("10.99.0.5/32#10 owner phone", "10.99.0.1/32#10 owner ruvds"),
      connLines = listOf("ruvds at 198.51.100.10 port 443 options 700000c socket 6 status 5 transport quic"),
    )
    assertEquals(2, snap.nodes.size)
    val selfNode = snap.nodes["phone"]!!
    assertTrue(selfNode.isSelf)
    assertEquals("10.99.0.5", selfNode.vpnAddress)

    val peer = snap.nodes["ruvds"]!!
    assertFalse(peer.isSelf)
    assertTrue(peer.reachable)
    assertEquals("direct-udp", peer.link)
    assertEquals("quic", peer.transport)
    assertEquals("10.99.0.1", peer.vpnAddress)
    assertEquals(1420, peer.pmtu)
    assertEquals(35.5, peer.rtt, 1e-6)

    val pingOk = DiagManager.parseDiagPingOutput(
      listOf("OK from=10.99.0.1 node=ruvds type=0 code=0 rtt_ms=28.45 ttl=64 mtu=0 seq=1 size=56")
    )
    assertEquals(true, pingOk["ok"])
    assertEquals("echo_reply", pingOk["status"])
    assertEquals("10.99.0.1", pingOk["from_ip"])
    assertEquals("ruvds", pingOk["node"])
    assertEquals(28.45, (pingOk["rtt_ms"] as Number).toDouble(), 1e-6)

    val pingFrag = DiagManager.parseDiagPingOutput(
      listOf("OK from=10.99.0.1 node=ruvds type=3 code=4 rtt_ms=12.10 ttl=64 mtu=1380 seq=2 size=1444")
    )
    assertEquals(false, pingFrag["ok"])
    assertEquals("frag_needed", pingFrag["status"])
    assertEquals(1380, pingFrag["mtu"])

    // H-AND-10: selectBestVpnIp prioritizes InterfaceAddress/Ifconfig and /32 over 0.0.0.0/0 and /24
    assertEquals(
      "10.99.0.5",
      DiagManager.selectBestVpnIp(listOf("0.0.0.0/0#10", "::/0#10", "10.99.0.0/24#10", "10.99.0.5/32#10")),
    )
    assertEquals(
      "10.99.0.77",
      DiagManager.selectBestVpnIp(
        subnets = listOf("0.0.0.0/0#10", "10.99.0.5/32#10"),
        interfaceAddresses = listOf("10.99.0.77/24"),
      ),
    )

    // M-AND-09: transit peer without a direct metaconnection is classified as "relay", not "direct-tcp"
    val transitPeerLine =
      "leafB id 040506 at 198.51.100.22 port 655 cipher 0 digest 0 maclength 0 compression 0 options 700000c " +
        "status 0016 nexthop ruvds via ruvds distance 2 pmtu 1250 (min 1250 max 1420) rx 10 1000 tx 10 1000 transports plain rtt 55.0"
    val relaySnap = DiagManager.buildSnapshotFromLines(
      net = "mynet",
      nodeLines = listOf(selfLine, ruvdsTcpFallbackLine, transitPeerLine),
      subnetLines = listOf("0.0.0.0/0#10 owner ruvds", "10.99.0.0/24#10 owner ruvds", "10.99.0.1/32#10 owner ruvds"),
      connLines = listOf("ruvds at 198.51.100.10 port 443 options 700000c socket 6 status 5 transport https"),
    )
    assertEquals("direct-tcp", relaySnap.nodes["ruvds"]!!.link)
    assertEquals("10.99.0.1", relaySnap.nodes["ruvds"]!!.vpnAddress)
    assertEquals("relay", relaySnap.nodes["leafB"]!!.link)

    // Even if nexthop == name temporarily in dump nodes, without a direct connection it must be "relay"
    val noConnSnap = DiagManager.buildSnapshotFromLines(
      net = "mynet",
      nodeLines = listOf(selfLine, ruvdsTcpFallbackLine),
      connLines = emptyList(),
    )
    assertEquals("relay", noConnSnap.nodes["ruvds"]!!.link)
  }

  @Test
  fun telemetryCollectorDetectsAnomaliesAndPersistsEvents() {
    val dir = tmp.newFolder("diag-events")
    val collector = DiagManager.TelemetryCollector(dir)

    val s1 = DiagManager.buildSnapshotFromLines(
      net = "mynet",
      nodeLines = listOf(selfLine, ruvdsUdpLine),
      subnetLines = listOf("10.99.0.1/32#10 owner ruvds"),
      connLines = listOf("ruvds at 198.51.100.10 port 443 options 700000c socket 6 status 5 transport quic"),
    )
    collector.recordSnapshot("mynet", s1, now = 1000.0)

    val s2 = DiagManager.buildSnapshotFromLines(
      net = "mynet",
      nodeLines = listOf(selfLine, ruvdsTcpFallbackLine),
      subnetLines = listOf("10.99.0.1/32#10 owner ruvds"),
      connLines = listOf("ruvds at 198.51.100.10 port 443 options 700000c socket 6 status 5 transport https"),
    )
    collector.recordSnapshot("mynet", s2, now = 1002.5)
    collector.recordUserMark("mynet", "video freeze")

    val incs = collector.getIncidents("mynet")
    val kinds = incs.map { it["kind"] }.toSet()
    assertTrue(kinds.contains("UDP_FALLBACK"))
    assertTrue(kinds.contains("TRANSPORT_CHANGED"))
    assertTrue(kinds.contains("PMTU_DROP"))
    assertTrue(kinds.contains("RTT_SPIKE"))
    assertTrue(kinds.contains("USER_MARK"))

    // Verify persistence across new collector instance
    val collector2 = DiagManager.TelemetryCollector(dir)
    val incs2 = collector2.getIncidents("mynet")
    assertEquals(incs.size, incs2.size)
  }

  private fun inMemoryContext(backing: MutableMap<String, Any?> = HashMap()): ContextWrapper {
    lateinit var prefsProxy: SharedPreferences
    val editorProxy = Proxy.newProxyInstance(
      SharedPreferences.Editor::class.java.classLoader,
      arrayOf(SharedPreferences.Editor::class.java),
    ) { proxy, method, args ->
      when (method.name) {
        "putString", "putInt", "putBoolean", "putLong", "putFloat" -> {
          val k = args?.getOrNull(0) as? String
          if (k != null) backing[k] = args.getOrNull(1)
          proxy
        }
        "remove" -> {
          backing.remove(args?.getOrNull(0) as? String)
          proxy
        }
        "clear" -> {
          backing.clear()
          proxy
        }
        "commit" -> true
        "apply" -> Unit
        else -> null
      }
    } as SharedPreferences.Editor

    prefsProxy = Proxy.newProxyInstance(
      SharedPreferences::class.java.classLoader,
      arrayOf(SharedPreferences::class.java),
    ) { _, method, args ->
      when (method.name) {
        "getString" -> (backing[args?.getOrNull(0) as? String] as? String) ?: args?.getOrNull(1)
        "getBoolean" -> (backing[args?.getOrNull(0) as? String] as? Boolean) ?: (args?.getOrNull(1) as? Boolean ?: false)
        "getInt" -> (backing[args?.getOrNull(0) as? String] as? Int) ?: (args?.getOrNull(1) as? Int ?: 0)
        "contains" -> backing.containsKey(args?.getOrNull(0) as? String)
        "getAll" -> HashMap(backing)
        "edit" -> editorProxy
        else -> null
      }
    } as SharedPreferences

    return object : ContextWrapper(null) {
      override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences = prefsProxy
    }
  }

  @Test
  fun ensurePasswordPersistsAndReusesAcrossRestarts() {
    val store = HashMap<String, Any?>()
    val ctx = inMemoryContext(store)
    try {
      DiagManager.resetAuthForTests()
      val first = DiagManager.ensurePassword(ctx)
      assertEquals(16, first.length)
      assertTrue(first.all { it in "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789" })
      assertEquals(first, store["password"])

      // Simulate process restart by clearing in-memory password & sessions
      DiagManager.resetAuthForTests()
      val afterRestart = DiagManager.ensurePassword(ctx)
      assertEquals(first, afterRestart)
      assertEquals(first, DiagManager.getPassword(ctx))

      // L-AND-04: Regenerating password rotates stored secret
      val rotated = DiagManager.regeneratePassword(ctx)
      assertEquals(16, rotated.length)
      assertFalse(first == rotated)
      assertEquals(rotated, store["password"])
      assertEquals(rotated, DiagManager.getPassword(ctx))
    } finally {
      DiagManager.resetAuthForTests()
    }
  }

  @Test
  fun yamlSecretRedactionAndRestoreAndScriptBlock() {
    val origYaml = """
      |networks:
      |  mynet:
      |    options:
      |      Name: phone1
      |      Port: 655
      |      CloudflareToken: cf_super_secret_token
      |      Ed25519PrivateKey: inline_ed_priv_secret
      |    hosts:
      |      phone1: |
      |        Ed25519PublicKey = PUBLIC_ED25519_KEY
      |        Subnet = 10.99.0.5/32
      |    keys:
      |      ed25519_priv: |
      |        -----BEGIN ED25519 PRIVATE KEY-----
      |        SECRET_ED25519_BYTES
      |        -----END ED25519 PRIVATE KEY-----
      |      rsa_priv: |
      |        -----BEGIN RSA PRIVATE KEY-----
      |        SECRET_RSA_BYTES
      |        -----END RSA PRIVATE KEY-----
      |      tls_cert: |
      |        -----BEGIN CERTIFICATE-----
      |        PUBLIC_TLS_CERT_BYTES
      |        -----END CERTIFICATE-----
      |      tls_key: |
      |        -----BEGIN PRIVATE KEY-----
      |        SECRET_TLS_KEY_BYTES
      |        -----END PRIVATE KEY-----
      |      acme_account: |
      |        -----BEGIN EC PRIVATE KEY-----
      |        SECRET_ACME_BYTES
      |        -----END EC PRIVATE KEY-----
      |""".trimMargin()

    val redacted = DiagManager.redactYamlSecrets(origYaml)
    assertFalse(redacted.contains("cf_super_secret_token"))
    assertFalse(redacted.contains("inline_ed_priv_secret"))
    assertFalse(redacted.contains("SECRET_ED25519_BYTES"))
    assertFalse(redacted.contains("SECRET_RSA_BYTES"))
    assertFalse(redacted.contains("SECRET_TLS_KEY_BYTES"))
    assertFalse(redacted.contains("SECRET_ACME_BYTES"))
    // Public cert and host public key remain visible
    assertTrue(redacted.contains("PUBLIC_TLS_CERT_BYTES"))
    assertTrue(redacted.contains("PUBLIC_ED25519_KEY"))

    val editedRedacted = redacted.replace("Port: 655", "Port: 8443")
    val restored = DiagManager.restoreYamlSecretsAndValidate(editedRedacted, origYaml)
    assertTrue(restored.contains("Port: 8443"))
    assertTrue(restored.contains("cf_super_secret_token"))
    assertTrue(restored.contains("inline_ed_priv_secret"))
    assertTrue(restored.contains("SECRET_ED25519_BYTES"))
    assertTrue(restored.contains("SECRET_RSA_BYTES"))
    assertTrue(restored.contains("SECRET_TLS_KEY_BYTES"))
    assertTrue(restored.contains("SECRET_ACME_BYTES"))
    assertFalse(restored.contains("***REDACTED***"))

    // Attempting to inject a `scripts:` section must be rejected
    val withInjectedScript = editedRedacted + "\n    scripts:\n      tinc-up: |\n        #!/bin/sh\n        id > /tmp/pwn\n"
    try {
      DiagManager.restoreYamlSecretsAndValidate(withInjectedScript, origYaml)
      fail("Expected scripts injection to be rejected")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("scripts"))
    }

    // C-AND-02: Attempting to inject `ScriptsInterpreter` (case-insensitive) in options or host block must be rejected
    val withInterpreterOpt = editedRedacted.replace("Port: 8443", "Port: 8443\n      scriptsinterpreter: /system/bin/sh")
    try {
      DiagManager.restoreYamlSecretsAndValidate(withInterpreterOpt, origYaml)
      fail("Expected ScriptsInterpreter injection in options to be rejected")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("ScriptsInterpreter", ignoreCase = true))
    }

    val withInterpreterHost = editedRedacted.replace(
      "Subnet = 10.99.0.5/32",
      "Subnet = 10.99.0.5/32\n        ScriptsInterpreter = /system/bin/sh",
    )
    try {
      DiagManager.restoreYamlSecretsAndValidate(withInterpreterHost, origYaml)
      fail("Expected ScriptsInterpreter injection in host block to be rejected")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("ScriptsInterpreter", ignoreCase = true))
    }

    // C-AND-02: Cross-section `<redacted>` / `***REDACTED***` exfiltration into public options/hosts must be rejected
    val crossSectionOpt = editedRedacted.replace("Name: phone1", "Name: \"<redacted>\"")
    try {
      DiagManager.restoreYamlSecretsAndValidate(crossSectionOpt, origYaml)
      fail("Expected <redacted> in non-secret option to be rejected")
    } catch (_: IllegalArgumentException) {
    }

    val crossSectionHost = editedRedacted.replace("Subnet = 10.99.0.5/32", "Subnet = ***REDACTED***")
    try {
      DiagManager.restoreYamlSecretsAndValidate(crossSectionHost, origYaml)
      fail("Expected ***REDACTED*** in host Subnet to be rejected")
    } catch (_: IllegalArgumentException) {
    }

    // C-AND-02: YAML anchors (&), aliases (*), and merge keys (<<) must be rejected
    val anchorExploit = """
      |networks:
      |  mynet:
      |    keys:
      |      ed25519_priv: &leak "***REDACTED***"
      |    options:
      |      Name: *leak
      |""".trimMargin()
    try {
      DiagManager.restoreYamlSecretsAndValidate(anchorExploit, origYaml)
      fail("Expected YAML anchor/alias to be rejected")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("aliases") || e.message!!.contains("anchors"))
    }

    val mergeExploit = """
      |networks:
      |  mynet:
      |    options:
      |      <<: { Name: phone1 }
      |""".trimMargin()
    try {
      DiagManager.restoreYamlSecretsAndValidate(mergeExploit, origYaml)
      fail("Expected YAML merge key (<<) to be rejected")
    } catch (e: IllegalArgumentException) {
      assertTrue(e.message!!.contains("merge"))
    }

    // C-AND-02: ObfsPassword, Obfs*MagicHeader, acme_account, and Proxy credentials redact & restore cleanly
    val obfsAndProxyYaml = """
      |networks:
      |  mynet:
      |    options:
      |      Name: phone1
      |      ObfsPassword: my_obfs_secret_pass
      |      ObfsInitMagicHeader: 123456789
      |      Proxy: socks5 127.0.0.1 1080 proxyuser proxypassword
      |    hosts:
      |      hub: |
      |        Address = 198.51.100.10
      |        ObfsPassword = peer_obfs_secret
      |        Proxy = http://alice:topsecret@10.0.0.1:8080
      |""".trimMargin()
    val redactedObfs = DiagManager.redactYamlSecrets(obfsAndProxyYaml)
    assertFalse(redactedObfs.contains("my_obfs_secret_pass"))
    assertFalse(redactedObfs.contains("123456789"))
    assertFalse(redactedObfs.contains("proxyuser"))
    assertFalse(redactedObfs.contains("proxypassword"))
    assertFalse(redactedObfs.contains("peer_obfs_secret"))
    assertFalse(redactedObfs.contains("topsecret"))
    assertTrue(redactedObfs.contains("socks5 127.0.0.1 1080"))

    val restoredObfs = DiagManager.restoreYamlSecretsAndValidate(redactedObfs, obfsAndProxyYaml)
    assertTrue(restoredObfs.contains("my_obfs_secret_pass"))
    assertTrue(restoredObfs.contains("123456789"))
    assertTrue(restoredObfs.contains("socks5 127.0.0.1 1080 proxyuser proxypassword"))
    assertTrue(restoredObfs.contains("peer_obfs_secret"))
    assertTrue(restoredObfs.contains("http://alice:topsecret@10.0.0.1:8080"))

    // L-AND-01: JsonCodec.parse falls back to Double on integers overflowing signed 64-bit Long
    val bigJson = DiagManager.JsonCodec.parse("""{"ok":true,"big":99999999999999999999999999}""") as Map<*, *>
    assertTrue(bigJson["big"] is Double)
  }

  private data class RawHttpResponse(
    val status: Int,
    val headers: Map<String, String>,
    val body: String,
  )

  private fun sendHttp(
    port: Int,
    method: String,
    path: String,
    headers: Map<String, String> = emptyMap(),
    body: String = "",
  ): RawHttpResponse {
    Socket("127.0.0.1", port).use { sock ->
      sock.soTimeout = 10_000
      val bodyBytes = body.toByteArray(StandardCharsets.UTF_8)
      val sb = StringBuilder()
      sb.append("$method $path HTTP/1.1\r\n")
      if (headers.keys.none { it.equals("Host", ignoreCase = true) }) {
        sb.append("Host: 127.0.0.1:$port\r\n")
      }
      for ((k, v) in headers) {
        sb.append("$k: $v\r\n")
      }
      if (bodyBytes.isNotEmpty() && headers.keys.none { it.equals("Content-Length", ignoreCase = true) }) {
        sb.append("Content-Length: ${bodyBytes.size}\r\n")
      }
      sb.append("Connection: close\r\n\r\n")
      val out = sock.getOutputStream()
      out.write(sb.toString().toByteArray(StandardCharsets.UTF_8))
      if (bodyBytes.isNotEmpty()) out.write(bodyBytes)
      out.flush()

      val rawResp = sock.getInputStream().readBytes().toString(StandardCharsets.UTF_8)
      val sepIdx = rawResp.indexOf("\r\n\r\n")
      val hdrBlock = if (sepIdx >= 0) rawResp.substring(0, sepIdx) else rawResp
      val respBody = if (sepIdx >= 0) rawResp.substring(sepIdx + 4) else ""
      val hdrLines = hdrBlock.split("\r\n")
      val status = hdrLines.firstOrNull()?.split(' ')?.getOrNull(1)?.toIntOrNull() ?: 0
      val respHeaders = LinkedHashMap<String, String>()
      for (line in hdrLines.drop(1)) {
        val c = line.indexOf(':')
        if (c > 0) {
          respHeaders[line.substring(0, c).trim().lowercase(Locale.ROOT)] = line.substring(c + 1).trim()
        }
      }
      return RawHttpResponse(status, respHeaders, respBody)
    }
  }

  @Test
  fun embeddedHttpServerServesWebUiAndApiWithPasswordAuthAndSecurityGuards() {
    DiagManager.resetAuthForTests()
    DiagManager.testKnownNetsOverride = setOf("mynet")
    val freePort = ServerSocket(0).use { it.localPort }
    val origin = "http://127.0.0.1:$freePort"
    try {
      val (ok, _) = DiagManager.startServer(freePort)
      assertTrue(ok)
      assertTrue(DiagManager.isEnabled())
      val pwd = DiagManager.getPassword()
      assertEquals(16, pwd.length)

      // 1. Unauthenticated GET / serves login HTML, NOT dashboard
      val loginPage = sendHttp(freePort, "GET", "/")
      assertEquals(200, loginPage.status)
      assertTrue(loginPage.body.contains("/api/login"))
      assertFalse(loginPage.body.contains("peers-tbody"))

      // 2. Unauthenticated GET /api/overview & POST /api/mark return 401 BEFORE reading body (H-AND-01)
      assertEquals(401, sendHttp(freePort, "GET", "/api/overview?net=mynet").status)
      assertEquals(
        401,
        sendHttp(
          freePort,
          "POST",
          "/api/mark",
          headers = mapOf("Origin" to origin, "X-Diag-CSRF" to "1", "Content-Type" to "application/json"),
          body = """{"net":"mynet","note":"unauth"}""",
        ).status,
      )
      Socket("127.0.0.1", freePort).use { sock ->
        sock.soTimeout = 5_000
        val preAuthHugeReq = "POST /api/action HTTP/1.1\r\n" +
          "Host: 127.0.0.1:$freePort\r\n" +
          "Origin: $origin\r\n" +
          "X-Diag-CSRF: 1\r\n" +
          "Content-Type: application/json\r\n" +
          "Content-Length: 4000000\r\n\r\n"
        sock.getOutputStream().write(preAuthHugeReq.toByteArray(StandardCharsets.UTF_8))
        sock.getOutputStream().flush()
        val firstLine = sock.getInputStream().bufferedReader().readLine()
        assertTrue("Expected immediate 401 before body read, got: $firstLine", firstLine.contains("401"))
      }

      // 3. Login CSRF & cap guards: missing X-Diag-CSRF -> 403, wrong port Origin -> 403, >1024B -> 413, wrong pwd -> 401
      assertEquals(
        403,
        sendHttp(
          freePort,
          "POST",
          "/api/login",
          headers = mapOf("Origin" to origin, "Content-Type" to "application/json"),
          body = """{"password":"$pwd"}""",
        ).status,
      )
      assertEquals(
        403,
        sendHttp(
          freePort,
          "POST",
          "/api/login",
          headers = mapOf(
            "Origin" to "http://127.0.0.1:${freePort + 1}",
            "X-Diag-CSRF" to "1",
            "Content-Type" to "application/json",
          ),
          body = """{"password":"$pwd"}""",
        ).status,
      )
      assertEquals(
        413,
        sendHttp(
          freePort,
          "POST",
          "/api/login",
          headers = mapOf("Origin" to origin, "X-Diag-CSRF" to "1", "Content-Type" to "application/json"),
          body = """{"password":"${"a".repeat(1200)}"}""",
        ).status,
      )
      assertEquals(
        401,
        sendHttp(
          freePort,
          "POST",
          "/api/login",
          headers = mapOf("Origin" to origin, "X-Diag-CSRF" to "1", "Content-Type" to "application/json"),
          body = """{"password":"wrongpassword"}""",
        ).status,
      )

      // 4. Valid login issues HttpOnly SameSite=Strict session cookie
      val goodLogin = sendHttp(
        freePort,
        "POST",
        "/api/login",
        headers = mapOf("Origin" to origin, "X-Diag-CSRF" to "1", "Content-Type" to "application/json"),
        body = """{"password":"$pwd"}""",
      )
      assertEquals(200, goodLogin.status)
      val setCookie = goodLogin.headers["set-cookie"]
      assertNotNull(setCookie)
      assertTrue(setCookie!!.contains("tinc_diag_sid="))
      assertTrue(setCookie.contains("HttpOnly"))
      assertTrue(setCookie.contains("SameSite=Strict"))
      val cookiePair = setCookie.substringBefore(";")

      // 5. Authenticated GET / serves full WebUI with Logout button
      val dashResp = sendHttp(freePort, "GET", "/", headers = mapOf("Cookie" to cookiePair))
      assertEquals(200, dashResp.status)
      assertTrue(dashResp.body.contains("peers-tbody"))
      assertTrue(dashResp.body.contains("logoutDiag()"))

      // 6. Authenticated GET /api/overview (and /api/state) and malformed %ZZ query resilience (AN-02)
      val ovResp = sendHttp(freePort, "GET", "/api/overview?net=mynet&bad=%ZZ", headers = mapOf("Cookie" to cookiePair))
      assertEquals(200, ovResp.status)
      val ovJson = DiagManager.JsonCodec.parse(ovResp.body) as Map<*, *>
      assertEquals(true, ovJson["ok"])
      assertEquals("android", ovJson["platform"])
      assertEquals(
        200,
        sendHttp(freePort, "GET", "/api/state?net=mynet", headers = mapOf("Cookie" to cookiePair)).status,
      )

      // 7. Path traversal & unknown network rejection (AN-01)
      assertEquals(
        400,
        sendHttp(freePort, "GET", "/api/logs?net=../../etc/passwd", headers = mapOf("Cookie" to cookiePair)).status,
      )
      assertEquals(
        400,
        sendHttp(freePort, "GET", "/api/overview?net=nonexistent", headers = mapOf("Cookie" to cookiePair)).status,
      )

      // 8. CSRF: cookie-authenticated POST without X-Diag-CSRF, without Origin, or with cross-site/cross-port Origin returns 403
      assertEquals(
        403,
        sendHttp(
          freePort,
          "POST",
          "/api/mark",
          headers = mapOf("Cookie" to cookiePair, "Origin" to origin, "Content-Type" to "application/json"),
          body = """{"net":"mynet","note":"missing-csrf-hdr"}""",
        ).status,
      )
      assertEquals(
        403,
        sendHttp(
          freePort,
          "POST",
          "/api/mark",
          headers = mapOf("Cookie" to cookiePair, "X-Diag-CSRF" to "1", "Content-Type" to "application/json"),
          body = """{"net":"mynet","note":"csrf"}""",
        ).status,
      )
      assertEquals(
        403,
        sendHttp(
          freePort,
          "POST",
          "/api/mark",
          headers = mapOf(
            "Cookie" to cookiePair,
            "Origin" to "http://evil.example",
            "X-Diag-CSRF" to "1",
            "Content-Type" to "application/json",
          ),
          body = """{"net":"mynet","note":"csrf"}""",
        ).status,
      )
      assertEquals(
        403,
        sendHttp(
          freePort,
          "POST",
          "/api/mark",
          headers = mapOf(
            "Cookie" to cookiePair,
            "Origin" to "http://127.0.0.1:${freePort + 1}",
            "X-Diag-CSRF" to "1",
            "Content-Type" to "application/json",
          ),
          body = """{"net":"mynet","note":"cross-port-csrf"}""",
        ).status,
      )

      // 9. Authenticated POST /api/mark with valid Origin and X-Diag-CSRF succeeds
      val markRespHttp = sendHttp(
        freePort,
        "POST",
        "/api/mark",
        headers = mapOf(
          "Cookie" to cookiePair,
          "Origin" to origin,
          "X-Diag-CSRF" to "1",
          "Content-Type" to "application/json",
        ),
        body = """{"net":"mynet","note":"test lag from junit"}""",
      )
      assertEquals(200, markRespHttp.status)
      val markResp = DiagManager.JsonCodec.parse(markRespHttp.body) as Map<*, *>
      assertEquals(true, markResp["ok"])

      // 10. Authorization: Bearer, Basic, and X-Diag-Password headers work (including CLI POST without Origin)
      val basicB64 = Base64.getEncoder().encodeToString("admin:$pwd".toByteArray(StandardCharsets.UTF_8))
      assertEquals(
        200,
        sendHttp(freePort, "GET", "/api/overview?net=mynet", headers = mapOf("Authorization" to "Basic $basicB64")).status,
      )
      assertEquals(
        200,
        sendHttp(freePort, "GET", "/api/overview?net=mynet", headers = mapOf("X-Diag-Password" to pwd)).status,
      )
      assertEquals(
        200,
        sendHttp(
          freePort,
          "POST",
          "/api/mark",
          headers = mapOf("Authorization" to "Bearer $pwd", "X-Diag-CSRF" to "1", "Content-Type" to "application/json"),
          body = """{"net":"mynet","note":"cli bearer"}""",
        ).status,
      )

      // 11. DNS rebinding & cross-port check on Host header & truncated body check (AN-01, AN-11, C-AND-02)
      assertTrue(DiagManager.isAllowedHost("[::1]:$freePort", expectedPort = freePort))
      assertTrue(DiagManager.isAllowedHost("10.99.0.5:$freePort", setOf("10.99.0.5"), expectedPort = freePort))
      assertFalse(DiagManager.isAllowedHost("127.0.0.1:${freePort + 1}", expectedPort = freePort))
      assertFalse(DiagManager.isAllowedHost("evil.rebind.test:$freePort", setOf("10.99.0.5"), expectedPort = freePort))

      assertEquals(
        403,
        sendHttp(freePort, "GET", "/", headers = mapOf("Host" to "evil.rebind.test:$freePort")).status,
      )
      assertEquals(
        403,
        sendHttp(freePort, "GET", "/", headers = mapOf("Host" to "127.0.0.1:${freePort + 1}")).status,
      )

      Socket("127.0.0.1", freePort).use { sock ->
        val partialBody = """{"net":"mynet""""
        val rawReq = "POST /api/mark HTTP/1.1\r\n" +
          "Host: 127.0.0.1:$freePort\r\n" +
          "Authorization: Bearer $pwd\r\n" +
          "X-Diag-CSRF: 1\r\n" +
          "Content-Type: application/json\r\n" +
          "Content-Length: 100\r\n\r\n" +
          partialBody
        sock.getOutputStream().write(rawReq.toByteArray(StandardCharsets.UTF_8))
        sock.getOutputStream().flush()
        sock.shutdownOutput()
        val firstLine = sock.getInputStream().bufferedReader().readLine()
        assertTrue(firstLine.contains("400"))
      }

      // 12. Logout invalidates session cookie
      assertEquals(
        200,
        sendHttp(
          freePort,
          "POST",
          "/api/logout",
          headers = mapOf(
            "Cookie" to cookiePair,
            "Origin" to origin,
            "X-Diag-CSRF" to "1",
            "Content-Type" to "application/json",
          ),
          body = "{}",
        ).status,
      )
      assertEquals(
        401,
        sendHttp(freePort, "GET", "/api/overview?net=mynet", headers = mapOf("Cookie" to cookiePair)).status,
      )

      // 13. Brute-force rate-limiting on /api/login returns 429 after repeated failures (H-AND-01)
      val attemptStatuses = (1..4).map {
        sendHttp(
          freePort,
          "POST",
          "/api/login",
          headers = mapOf("Origin" to origin, "X-Diag-CSRF" to "1", "Content-Type" to "application/json"),
          body = """{"password":"wrong-attempt-$it"}""",
        ).status
      }
      assertEquals(listOf(401, 401, 401, 429), attemptStatuses)
    } finally {
      DiagManager.testKnownNetsOverride = null
      DiagManager.stopServer(persist = false)
      DiagManager.resetAuthForTests()
      assertFalse(DiagManager.isEnabled())
    }
  }
}
