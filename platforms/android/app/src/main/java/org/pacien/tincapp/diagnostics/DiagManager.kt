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

import android.content.Context
import android.os.Build
import android.os.PowerManager
import org.pacien.tincapp.BuildConfig
import org.pacien.tincapp.commands.Executor
import org.pacien.tincapp.context.App
import org.pacien.tincapp.context.AppPaths
import org.pacien.tincapp.data.Networks
import org.pacien.tincapp.data.TincYaml
import org.pacien.tincapp.data.Transport
import org.pacien.tincapp.data.VpnInterfaceConfiguration
import org.pacien.tincapp.service.TincVpnService
import org.slf4j.LoggerFactory
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.roundToLong

/**
 * Local Telemetry & Incident Collector, Active Diagnostic Prober, and
 * Opt-In Remote Diagnostic Web Server (`http://<vpn-ip>:8655/`) for Android.
 */
object DiagManager {
  private val log by lazy { LoggerFactory.getLogger(DiagManager::class.java)!! }

  const val DEFAULT_DIAG_PORT = 8655
  const val SERIES_MAX_POINTS = 3600
  const val INCIDENTS_MAX = 500
  private const val EVENTS_FILE_MAX_BYTES = 2L * 1024 * 1024
  private const val MAX_HTTP_BODY_BYTES = 4L * 1024 * 1024
  private const val MAX_HTTP_HEADERS = 128
  private const val MAX_HEADER_LINE_LEN = 8192
  private const val PREFS_NAME = "diag_settings"
  private const val PREF_ENABLED = "enabled"
  private const val PREF_PORT = "port"
  private const val PREF_PASSWORD = "password"
  private const val PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
  private const val PASSWORD_LEN = 16
  internal const val SESSION_COOKIE_NAME = "tinc_diag_sid"
  private const val MAX_SESSIONS = 64
  private const val SESSION_TTL_MS = 24L * 60 * 60 * 1000L
  private const val REDACTED_MARKER = "***REDACTED***"
  private val SECRET_OPTION_KEYS = setOf(
    "ed25519privatekey",
    "privatekey",
    "cloudflaretoken",
    "acmeaccountkey",
    "obfspassword",
  )
  private val SAFE_NET_NAME_RE = Regex("^[A-Za-z0-9_.-]{1,64}$")
  private val SAFE_NODE_NAME_RE = Regex("^[A-Za-z0-9_.-]{1,64}$")
  private val SAFE_PROBE_HOST_RE = Regex("^[A-Za-z0-9_.:\\[\\]-]{1,253}$")

  val STATUS_BITS = listOf(
    0x0001 to "unused_active",
    0x0002 to "validkey",
    0x0004 to "waitingforkey",
    0x0008 to "visited",
    0x0010 to "reachable",
    0x0020 to "indirect",
    0x0040 to "sptps",
    0x0080 to "udp_confirmed",
    0x0100 to "send_locally",
    0x0200 to "udppacket",
    0x0400 to "validkey_in",
    0x0800 to "has_address",
    0x1000 to "ping_sent",
    0x2000 to "sptps_route_stale",
    0x4000 to "udp_addr_confirmed",
    0x8000 to "no_direct",
  )

  fun decodeStatus(statusHex: String): Map<String, Boolean> {
    val clean = statusHex.trim().removePrefix("0x").removePrefix("0X")
    val bits = clean.toIntOrNull(16) ?: 0
    return STATUS_BITS.associate { (mask, name) -> name.trim() to ((bits and mask) != 0) }
  }

  data class DiagNode(
    val name: String,
    var id: String = "",
    var address: String = "",
    var port: String = "",
    var options: String = "0",
    var statusHex: String = "0",
    var status: Map<String, Boolean> = emptyMap(),
    var nexthop: String = "-",
    var via: String = "-",
    var distance: Int = -1,
    var pmtu: Int = 0,
    var pmtuMin: Int = 0,
    var pmtuMax: Int = 0,
    var rxPackets: Long = 0,
    var rxBytes: Long = 0,
    var txPackets: Long = 0,
    var txBytes: Long = 0,
    var rtt: Double = 0.0,
    var supportedTransports: List<String> = emptyList(),
    var subnets: MutableList<String> = mutableListOf(),
    var transport: String = "",
  ) {
    val isSelf: Boolean get() = address == "MYSELF"
    val reachable: Boolean get() = isSelf || (status["reachable"] == true)
    val link: String
      get() {
        if (isSelf) return "self"
        if (!reachable) return "unreachable"
        val relay = via != "-" && via != name
        return when {
          status["udp_confirmed"] == true && !relay -> "direct-udp"
          !relay -> "direct-tcp"
          else -> "relay"
        }
      }
    val vpnAddress: String
      get() {
        for (s in subnets) {
          val ip = s.substringBefore('#').substringBefore('/')
          if (ip.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$""")) && ip != "0.0.0.0") {
            return ip
          }
        }
        return ""
      }
  }

  data class DiagEdge(
    val fromNode: String,
    val toNode: String,
    var address: String = "",
    var port: String = "",
    var localAddress: String = "",
    var localPort: String = "",
    var options: String = "0",
    var weight: Int = 0,
  ) {
    fun toMap(): Map<String, Any?> = mapOf(
      "from_node" to fromNode,
      "to_node" to toNode,
      "address" to address,
      "port" to port,
      "local_address" to localAddress,
      "local_port" to localPort,
      "options" to options,
      "weight" to weight,
    )
  }

  data class DiagSnapshot(
    val net: String,
    var nodes: Map<String, DiagNode> = emptyMap(),
    var edges: List<DiagEdge> = emptyList(),
    var subnets: List<Pair<String, String>> = emptyList(),
    var connections: Map<String, String> = emptyMap(),
    var error: String = "",
  )

  fun parseNodes(lines: List<String>): Map<String, DiagNode> {
    val out = LinkedHashMap<String, DiagNode>()
    for (line in lines) {
      val t = line.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
      if (t.size < 4 || t[1] != "id") continue
      val n = DiagNode(name = t[0], id = t[2])
      var i = 3
      if (i < t.size && t[i] == "at") {
        if (i + 1 < t.size && t[i + 1] == "MYSELF") {
          n.address = "MYSELF"
          n.port = ""
          i += 2
        } else if (i + 3 < t.size && t[i + 2] == "port") {
          n.address = t[i + 1]
          n.port = t[i + 3]
          i += 4
        }
      }
      while (i < t.size) {
        when (t[i]) {
          "cipher", "digest", "maclength", "compression" -> i += 2
          "options" -> {
            if (i + 1 < t.size) n.options = t[i + 1]
            i += 2
          }
          "status" -> {
            if (i + 1 < t.size) {
              n.statusHex = t[i + 1]
              n.status = decodeStatus(n.statusHex)
            }
            i += 2
          }
          "nexthop" -> {
            if (i + 1 < t.size) n.nexthop = t[i + 1]
            i += 2
          }
          "via" -> {
            if (i + 1 < t.size) n.via = t[i + 1]
            i += 2
          }
          "distance" -> {
            if (i + 1 < t.size) n.distance = t[i + 1].toIntOrNull() ?: -1
            i += 2
          }
          "pmtu" -> {
            if (i + 1 < t.size) n.pmtu = t[i + 1].toIntOrNull() ?: 0
            i += 2
          }
          "(min" -> {
            if (i + 3 < t.size) {
              n.pmtuMin = t[i + 1].toIntOrNull() ?: 0
              n.pmtuMax = t[i + 3].trimEnd(')').toIntOrNull() ?: 0
            }
            i += 4
          }
          "rx" -> {
            if (i + 2 < t.size) {
              n.rxPackets = t[i + 1].toLongOrNull() ?: 0L
              n.rxBytes = t[i + 2].toLongOrNull() ?: 0L
            }
            i += 3
          }
          "tx" -> {
            if (i + 2 < t.size) {
              n.txPackets = t[i + 1].toLongOrNull() ?: 0L
              n.txBytes = t[i + 2].toLongOrNull() ?: 0L
            }
            i += 3
          }
          "transports" -> {
            if (i + 1 < t.size && t[i + 1] != "-") {
              n.supportedTransports = t[i + 1].split(',').map { it.trim() }.filter { it.isNotEmpty() }
            }
            i += 2
          }
          "rtt" -> {
            if (i + 1 < t.size) {
              n.rtt = if (t[i + 1] == "-") 0.0 else (t[i + 1].toDoubleOrNull() ?: 0.0)
            }
            i += 2
          }
          else -> i += 1
        }
      }
      out[n.name] = n
    }
    return out
  }

  fun parseEdges(lines: List<String>): List<DiagEdge> {
    val out = mutableListOf<DiagEdge>()
    for (line in lines) {
      val t = line.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
      if (t.size < 3 || t[1] != "to") continue
      val e = DiagEdge(fromNode = t[0], toNode = t[2])
      var i = 3
      while (i < t.size) {
        when (t[i]) {
          "at" -> {
            if (i + 1 < t.size) e.address = t[i + 1]
            i += 2
          }
          "port" -> {
            if (i + 1 < t.size) {
              if (e.port.isEmpty()) e.port = t[i + 1] else e.localPort = t[i + 1]
            }
            i += 2
          }
          "local" -> {
            if (i + 1 < t.size) e.localAddress = t[i + 1]
            i += 2
          }
          "options" -> {
            if (i + 1 < t.size) e.options = t[i + 1]
            i += 2
          }
          "weight" -> {
            if (i + 1 < t.size) e.weight = t[i + 1].toIntOrNull() ?: 0
            i += 2
          }
          else -> i += 1
        }
      }
      out.add(e)
    }
    return out
  }

  fun parseSubnets(lines: List<String>): List<Pair<String, String>> =
    lines.mapNotNull { line ->
      val t = line.trim().split(Regex("\\s+"))
      if (t.size >= 3 && t[1] == "owner") t[0] to t[2] else null
    }

  fun parseConnections(lines: List<String>): Map<String, String> {
    val conns = LinkedHashMap<String, String>()
    for (line in lines) {
      val t = line.trim().split(Regex("\\s+"))
      if (t.size < 2 || t[1] != "at" || t[0].startsWith("<")) continue
      val name = t[0]
      var carrier = "plain"
      for (i in 2 until t.size - 1) {
        if (t[i] == "transport") {
          carrier = t[i + 1]
          break
        }
      }
      if (name !in conns || conns[name] == "plain") {
        conns[name] = carrier
      }
    }
    return conns
  }

  fun buildSnapshotFromLines(
    net: String,
    nodeLines: List<String>,
    edgeLines: List<String> = emptyList(),
    subnetLines: List<String> = emptyList(),
    connLines: List<String> = emptyList(),
  ): DiagSnapshot {
    val nodes = parseNodes(nodeLines)
    val edges = parseEdges(edgeLines)
    val subnets = parseSubnets(subnetLines)
    val conns = parseConnections(connLines)
    for ((sub, owner) in subnets) {
      nodes[owner]?.subnets?.add(sub)
    }
    for (n in nodes.values) {
      if (n.isSelf) continue
      val c = conns[n.name]
      if (c != null) {
        n.transport = c
      } else if (n.link == "direct-udp") {
        n.transport = "udp"
      } else if (n.link == "relay" && n.nexthop in conns) {
        n.transport = conns[n.nexthop] ?: ""
      }
    }
    return DiagSnapshot(net = net, nodes = nodes, edges = edges, subnets = subnets, connections = conns)
  }

  private fun applySafeTmpDir(pb: ProcessBuilder) {
    val tmpDir = try {
      AppPaths.runtimeDir().absolutePath
    } catch (_: Throwable) {
      System.getProperty("java.io.tmpdir", "/tmp") ?: "/tmp"
    }
    pb.environment()["TMPDIR"] = tmpDir
  }

  private fun execProcessWithTimeout(cmd: List<String>, timeoutMs: Long): Pair<Int, List<String>> {
    val pb = ProcessBuilder(cmd).redirectErrorStream(true)
    applySafeTmpDir(pb)
    val proc = pb.start()
    try {
      proc.outputStream.close()
    } catch (_: Exception) {
    }
    try {
      proc.errorStream.close()
    } catch (_: Exception) {
    }
    val readerFuture = Executor.supplyAsyncTask {
      try {
        proc.inputStream.bufferedReader(StandardCharsets.UTF_8).use { it.readLines() }
      } catch (_: Exception) {
        emptyList()
      }
    }
    val finished = Executor.waitForProcess(proc, timeoutMs)
    if (!finished) {
      Executor.destroyProcessForcibly(proc)
      try {
        proc.inputStream.close()
      } catch (_: Exception) {
      }
      return 124 to listOf("TIMEOUT")
    }
    val lines = try {
      readerFuture.get(2000L, TimeUnit.MILLISECONDS)
    } catch (_: Exception) {
      try {
        proc.inputStream.close()
      } catch (_: Exception) {
      }
      emptyList()
    }
    return proc.exitValue() to lines
  }

  /**
   * Executes `libtinc.so` directly on the calling background thread with an API 21+
   * compatible process timeout (`Executor.waitForProcess` + `destroyProcessForcibly`)
   * and concurrent pipe draining so >64 KB output never deadlocks.
   */
  private fun runTincCli(netName: String, timeoutMs: Long = 3000L, vararg args: String): Pair<Int, List<String>> {
    if (!isKnownValidNet(netName)) {
      return 1 to listOf("Invalid network name")
    }
    return try {
      val yamlFile = AppPaths.tincYamlFile(netName)
      val stanza = TincYaml(yamlFile).resolveNetwork(netName)
      val cmd = ArrayList<String>(args.size + 4)
      cmd.add(AppPaths.tinc().absolutePath)
      cmd.add("--config=${yamlFile.absolutePath}")
      cmd.add("--net=$stanza")
      cmd.add("--pidfile=${AppPaths.pidFile(netName).absolutePath}")
      cmd.addAll(args)
      execProcessWithTimeout(cmd, timeoutMs)
    } catch (e: Exception) {
      1 to listOf(e.message ?: "tinc cli failed")
    }
  }

  fun captureLiveSnapshot(netName: String): DiagSnapshot {
    val (rc, nodeLines) = runTincCli(netName, 2500L, "dump", "nodes")
    if (rc != 0) {
      val err = nodeLines.firstOrNull()?.trim().orEmpty().ifEmpty { "Daemon not running" }
      return DiagSnapshot(net = netName, error = err)
    }
    val (_, edgeLines) = runTincCli(netName, 2000L, "dump", "edges")
    val (_, subnetLines) = runTincCli(netName, 2000L, "dump", "subnets")
    val (_, connLines) = runTincCli(netName, 2000L, "dump", "connections")
    return buildSnapshotFromLines(netName, nodeLines, edgeLines, subnetLines, connLines)
  }

  fun parseDiagPingOutput(lines: List<String>): Map<String, Any?> {
    val line = lines.firstOrNull()?.trim().orEmpty()
    if (line.startsWith("OK ")) {
      val kv = LinkedHashMap<String, String>()
      for (tok in line.substring(3).trim().split(Regex("\\s+"))) {
        val eq = tok.indexOf('=')
        if (eq > 0) kv[tok.substring(0, eq)] = tok.substring(eq + 1)
      }
      val icmpType = kv["type"]?.toIntOrNull() ?: -1
      val icmpCode = kv["code"]?.toIntOrNull() ?: -1
      val status = when {
        icmpType == 0 -> "echo_reply"
        icmpType == 11 -> "time_exceeded"
        icmpType == 3 && icmpCode == 4 -> "frag_needed"
        else -> "unreachable"
      }
      return mapOf(
        "ok" to (icmpType == 0),
        "replied" to true,
        "status" to status,
        "from_ip" to (kv["from"] ?: ""),
        "node" to (kv["node"] ?: "-"),
        "icmp_type" to icmpType,
        "icmp_code" to icmpCode,
        "rtt_ms" to (kv["rtt_ms"]?.toDoubleOrNull() ?: 0.0),
        "ttl" to (kv["ttl"]?.toIntOrNull() ?: 0),
        "mtu" to (kv["mtu"]?.toIntOrNull() ?: 0),
        "raw" to line,
      )
    }
    return mapOf(
      "ok" to false,
      "replied" to false,
      "status" to if ("TIMEOUT" in line) "timeout" else "error",
      "from_ip" to "",
      "node" to "",
      "rtt_ms" to null,
      "ttl" to 0,
      "mtu" to 0,
      "raw" to line.ifEmpty { "no reply" },
    )
  }

  fun parseHostEndpoints(hostText: String?): Map<String, Any?> {
    val addresses = mutableListOf<Pair<String, String>>()
    var port = 655
    var httpsPort = 0
    var quicPort = 0
    var obfsPort = 0
    val subnets = mutableListOf<String>()
    var prefTransport = "auto"

    for (raw in (hostText ?: "").lineSequence()) {
      val line = raw.substringBefore('#').trim()
      val eq = line.indexOf('=')
      if (line.isEmpty() || eq <= 0) continue
      val k = line.substring(0, eq).trim().lowercase()
      val v = line.substring(eq + 1).trim()
      when (k) {
        "address" -> {
          val parts = v.split(Regex("\\s+")).filter { it.isNotEmpty() }
          if (parts.isNotEmpty()) addresses.add(parts[0] to (parts.getOrNull(1) ?: ""))
        }
        "port" -> v.split(Regex("\\s+")).firstOrNull()?.toIntOrNull()?.let { port = it }
        "httpsport" -> v.split(Regex("\\s+")).firstOrNull()?.toIntOrNull()?.let { httpsPort = it }
        "quicport" -> v.split(Regex("\\s+")).firstOrNull()?.toIntOrNull()?.let { quicPort = it }
        "obfsport" -> v.split(Regex("\\s+")).firstOrNull()?.toIntOrNull()?.let { obfsPort = it }
        "subnet" -> subnets.add(v)
        "preferredtransport", "preferredtransports" -> {
          val tok = v.split(',', ' ').map { it.trim().lowercase() }.firstOrNull { it.isNotEmpty() }
          if (!tok.isNullOrEmpty()) prefTransport = tok
        }
      }
    }
    return mapOf(
      "addresses" to addresses,
      "configured_address" to (addresses.firstOrNull()?.first ?: ""),
      "port" to port,
      "https_port" to httpsPort,
      "quic_port" to quicPort,
      "obfs_port" to obfsPort,
      "subnets" to subnets,
      "preferred_transport" to prefTransport,
    )
  }

  data class IncidentEvent(
    val ts: Double,
    val net: String,
    val kind: String,
    val severity: String,
    val peer: String = "",
    val summary: String = "",
    val details: Map<String, Any?> = emptyMap(),
  ) {
    fun toMap(): Map<String, Any?> {
      val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
      return mapOf(
        "ts" to ((ts * 1000.0).roundToLong() / 1000.0),
        "time_str" to sdf.format(Date((ts * 1000.0).toLong())),
        "net" to net,
        "kind" to kind,
        "severity" to severity,
        "peer" to peer,
        "summary" to summary,
        "message" to summary,
        "details" to details,
      )
    }
  }

  private class PeerTrack(
    var link: String = "",
    var transport: String = "",
    var nexthop: String = "",
    var rtt: Double = 0.0,
    var pmtu: Int = 0,
    var rxBytes: Long = 0,
    var txBytes: Long = 0,
    var reachable: Boolean = false,
    var validkey: Boolean = false,
    var udpConfirmed: Boolean = false,
    var txOnlyStreak: Int = 0,
    var keyWaitStreak: Int = 0,
    var initialized: Boolean = false,
  )

  class TelemetryCollector(private val baseDir: File) {
    private val lock = Any()
    private val series = HashMap<String, ArrayDeque<Map<String, Any?>>>()
    private val incidents = HashMap<String, ArrayDeque<IncidentEvent>>()
    private val peerState = HashMap<Pair<String, String>, PeerTrack>()
    private val lastTotals = HashMap<String, Triple<Double, Long, Long>>()
    private val latestSnap = HashMap<String, DiagSnapshot>()
    private val latestSnapTs = HashMap<String, Double>()

    init {
      loadPersistedEvents()
    }

    fun eventsFile(net: String): File {
      val safe = net.replace(Regex("[^A-Za-z0-9_.-]"), "_").let {
        if (it.isEmpty() || it == "." || it == ".." || ".." in it) "default" else it
      }
      return File(baseDir, "$safe-diag-events.jsonl")
    }

    @Suppress("UNCHECKED_CAST")
    private fun loadPersistedEvents() {
      if (!baseDir.isDirectory) return
      val files = baseDir.listFiles() ?: return
      for (f in files) {
        if (!f.name.endsWith("-diag-events.jsonl")) continue
        val net = f.name.removeSuffix("-diag-events.jsonl")
        val dq = incidents.getOrPut(net) { ArrayDeque() }
        try {
          val lines = f.readLines().takeLast(INCIDENTS_MAX)
          for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue
            val obj = JsonCodec.parse(trimmed) as? Map<String, Any?> ?: continue
            while (dq.size >= INCIDENTS_MAX) dq.removeFirst()
            dq.addLast(
              IncidentEvent(
                ts = (obj["ts"] as? Number)?.toDouble() ?: 0.0,
                net = (obj["net"] as? String) ?: net,
                kind = (obj["kind"] as? String) ?: "INFO",
                severity = (obj["severity"] as? String) ?: "info",
                peer = (obj["peer"] as? String) ?: "",
                summary = (obj["summary"] as? String) ?: (obj["message"] as? String) ?: "",
                details = (obj["details"] as? Map<String, Any?>) ?: emptyMap(),
              )
            )
          }
        } catch (_: Exception) {
        }
      }
    }

    private fun persistEvent(ev: IncidentEvent) {
      try {
        baseDir.mkdirs()
        val f = eventsFile(ev.net)
        if (f.isFile && f.length() > EVENTS_FILE_MAX_BYTES) {
          val bak = File(baseDir, "${f.name}.1")
          f.renameTo(bak)
        }
        f.appendText(JsonCodec.stringify(ev.toMap()) + "\n")
      } catch (_: Exception) {
      }
    }

    fun clearIncidents(net: String) {
      synchronized(lock) {
        incidents.remove(net)
      }
      try {
        eventsFile(net).delete()
      } catch (_: Exception) {
      }
    }

    fun addIncident(
      net: String,
      kind: String,
      severity: String,
      summary: String,
      peer: String = "",
      details: Map<String, Any?> = emptyMap(),
      ts: Double = System.currentTimeMillis() / 1000.0,
    ): IncidentEvent {
      val ev = IncidentEvent(ts, net, kind, severity, peer, summary, details)
      synchronized(lock) {
        val dq = incidents.getOrPut(net) { ArrayDeque() }
        while (dq.size >= INCIDENTS_MAX) dq.removeFirst()
        dq.addLast(ev)
      }
      persistEvent(ev)
      return ev
    }

    fun recordUserMark(net: String, note: String = ""): IncidentEvent {
      val snap = synchronized(lock) { latestSnap[net] }
      val peerSummary = LinkedHashMap<String, Any?>()
      if (snap != null && snap.error.isEmpty()) {
        for ((name, n) in snap.nodes) {
          if (!n.isSelf) {
            peerSummary[name] = mapOf(
              "link" to n.link,
              "transport" to n.transport,
              "via" to n.nexthop,
              "rtt_ms" to ((n.rtt * 10.0).roundToLong() / 10.0),
              "pmtu" to n.pmtu,
              "status" to "0x${n.statusHex}",
              "rx_bytes" to n.rxBytes,
              "tx_bytes" to n.txBytes,
            )
          }
        }
      }
      val msg = note.trim().ifEmpty { "User marked lag / anomaly moment" }
      return addIncident(
        net = net,
        kind = "USER_MARK",
        severity = "mark",
        summary = msg,
        details = mapOf("note" to msg, "peers" to peerSummary),
      )
    }

    fun recordSnapshot(net: String, snap: DiagSnapshot, now: Double = System.currentTimeMillis() / 1000.0) {
      val prevSnap = synchronized(lock) {
        val p = latestSnap[net]
        latestSnap[net] = snap
        latestSnapTs[net] = now
        p
      }
      if (snap.error.isNotEmpty()) {
        if (prevSnap != null && prevSnap.error.isEmpty()) {
          addIncident(
            net = net,
            kind = "DAEMON_DOWN",
            severity = "error",
            summary = "Network '$net' stopped or control socket unreachable: ${snap.error}",
            ts = now,
          )
        }
        return
      }
      val selfNode = snap.nodes.values.firstOrNull { it.isSelf }?.name.orEmpty()
      if (prevSnap != null && prevSnap.error.isNotEmpty()) {
        addIncident(
          net = net,
          kind = "DAEMON_UP",
          severity = "info",
          summary = "Network '$net' is running (${selfNode.ifEmpty { "self" }})",
          ts = now,
        )
      }

      val totalRx = snap.nodes.values.filter { !it.isSelf }.sumOf { it.rxBytes }
      val totalTx = snap.nodes.values.filter { !it.isSelf }.sumOf { it.txBytes }

      var rxBps = 0.0
      var txBps = 0.0
      val prevTot = synchronized(lock) {
        val p = lastTotals[net]
        lastTotals[net] = Triple(now, totalRx, totalTx)
        p
      }
      if (prevTot != null) {
        val dt = now - prevTot.first
        if (dt > 0.2) {
          rxBps = max(0L, totalRx - prevTot.second) * 8.0 / dt
          txBps = max(0L, totalTx - prevTot.third) * 8.0 / dt
        }
      }

      val peersPoint = LinkedHashMap<String, Any?>()
      val peerRtt = LinkedHashMap<String, Double>()
      for ((name, n) in snap.nodes) {
        if (n.isSelf) continue
        val rttRounded = (n.rtt * 10.0).roundToLong() / 10.0
        peerRtt[name] = rttRounded
        peersPoint[name] = mapOf(
          "rtt" to rttRounded,
          "pmtu" to n.pmtu,
          "link" to n.link,
          "transport" to n.transport,
          "via" to n.nexthop,
          "rx" to n.rxBytes,
          "tx" to n.txBytes,
        )
        analyzePeer(net, n, now)
      }

      val point = mapOf(
        "ts" to ((now * 100.0).roundToLong() / 100.0),
        "rx_bps" to ((rxBps * 10.0).roundToLong() / 10.0),
        "tx_bps" to ((txBps * 10.0).roundToLong() / 10.0),
        "rx_bytes" to totalRx,
        "tx_bytes" to totalTx,
        "peer_rtt" to peerRtt,
        "peers" to peersPoint,
      )
      synchronized(lock) {
        val dq = series.getOrPut(net) { ArrayDeque() }
        while (dq.size >= SERIES_MAX_POINTS) dq.removeFirst()
        dq.addLast(point)
      }
    }

    private fun analyzePeer(net: String, n: DiagNode, ts: Double) {
      val key = net to n.name
      val st = synchronized(lock) { peerState.getOrPut(key) { PeerTrack() } }
      val sdict = n.status.ifEmpty { decodeStatus(n.statusHex) }
      val reachable = sdict["reachable"] == true
      val validkey = sdict["validkey"] == true
      val udpConfirmed = sdict["udp_confirmed"] == true

      if (!st.initialized) {
        st.initialized = true
        st.link = n.link
        st.transport = n.transport
        st.nexthop = n.nexthop
        st.rtt = n.rtt
        st.pmtu = n.pmtu
        st.rxBytes = n.rxBytes
        st.txBytes = n.txBytes
        st.reachable = reachable
        st.validkey = validkey
        st.udpConfirmed = udpConfirmed
        return
      }

      if (st.reachable && !reachable) {
        addIncident(
          net = net,
          kind = "PEER_DOWN",
          severity = "error",
          peer = n.name,
          summary = "Peer '${n.name}' became unreachable (was ${st.link} via ${st.transport.ifEmpty { st.nexthop.ifEmpty { "mesh" } }})",
          details = mapOf("prev_link" to st.link, "prev_transport" to st.transport, "prev_rtt" to st.rtt),
          ts = ts,
        )
      } else if (!st.reachable && reachable) {
        addIncident(
          net = net,
          kind = "PEER_UP",
          severity = "info",
          peer = n.name,
          summary = "Peer '${n.name}' is reachable (${n.link}, transport=${n.transport.ifEmpty { "meta" }}, via=${n.nexthop.ifEmpty { "direct" }})",
          details = mapOf("link" to n.link, "transport" to n.transport, "via" to n.nexthop, "rtt" to n.rtt, "pmtu" to n.pmtu),
          ts = ts,
        )
      }

      if (reachable) {
        if (st.link == "direct-udp" && (n.link == "direct-tcp" || n.link == "relay")) {
          addIncident(
            net = net,
            kind = "UDP_FALLBACK",
            severity = "warn",
            peer = n.name,
            summary = "Peer '${n.name}' fell back from direct UDP to ${n.link} (via ${n.nexthop.ifEmpty { "TCP" }}, transport=${n.transport.ifEmpty { "meta" }})",
            details = mapOf("prev_link" to st.link, "new_link" to n.link, "via" to n.nexthop, "transport" to n.transport, "status" to "0x${n.statusHex}"),
            ts = ts,
          )
        } else if ((st.link == "direct-tcp" || st.link == "relay") && n.link == "direct-udp") {
          addIncident(
            net = net,
            kind = "UDP_RECOVERED",
            severity = "info",
            peer = n.name,
            summary = "Peer '${n.name}' established direct UDP path (rtt=${n.rtt.toInt()}ms, pmtu=${n.pmtu}, transport=${n.transport.ifEmpty { "udp" }})",
            details = mapOf("prev_link" to st.link, "rtt" to n.rtt, "pmtu" to n.pmtu, "transport" to n.transport),
            ts = ts,
          )
        }

        if (st.transport.isNotEmpty() && n.transport.isNotEmpty() && st.transport != n.transport) {
          addIncident(
            net = net,
            kind = "TRANSPORT_CHANGED",
            severity = "info",
            peer = n.name,
            summary = "Peer '${n.name}' transport switched: ${st.transport} → ${n.transport}",
            details = mapOf("prev_transport" to st.transport, "new_transport" to n.transport, "link" to n.link),
            ts = ts,
          )
        }

        if (st.nexthop.isNotEmpty() && n.nexthop.isNotEmpty() && st.nexthop != n.nexthop) {
          addIncident(
            net = net,
            kind = "ROUTE_VIA_CHANGED",
            severity = "warn",
            peer = n.name,
            summary = "Peer '${n.name}' nexthop changed: ${st.nexthop} → ${n.nexthop} (${n.link})",
            details = mapOf("prev_via" to st.nexthop, "new_via" to n.nexthop, "link" to n.link),
            ts = ts,
          )
        }

        if (st.pmtu > 0 && n.pmtu > 0 && (st.pmtu - n.pmtu >= 100 || (n.pmtu < 1280 && st.pmtu >= 1280))) {
          addIncident(
            net = net,
            kind = "PMTU_DROP",
            severity = "warn",
            peer = n.name,
            summary = "Peer '${n.name}' PMTU dropped from ${st.pmtu} to ${n.pmtu} bytes",
            details = mapOf("prev_pmtu" to st.pmtu, "new_pmtu" to n.pmtu, "link" to n.link, "transport" to n.transport),
            ts = ts,
          )
        }

        if (st.rtt > 0 && n.rtt > 0) {
          if ((n.rtt - st.rtt >= 150.0 && n.rtt >= st.rtt * 2.2) || (n.rtt >= 450.0 && st.rtt < 250.0)) {
            addIncident(
              net = net,
              kind = "RTT_SPIKE",
              severity = "warn",
              peer = n.name,
              summary = "Peer '${n.name}' RTT spiked: ${st.rtt.toInt()} ms → ${n.rtt.toInt()} ms (${n.link})",
              details = mapOf("prev_rtt" to st.rtt, "new_rtt" to n.rtt, "link" to n.link, "transport" to n.transport),
              ts = ts,
            )
          }
        }

        if (!validkey) {
          st.keyWaitStreak += 1
          if (st.keyWaitStreak == 3) {
            addIncident(
              net = net,
              kind = "SPTPS_KEY_WAIT",
              severity = "warn",
              peer = n.name,
              summary = "Peer '${n.name}' is reachable in graph but has no valid SPTPS session key for >7s (status=0x${n.statusHex})",
              details = mapOf("status" to "0x${n.statusHex}", "link" to n.link, "via" to n.nexthop),
              ts = ts,
            )
          }
        } else {
          st.keyWaitStreak = 0
        }

        val rxDelta = n.rxBytes - st.rxBytes
        val txDelta = n.txBytes - st.txBytes
        if (txDelta >= 2048L && rxDelta == 0L) {
          st.txOnlyStreak += 1
          if (st.txOnlyStreak == 4) {
            addIncident(
              net = net,
              kind = "ONE_WAY_BLACKHOLE",
              severity = "warn",
              peer = n.name,
              summary = "Peer '${n.name}' shows one-way TX without RX replies for ~10s (TX +$txDelta B, RX +0 B, link=${n.link})",
              details = mapOf("tx_delta" to txDelta, "link" to n.link, "transport" to n.transport, "status" to "0x${n.statusHex}"),
              ts = ts,
            )
          }
        } else if (rxDelta > 0L) {
          st.txOnlyStreak = 0
        }
      }

      st.link = n.link
      st.transport = n.transport
      st.nexthop = n.nexthop
      st.rtt = n.rtt
      st.pmtu = n.pmtu
      st.rxBytes = n.rxBytes
      st.txBytes = n.txBytes
      st.reachable = reachable
      st.validkey = validkey
      st.udpConfirmed = udpConfirmed
    }

    fun getSeries(net: String, maxPoints: Int = 720): List<Map<String, Any?>> {
      val list = synchronized(lock) { series[net]?.toList() ?: emptyList() }
      return if (list.size > maxPoints) list.takeLast(maxPoints) else list
    }

    fun getIncidents(net: String, limit: Int = 200): List<Map<String, Any?>> {
      val list = synchronized(lock) { incidents[net]?.toList() ?: emptyList() }
      return list.takeLast(limit).asReversed().map { it.toMap() }
    }

    fun getLatestSnapshot(net: String): DiagSnapshot? = synchronized(lock) { latestSnap[net] }

    fun getLatestSnapshotWithAge(net: String, now: Double = System.currentTimeMillis() / 1000.0): Pair<DiagSnapshot?, Double> {
      val (snap, ts) = synchronized(lock) { latestSnap[net] to (latestSnapTs[net] ?: 0.0) }
      if (snap == null) return null to Double.POSITIVE_INFINITY
      return snap to max(0.0, now - ts)
    }
  }

  // ---- Active Diagnostic Prober --------------------------------------------

  private val probeSem = Semaphore(2)

  private fun runDiagPingCli(
    net: String,
    dstIp: String,
    size: Int = 56,
    ttl: Int = 64,
    df: Boolean = false,
    timeoutMs: Int = 2000,
  ): List<String> {
    val waitMs = max(2500L, timeoutMs.toLong() + 1000L)
    val (_, lines) = runTincCli(
      net,
      waitMs,
      "diag-ping",
      dstIp.trim(),
      size.coerceIn(0, 9000).toString(),
      ttl.coerceIn(1, 255).toString(),
      if (df) "1" else "0",
      timeoutMs.coerceIn(100, 15000).toString(),
    )
    return lines
  }

  private fun resolvePeerVpnIp(net: String, target: String): Pair<String, String> {
    val clean = target.trim()
    if (clean.isEmpty()) return "" to ""
    if (clean.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) return clean to clean
    val snap = collector.getLatestSnapshot(net) ?: captureLiveSnapshot(net)
    val node = snap.nodes[clean]
    if (node != null && node.vpnAddress.isNotEmpty()) {
      return node.vpnAddress.substringBefore('/') to clean
    }
    try {
      val yaml = TincYaml(AppPaths.tincYamlFile(net))
      val stanza = yaml.resolveNetwork(net)
      val hostText = yaml.hostText(stanza, clean)
      if (!hostText.isNullOrEmpty()) {
        val ep = parseHostEndpoints(hostText)
        @Suppress("UNCHECKED_CAST")
        val subs = (ep["subnets"] as? List<String>).orEmpty()
        for (s in subs) {
          val ip = s.substringBefore('/').trim()
          if (ip.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$""")) && ip != "0.0.0.0") {
            return ip to clean
          }
        }
      }
    } catch (_: Exception) {
    }
    return clean to clean
  }

  @Suppress("UNCHECKED_CAST")
  private fun resolvePeerOuterHost(net: String, target: String): Pair<String, Map<String, Any?>> {
    val clean = target.trim()
    try {
      val yaml = TincYaml(AppPaths.tincYamlFile(net))
      val stanza = yaml.resolveNetwork(net)
      val hostText = yaml.hostText(stanza, clean)
      if (!hostText.isNullOrEmpty()) {
        val ep = parseHostEndpoints(hostText)
        val addrs = (ep["addresses"] as? List<Pair<String, String>>).orEmpty()
        if (addrs.isNotEmpty()) return addrs[0].first to ep
      }
    } catch (_: Exception) {
    }
    val snap = collector.getLatestSnapshot(net) ?: captureLiveSnapshot(net)
    val n = snap.nodes[clean]
    if (n != null && n.address.isNotEmpty() && n.address !in setOf("local", "unknown", "0.0.0.0", "MYSELF")) {
      val p = n.port.toIntOrNull() ?: 655
      return n.address to mapOf(
        "addresses" to listOf(n.address to n.port),
        "port" to p,
        "https_port" to 443,
        "quic_port" to 443,
        "obfs_port" to 0,
        "subnets" to n.subnets,
      )
    }
    if (clean.contains(':') && !clean.startsWith("[")) {
      val host = clean.substringBeforeLast(':')
      val p = clean.substringAfterLast(':').toIntOrNull() ?: 655
      return host to mapOf("port" to p, "https_port" to p, "quic_port" to p, "obfs_port" to p)
    }
    return clean to mapOf("port" to 655, "https_port" to 443, "quic_port" to 443, "obfs_port" to 0)
  }

  private fun isSafeProbeHost(host: String): Boolean =
    host.isNotEmpty() && !host.startsWith("-") && SAFE_PROBE_HOST_RE.matches(host)

  internal fun isSafeNodeName(node: String): Boolean =
    node.isNotEmpty() &&
      !node.startsWith("-") &&
      !node.startsWith(".") &&
      ".." !in node &&
      SAFE_NODE_NAME_RE.matches(node)

  internal fun isSafeNetSyntax(net: String): Boolean {
    if (net.isEmpty()) return false
    if (net == "." || net == ".." || ".." in net) return false
    return SAFE_NET_NAME_RE.matches(net)
  }

  @Volatile internal var testKnownNetsOverride: Set<String>? = null

  internal fun isKnownValidNet(net: String): Boolean {
    if (!isSafeNetSyntax(net)) return false
    val override = testKnownNetsOverride
    if (override != null) return net in override
    val hasAppCtx = try {
      App.getContext()
      true
    } catch (_: Throwable) {
      false
    }
    if (!hasAppCtx) {
      // Plain JVM unit test without Android Application context: syntax check suffices.
      return true
    }
    return try {
      if (net in Networks.list()) return true
      val confDir = AppPaths.confDir(net)
      File(confDir, TincYaml.FILE_NAME).isFile
    } catch (_: Throwable) {
      false
    }
  }

  fun runProbe(net: String, tool: String, params: Map<String, Any?>): Map<String, Any?> {
    if (net.isNotEmpty() && !isKnownValidNet(net)) {
      val msg = "Invalid or unknown network name"
      return mapOf("ok" to false, "output" to msg, "formatted" to msg)
    }
    if (!probeSem.tryAcquire()) {
      val msg = "Another diagnostic probe is already running — please wait for it to finish."
      return mapOf("ok" to false, "output" to msg, "formatted" to msg)
    }
    try {
      return runProbeImpl(net, tool, params)
    } finally {
      probeSem.release()
    }
  }

  private fun runProbeImpl(net: String, tool: String, params: Map<String, Any?>): Map<String, Any?> {
    val kind = (tool.ifEmpty { (params["kind"] ?: params["tool"] ?: "").toString() }).trim()
    val target = (params["target"] ?: params["dst_ip"] ?: params["host"] ?: params["peer"] ?: "").toString().trim()

    when (kind) {
      "in-ping", "in_tunnel_ping" -> {
        val (ip, label) = resolvePeerVpnIp(net, target)
        if (ip.isEmpty() || !isSafeProbeHost(ip)) {
          val msg = "Specify a valid peer name or VPN IPv4 address."
          return mapOf("ok" to false, "output" to msg, "formatted" to msg)
        }
        val count = ((params["count"] as? Number)?.toInt() ?: params["count"]?.toString()?.toIntOrNull() ?: 4).coerceIn(1, 20)
        val size = ((params["size"] as? Number)?.toInt() ?: params["size"]?.toString()?.toIntOrNull() ?: 56).coerceIn(0, 1472)
        val df = params["df"] == true || params["df"]?.toString() == "true" || params["df"]?.toString() == "1"
        val samples = mutableListOf<Map<String, Any?>>()
        val rtts = mutableListOf<Double>()
        val lines = mutableListOf("=== In-Tunnel ICMP Ping to $label ($ip) — $count probes, $size bytes, DF=${if (df) 1 else 0} ===")
        for (seq in 1..count) {
          val out = runDiagPingCli(net, ip, size = size, ttl = 64, df = df, timeoutMs = 2000)
          val r = parseDiagPingOutput(out) + ("seq" to seq)
          samples.add(r)
          if (r["replied"] == true) {
            val status = r["status"] as? String ?: ""
            val rttMs = (r["rtt_ms"] as? Number)?.toDouble() ?: 0.0
            val fromIp = (r["from_ip"] as? String)?.ifEmpty { ip } ?: ip
            val node = (r["node"] as? String).orEmpty()
            val nodeStr = if (node.isNotEmpty() && node != "-") " [$node]" else ""
            if (r["ok"] == true) rtts.add(rttMs)
            when (status) {
              "echo_reply" -> lines.add("  #$seq: $size bytes from $fromIp$nodeStr: ttl=${r["ttl"]} time=${String.format(Locale.US, "%.2f", rttMs)} ms")
              "frag_needed" -> lines.add("  #$seq: FRAG_NEEDED from $fromIp$nodeStr: next-hop MTU=${r["mtu"]} (${String.format(Locale.US, "%.2f", rttMs)} ms)")
              "time_exceeded" -> lines.add("  #$seq: TTL_EXCEEDED at $fromIp$nodeStr (${String.format(Locale.US, "%.2f", rttMs)} ms)")
              else -> lines.add("  #$seq: $status from $fromIp$nodeStr (${String.format(Locale.US, "%.2f", rttMs)} ms)")
            }
          } else {
            lines.add("  #$seq: timeout / ${r["raw"] ?: "no reply"}")
          }
          if (seq < count) Thread.sleep(100)
        }
        val lossPct = ((count - rtts.size) * 100.0 / count)
        lines.add("")
        lines.add("--- $label ($ip) ping statistics ---")
        lines.add("$count packets transmitted, ${rtts.size} received, ${String.format(Locale.US, "%.1f", lossPct)}% packet loss")
        if (rtts.isNotEmpty()) {
          val minRtt = rtts.minOrNull() ?: 0.0
          val maxRtt = rtts.maxOrNull() ?: 0.0
          val avgRtt = rtts.average()
          val jitter = if (rtts.size > 1) rtts.zipWithNext { a, b -> abs(b - a) }.average() else 0.0
          lines.add(
            String.format(
              Locale.US,
              "rtt min/avg/max/jitter = %.2f/%.2f/%.2f/%.2f ms",
              minRtt,
              avgRtt,
              maxRtt,
              jitter,
            )
          )
        }
        val outStr = lines.joinToString("\n")
        return mapOf("ok" to rtts.isNotEmpty(), "output" to outStr, "formatted" to outStr)
      }

      "in-trace", "in_tunnel_trace" -> {
        val (ip, label) = resolvePeerVpnIp(net, target)
        if (ip.isEmpty() || !isSafeProbeHost(ip)) {
          val msg = "Specify a valid peer name or VPN IPv4 address."
          return mapOf("ok" to false, "output" to msg, "formatted" to msg)
        }
        val maxHops = ((params["max_hops"] as? Number)?.toInt() ?: params["max_hops"]?.toString()?.toIntOrNull() ?: 12).coerceIn(1, 30)
        val lines = mutableListOf("=== In-Tunnel Mesh Traceroute to $label ($ip), $maxHops hops max ===")
        var consecutiveTimeouts = 0
        for (ttl in 1..maxHops) {
          val out = runDiagPingCli(net, ip, size = 56, ttl = ttl, df = false, timeoutMs = 1500)
          val r = parseDiagPingOutput(out)
          val fromIp = (r["from_ip"] as? String).orEmpty()
          if (fromIp.isNotEmpty()) {
            consecutiveTimeouts = 0
            val node = (r["node"] as? String).orEmpty()
            val nodeStr = if (node.isNotEmpty() && node != "-") " ($node)" else ""
            val rttMs = (r["rtt_ms"] as? Number)?.toDouble() ?: 0.0
            lines.add(String.format(Locale.US, " %2d  %s%s  %.2f ms  [%s]", ttl, fromIp, nodeStr, rttMs, r["status"]))
          } else {
            consecutiveTimeouts += 1
            lines.add(String.format(Locale.US, " %2d  * * *  (%s)", ttl, r["status"] ?: "timeout"))
          }
          if (r["ok"] == true || fromIp == ip || consecutiveTimeouts >= 3) break
        }
        val outStr = lines.joinToString("\n")
        return mapOf("ok" to true, "output" to outStr, "formatted" to outStr)
      }

      "in-pmtu", "in_tunnel_pmtu" -> {
        val (ip, label) = resolvePeerVpnIp(net, target)
        if (ip.isEmpty() || !isSafeProbeHost(ip)) {
          val msg = "Specify a valid peer name or VPN IPv4 address."
          return mapOf("ok" to false, "output" to msg, "formatted" to msg)
        }
        val sizes = listOf(500, 1000, 1200, 1280, 1340, 1372, 1400, 1420, 1450, 1472)
        var maxWorkingPayload = 0
        var reportedMtu = 0
        var consecutiveTimeouts = 0
        val stepLines = mutableListOf<String>()
        for (sz in sizes) {
          val out = runDiagPingCli(net, ip, size = sz, ttl = 64, df = true, timeoutMs = 1200)
          val r = parseDiagPingOutput(out)
          val ipMtu = sz + 28
          val mtuVal = (r["mtu"] as? Number)?.toInt() ?: 0
          if (mtuVal > 0) reportedMtu = mtuVal
          if (r["ok"] == true) {
            consecutiveTimeouts = 0
            if (sz > maxWorkingPayload) maxWorkingPayload = sz
            val rttMs = (r["rtt_ms"] as? Number)?.toDouble() ?: 0.0
            stepLines.add(String.format(Locale.US, "  payload=%4d B (IP MTU %4d B) : PASS  (%.2f ms)", sz, ipMtu, rttMs))
          } else {
            if (r["replied"] == true) consecutiveTimeouts = 0 else consecutiveTimeouts += 1
            val extra = if (r["status"] == "frag_needed") " [FRAG_NEEDED mtu=$mtuVal]" else " [${r["status"] ?: "dropped"}]"
            stepLines.add(String.format(Locale.US, "  payload=%4d B (IP MTU %4d B) : FAIL%s", sz, ipMtu, extra))
            if (consecutiveTimeouts >= 2) break
          }
        }
        val effMtu = if (maxWorkingPayload > 0) maxWorkingPayload + 28 else 0
        val header = mutableListOf(
          "=== In-Tunnel PMTU Discovery Sweep (DF=1) to $label ($ip) ===",
          "Max Working IP MTU: $effMtu bytes" + if (reportedMtu > 0) " (Reported Frag MTU: $reportedMtu)" else "",
          "",
          "Probe steps (DF=1):",
        )
        header.addAll(stepLines)
        val outStr = header.joinToString("\n")
        return mapOf("ok" to (effMtu > 0), "output" to outStr, "formatted" to outStr)
      }

      "out-ping", "underlay_ping" -> {
        val (host, _) = resolvePeerOuterHost(net, target)
        if (!isSafeProbeHost(host)) {
          val msg = "Specify a valid peer name, hostname, or outer IP address."
          return mapOf("ok" to false, "output" to msg, "formatted" to msg)
        }
        val count = ((params["count"] as? Number)?.toInt() ?: params["count"]?.toString()?.toIntOrNull() ?: 4).coerceIn(1, 10)
        val cmd = listOf("ping", "-c", count.toString(), "-W", "2", host)
        return runExternalCommand(cmd, timeoutSec = (count * 3 + 4).toLong())
      }

      "out-trace", "underlay_trace" -> {
        val (host, _) = resolvePeerOuterHost(net, target)
        if (!isSafeProbeHost(host)) {
          val msg = "Specify a valid peer name, hostname, or outer IP address."
          return mapOf("ok" to false, "output" to msg, "formatted" to msg)
        }
        val tr = runExternalCommand(listOf("traceroute", "-n", "-m", "15", "-w", "1", host), timeoutSec = 25)
        if (tr["ok"] == true || !(tr["output"]?.toString().orEmpty().contains("Cannot run program"))) {
          return tr
        }
        // Fallback: TTL-stepping with `ping -c 1 -t <ttl> -W 1 <host>` on Android
        val lines = mutableListOf("=== Outer TTL-Step Trace (via ping -t) to $host ===")
        for (ttl in 1..12) {
          val step = runExternalCommand(listOf("ping", "-c", "1", "-t", ttl.toString(), "-W", "1", host), timeoutSec = 3)
          val out = step["output"]?.toString().orEmpty()
          val hopLine = out.lineSequence().firstOrNull {
            it.contains("From ", ignoreCase = true) || it.contains("bytes from", ignoreCase = true)
          }
          if (hopLine != null) {
            lines.add(String.format(Locale.US, " %2d  %s", ttl, hopLine.trim()))
            if (hopLine.contains("bytes from", ignoreCase = true)) break
          } else {
            lines.add(String.format(Locale.US, " %2d  * * *", ttl))
          }
        }
        val outStr = lines.joinToString("\n")
        return mapOf("ok" to true, "output" to outStr, "formatted" to outStr)
      }

      "ports", "port_probe" -> return probeCarrierPorts(net, target)
      "dns", "dns_lookup" -> return probeDnsAndCache(net)
      "routes", "os_net" -> return probeOsRoutes()
      "dump", "tinc_cmd" -> {
        val item = (params["cmd"] ?: params["item"] ?: "nodes").toString().trim()
        val (rc, lines) = when {
          item == "fsck" -> runTincCli(net, 10000L, "fsck")
          item.startsWith("info:") -> {
            val node = item.substringAfter("info:").trim().ifEmpty { target }
            if (!isSafeNodeName(node)) {
              return mapOf("ok" to false, "output" to "Invalid node name", "formatted" to "Invalid node name")
            }
            runTincCli(net, 5000L, "info", node)
          }
          else -> {
            val tokens = item.split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (tokens.isEmpty() || tokens.any { !it.matches(Regex("^[A-Za-z0-9_-]{1,32}$")) || it.startsWith("-") }) {
              return mapOf("ok" to false, "output" to "Invalid dump target", "formatted" to "Invalid dump target")
            }
            val dumpArgs = mutableListOf("dump")
            dumpArgs.addAll(tokens)
            runTincCli(net, 5000L, *dumpArgs.toTypedArray())
          }
        }
        val outStr = lines.joinToString("\n").trim().ifEmpty { if (item == "fsck") "(no issues reported)" else "" }
        return mapOf("ok" to (rc == 0), "output" to outStr, "formatted" to outStr)
      }
    }

    val msg = "Unknown diagnostic tool: $kind"
    return mapOf("ok" to false, "output" to msg, "formatted" to msg)
  }

  private fun runExternalCommand(cmd: List<String>, timeoutSec: Long = 10): Map<String, Any?> {
    return try {
      val (rc, lines) = execProcessWithTimeout(cmd, timeoutSec.coerceAtLeast(1L) * 1000L)
      if (rc == 124 && lines == listOf("TIMEOUT")) {
        val msg = "$ ${cmd.joinToString(" ")}\n\n(Command timed out after ${timeoutSec}s)"
        return mapOf("ok" to false, "output" to msg, "formatted" to msg)
      }
      val text = lines.joinToString("\n").trim()
      val outStr = "$ ${cmd.joinToString(" ")}\n\n$text"
      mapOf("ok" to (rc == 0), "output" to outStr, "formatted" to outStr)
    } catch (e: Exception) {
      val msg = "Command ${cmd.firstOrNull()} failed: ${e.message}"
      mapOf("ok" to false, "output" to msg, "formatted" to msg)
    }
  }

  private fun probeCarrierPorts(net: String, target: String): Map<String, Any?> {
    val (host, ep) = resolvePeerOuterHost(net, target)
    if (!isSafeProbeHost(host)) {
      val msg = "Specify a valid peer name or host[:port]."
      return mapOf("ok" to false, "output" to msg, "formatted" to msg)
    }
    val lines = mutableListOf("=== Carrier & Transport Handshake Prober for '$target' (host=$host) ===")

    val t0 = System.nanoTime()
    val ips = try {
      InetAddress.getAllByName(host).mapNotNull { it.hostAddress }.distinct()
    } catch (e: Exception) {
      lines.add("[DNS] FAILED to resolve $host: ${e.message}")
      val outStr = lines.joinToString("\n")
      return mapOf("ok" to false, "output" to outStr, "formatted" to outStr)
    }
    val dnsMs = (System.nanoTime() - t0) / 1_000_000.0
    lines.add(String.format(Locale.US, "[DNS] %s -> %s (%.1f ms)", host, ips.joinToString(", "), dnsMs))
    val ip = ips.firstOrNull() ?: host

    val port = (ep["port"] as? Number)?.toInt() ?: 655
    val httpsPort = (ep["https_port"] as? Number)?.toInt() ?: 0
    val quicPort = (ep["quic_port"] as? Number)?.toInt() ?: 0
    val obfsPort = (ep["obfs_port"] as? Number)?.toInt() ?: 0

    // 1. Plain TCP / Metaconnection Port
    if (port > 0) {
      val tc0 = System.nanoTime()
      try {
        Socket().use { s ->
          s.connect(InetSocketAddress(ip, port), 3000)
          val tcpMs = (System.nanoTime() - tc0) / 1_000_000.0
          s.soTimeout = 1200
          val banner = try {
            val buf = ByteArray(128)
            val n = s.getInputStream().read(buf)
            if (n > 0) String(buf, 0, n, StandardCharsets.UTF_8).trim() else ""
          } catch (_: Exception) {
            ""
          }
          lines.add(
            String.format(
              Locale.US,
              "[TCP Port %d (plain/meta)] OPEN — connect=%.1f ms%s",
              port,
              tcpMs,
              if (banner.isNotEmpty()) " | banner: '$banner'" else " | (no immediate banner — may share front port)",
            )
          )
        }
      } catch (e: Exception) {
        lines.add("[TCP Port $port (plain/meta)] FAILED — ${e.message}")
      }
    }

    // 2. HTTPS / TLS Front Port
    val tlsPorts = if (httpsPort > 0) listOf(httpsPort) else listOf(443)
    for (hp in tlsPorts) {
      if (hp <= 0) continue
      val tl0 = System.nanoTime()
      try {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
          override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
          override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
          override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, trustAll, SecureRandom())
        Socket().use { raw ->
          raw.connect(InetSocketAddress(ip, hp), 3000)
          val tcpMs = (System.nanoTime() - tl0) / 1_000_000.0
          val hs0 = System.nanoTime()
          (ctx.socketFactory.createSocket(raw, host, hp, true) as SSLSocket).use { ssock ->
            ssock.soTimeout = 3000
            ssock.startHandshake()
            val tlsMs = (System.nanoTime() - hs0) / 1_000_000.0
            val sess = ssock.session
            lines.add(
              String.format(
                Locale.US,
                "[HTTPS/TLS Port %d] PASS — TCP=%.1f ms, TLS=%.1f ms | protocol=%s, cipher=%s",
                hp,
                tcpMs,
                tlsMs,
                sess.protocol,
                sess.cipherSuite,
              )
            )
          }
        }
      } catch (e: Exception) {
        lines.add("[HTTPS/TLS Port $hp] FAILED — ${e.message}")
      }
    }

    // 3. QUIC / Obfs / Base UDP socket probe
    val udpPorts = mutableListOf<Pair<String, Int>>()
    if (quicPort > 0) udpPorts.add("QUIC UDP" to quicPort)
    if (obfsPort > 0) udpPorts.add("Obfs UDP" to obfsPort)
    if (port > 0 && udpPorts.none { it.second == port }) udpPorts.add("Base UDP" to port)
    for ((label, up) in udpPorts) {
      try {
        DatagramSocket().use { ds ->
          ds.soTimeout = 1000
          val addr = InetAddress.getByName(ip)
          ds.connect(addr, up)
          val pkt = DatagramPacket( byteArrayOf(0), 1, addr, up)
          ds.send(pkt)
          val recvBuf = ByteArray(64)
          val recvPkt = DatagramPacket(recvBuf, recvBuf.size)
          try {
            ds.receive(recvPkt)
            lines.add("[$label Port $up] UDP socket sent & received reply from $ip:$up")
          } catch (_: Exception) {
            lines.add("[$label Port $up] UDP datagram transmitted to $ip:$up (no immediate ICMP port-unreachable)")
          }
        }
      } catch (e: Exception) {
        lines.add("[$label Port $up] UDP error to $ip:$up — ${e.message}")
      }
    }

    val outStr = lines.joinToString("\n")
    return mapOf("ok" to true, "output" to outStr, "formatted" to outStr)
  }

  @Suppress("UNCHECKED_CAST")
  private fun probeDnsAndCache(net: String): Map<String, Any?> {
    val lines = mutableListOf("=== DNS Resolution & Address Cache Inspector for '$net' ===")
    try {
      val yaml = TincYaml(AppPaths.tincYamlFile(net))
      val stanza = yaml.resolveNetwork(net)
      val hostsMap = (yaml.networkMapPublic(stanza)["hosts"] as? Map<*, *>)?.entries
        ?.associate { it.key.toString() to it.value?.toString().orEmpty() }
        .orEmpty()
      for ((hname, hbody) in hostsMap.toSortedMap()) {
        val ep = parseHostEndpoints(hbody)
        val addrs = (ep["addresses"] as? List<Pair<String, String>>).orEmpty()
        for ((addr, p) in addrs) {
          val t0 = System.nanoTime()
          try {
            val ips = InetAddress.getAllByName(addr).mapNotNull { it.hostAddress }.distinct().sorted()
            val ms = (System.nanoTime() - t0) / 1_000_000.0
            lines.add(String.format(Locale.US, "  Host %-15s : %s:%s -> %s (%.1f ms)", hname, addr, p.ifEmpty { ep["port"].toString() }, ips.joinToString(", "), ms))
          } catch (e: Exception) {
            lines.add(String.format(Locale.US, "  Host %-15s : %s:%s -> ERROR: %s", hname, addr, p.ifEmpty { ep["port"].toString() }, e.message))
          }
        }
      }

      val candidateDirs = listOf(AppPaths.daemonSideDir(net, stanza), AppPaths.confDir(net))
      val dnsStateFile = candidateDirs.map { File(it, "dnsrefresh.state") }.firstOrNull { it.isFile }
      lines.add("")
      lines.add("--- dnsrefresh.state ---")
      lines.add(dnsStateFile?.readText()?.trim()?.ifEmpty { "(empty)" } ?: "(not present)")

      val cacheDir = candidateDirs.flatMap { listOf(File(it, "address_cache"), File(it, "cache")) }.firstOrNull { it.isDirectory }
      lines.add("")
      lines.add("--- address_cache / cache ---")
      if (cacheDir != null) {
        val files = cacheDir.listFiles()?.sortedBy { it.name }.orEmpty()
        if (files.isEmpty()) {
          lines.add("(empty directory)")
        } else {
          for (f in files) {
            if (f.isFile) {
              val body = f.readText().trim().replace("\n", " | ")
              lines.add("  ${f.name}: $body")
            }
          }
        }
      } else {
        lines.add("(not present)")
      }
    } catch (e: Exception) {
      lines.add("Error inspecting DNS/cache: ${e.message}")
    }
    val outStr = lines.joinToString("\n")
    return mapOf("ok" to true, "output" to outStr, "formatted" to outStr)
  }

  private fun probeOsRoutes(): Map<String, Any?> {
    val lines = mutableListOf("=== Android OS Interfaces, VPN Session & Power State Inspector ===")
    try {
      val ctx = App.getContext()
      val pm = ctx.getSystemService(Context.POWER_SERVICE) as? PowerManager
      if (pm != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        lines.add("Battery Optimization Ignored : ${pm.isIgnoringBatteryOptimizations(BuildConfig.APPLICATION_ID)}")
        lines.add("Device Idle (Doze) Mode      : ${pm.isDeviceIdleMode}")
        lines.add("Power Save Mode              : ${pm.isPowerSaveMode}")
      }
    } catch (_: Exception) {
    }

    val cfg = TincVpnService.getCurrentInterfaceCfg()
    if (cfg != null) {
      lines.add("Active VpnService Addresses  : ${cfg.addresses.joinToString(", ")}")
      lines.add("Active VpnService Routes     : ${cfg.routes.joinToString(", ")}")
      lines.add("Active VpnService DNS        : ${cfg.dnsServers.joinToString(", ")}")
    }

    lines.add("\n--- Java NetworkInterfaces ---")
    try {
      val ifaces = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
      for (nif in ifaces) {
        if (!nif.isUp) continue
        val addrs = nif.interfaceAddresses.map { "${it.address.hostAddress}/${it.networkPrefixLength}" }
        lines.add("  ${nif.name} (mtu=${nif.mtu}): ${addrs.joinToString(", ")}")
      }
    } catch (e: Exception) {
      lines.add("  (error: ${e.message})")
    }

    for ((title, cmd) in listOf(
      "ip addr" to listOf("ip", "-br", "addr"),
      "ip route" to listOf("ip", "route", "show"),
      "ip rule" to listOf("ip", "rule", "show"),
    )) {
      lines.add("\n--- $title ---")
      val res = runExternalCommand(cmd, timeoutSec = 4)
      lines.add(res["output"]?.toString().orEmpty())
    }

    val outStr = lines.joinToString("\n")
    return mapOf("ok" to true, "output" to outStr, "formatted" to outStr)
  }

  // ---- Embedded Multi-Threaded HTTP Server ---------------------------------

  val collector: TelemetryCollector by lazy {
    val dir = try {
      AppPaths.logsDir()
    } catch (_: Exception) {
      File(System.getProperty("java.io.tmpdir", "/tmp"), "tincstack-diag")
    }
    TelemetryCollector(dir)
  }

  private val serverLock = Any()
  @Volatile private var serverSocket: ServerSocket? = null
  @Volatile private var serverEnabled: Boolean = false
  @Volatile private var serverPort: Int = DEFAULT_DIAG_PORT
  @Volatile private var serverPassword: String = ""
  private val secureRandom = SecureRandom()
  private val sessionLock = Any()
  private val sessions = LinkedHashMap<String, Long>()
  private val httpPool = Executors.newCachedThreadPool { r -> Thread(r, "tinc-diag-http").apply { isDaemon = true } }
  private val samplerExec = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "tinc-diag-sampler").apply { isDaemon = true } }
  private val samplerBusy = AtomicBoolean(false)
  @Volatile private var samplerTask: ScheduledFuture<*>? = null

  private enum class AuthKind { NONE, COOKIE, HEADER }

  private fun generateRandomPassword(): String {
    val sb = StringBuilder(PASSWORD_LEN)
    for (i in 0 until PASSWORD_LEN) {
      sb.append(PASSWORD_ALPHABET[secureRandom.nextInt(PASSWORD_ALPHABET.length)])
    }
    return sb.toString()
  }

  /**
   * Ensures a persistent random 16-character Diagnostic WebUI password exists in
   * `SharedPreferences` (generated once on first launch and reused across all restarts).
   * Falls back to an in-memory random password in plain JVM unit tests where Android
   * `Context` is unavailable.
   */
  fun ensurePassword(context: Context? = null): String {
    val ctx = context ?: try { App.getContext() } catch (_: Throwable) { null }
    synchronized(serverLock) {
      if (ctx != null) {
        try {
          val prefs = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
          if (prefs != null) {
            val saved = prefs.getString(PREF_PASSWORD, null)?.trim()
            if (!saved.isNullOrEmpty()) {
              serverPassword = saved
              return saved
            }
            val editor = prefs.edit()
            if (editor != null) {
              val generated = generateRandomPassword()
              val putEd = editor.putString(PREF_PASSWORD, generated) ?: editor
              if (!putEd.commit()) putEd.apply()
              serverPassword = generated
              return generated
            }
          }
        } catch (_: Throwable) {
        }
      }
      if (serverPassword.isBlank()) {
        serverPassword = generateRandomPassword()
      }
      return serverPassword
    }
  }

  fun getPassword(context: Context? = null): String = ensurePassword(context)

  internal fun resetAuthForTests() {
    synchronized(serverLock) { serverPassword = "" }
    synchronized(sessionLock) { sessions.clear() }
  }

  internal fun constantTimeEquals(a: String, b: String): Boolean {
    val ba = a.toByteArray(StandardCharsets.UTF_8)
    val bb = b.toByteArray(StandardCharsets.UTF_8)
    return MessageDigest.isEqual(ba, bb)
  }

  /** Pure-Kotlin Base64 decoder compatible with Android API 21+ and plain JVM unit tests. */
  internal fun decodeBase64Utf8(input: String): String? {
    val clean = input.trim()
    if (clean.isEmpty()) return ""
    val out = ArrayList<Byte>((clean.length * 3) / 4 + 4)
    var buf = 0
    var bits = 0
    var padSeen = false
    for (ch in clean) {
      if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') continue
      if (ch == '=') {
        padSeen = true
        continue
      }
      if (padSeen) return null
      val v = when (ch) {
        in 'A'..'Z' -> ch.code - 'A'.code
        in 'a'..'z' -> ch.code - 'a'.code + 26
        in '0'..'9' -> ch.code - '0'.code + 52
        '+', '-' -> 62
        '/', '_' -> 63
        else -> return null
      }
      buf = (buf shl 6) or v
      bits += 6
      if (bits >= 8) {
        bits -= 8
        out.add(((buf shr bits) and 0xFF).toByte())
      }
    }
    val bytes = ByteArray(out.size)
    for (i in out.indices) bytes[i] = out[i]
    return String(bytes, StandardCharsets.UTF_8)
  }

  private fun issueSession(nowMs: Long = System.currentTimeMillis()): String {
    val raw = ByteArray(32)
    secureRandom.nextBytes(raw)
    val sb = StringBuilder(64)
    for (b in raw) sb.append(String.format(Locale.US, "%02x", b.toInt() and 0xFF))
    val sid = sb.toString()
    synchronized(sessionLock) {
      val iter = sessions.entries.iterator()
      while (iter.hasNext()) {
        val e = iter.next()
        if (nowMs - e.value > SESSION_TTL_MS) iter.remove()
      }
      while (sessions.size >= MAX_SESSIONS) {
        val oldest = sessions.keys.firstOrNull() ?: break
        sessions.remove(oldest)
      }
      sessions[sid] = nowMs
    }
    return sid
  }

  private fun validateSession(sid: String, nowMs: Long = System.currentTimeMillis()): Boolean {
    if (sid.length != 64 || !sid.all { it in '0'..'9' || it in 'a'..'f' }) return false
    synchronized(sessionLock) {
      var matchedKey: String? = null
      val iter = sessions.entries.iterator()
      while (iter.hasNext()) {
        val e = iter.next()
        if (nowMs - e.value > SESSION_TTL_MS) {
          iter.remove()
          continue
        }
        if (constantTimeEquals(sid, e.key)) {
          matchedKey = e.key
        }
      }
      if (matchedKey != null) {
        sessions[matchedKey] = nowMs
        return true
      }
      return false
    }
  }

  private fun revokeSession(sid: String) {
    if (sid.isEmpty()) return
    synchronized(sessionLock) {
      sessions.remove(sid)
    }
  }

  private fun parseCookieValue(cookieHeader: String, name: String): String {
    if (cookieHeader.isEmpty()) return ""
    for (part in cookieHeader.split(';')) {
      val trimmed = part.trim()
      val eq = trimmed.indexOf('=')
      if (eq > 0 && trimmed.substring(0, eq).trim() == name) {
        return trimmed.substring(eq + 1).trim().removeSurrounding("\"")
      }
    }
    return ""
  }

  private fun authenticateRequest(
    authHeader: String,
    diagPwdHeader: String,
    cookieHeader: String,
  ): Pair<AuthKind, String> {
    val expected = ensurePassword()
    if (diagPwdHeader.isNotEmpty() && constantTimeEquals(diagPwdHeader, expected)) {
      return AuthKind.HEADER to ""
    }
    if (authHeader.isNotEmpty()) {
      when {
        authHeader.startsWith("Bearer ", ignoreCase = true) -> {
          val tok = authHeader.substring(7).trim()
          if (tok.isNotEmpty() && constantTimeEquals(tok, expected)) return AuthKind.HEADER to ""
        }
        authHeader.startsWith("Basic ", ignoreCase = true) -> {
          val decoded = decodeBase64Utf8(authHeader.substring(6).trim())
          if (decoded != null) {
            val pwd = if (':' in decoded) decoded.substringAfter(':') else decoded
            if (pwd.isNotEmpty() && constantTimeEquals(pwd, expected)) return AuthKind.HEADER to ""
          }
        }
      }
    }
    val sid = parseCookieValue(cookieHeader, SESSION_COOKIE_NAME)
    if (sid.isNotEmpty() && validateSession(sid)) {
      return AuthKind.COOKIE to sid
    }
    return AuthKind.NONE to sid
  }

  internal fun parseHostFromHostHeader(hostHeader: String): String? {
    val trimmed = hostHeader.trim()
    if (trimmed.isEmpty()) return null
    if (trimmed.startsWith("[")) {
      val closeIdx = trimmed.indexOf(']')
      if (closeIdx <= 1) return null
      val ipv6 = trimmed.substring(1, closeIdx)
      if (!ipv6.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) return null
      val rem = trimmed.substring(closeIdx + 1)
      if (rem.isNotEmpty()) {
        if (!rem.startsWith(":")) return null
        val p = rem.substring(1).toIntOrNull() ?: return null
        if (p !in 1..65535) return null
      }
      return ipv6.lowercase(Locale.ROOT)
    }
    val colonCount = trimmed.count { it == ':' }
    if (colonCount == 0) {
      if (!trimmed.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '.' || it == '-' }) return null
      return trimmed.lowercase(Locale.ROOT)
    }
    if (colonCount == 1) {
      val host = trimmed.substringBefore(':')
      val portStr = trimmed.substringAfter(':')
      val p = portStr.toIntOrNull() ?: return null
      if (p !in 1..65535 || host.isEmpty()) return null
      if (!host.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '.' || it == '-' }) return null
      return host.lowercase(Locale.ROOT)
    }
    // Bare IPv6 literal without brackets/port (e.g. ::1)
    if (!trimmed.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) return null
    return trimmed.lowercase(Locale.ROOT)
  }

  private fun collectOwnVpnIps(): Set<String> {
    val ips = HashSet<String>()
    try {
      TincVpnService.getCurrentInterfaceCfg()?.addresses?.forEach { cidr ->
        val ip = cidr.address.trim().removeSurrounding("[", "]").lowercase(Locale.ROOT)
        if (ip.isNotEmpty() && ip != "0.0.0.0" && ip != "::") ips.add(ip)
      }
    } catch (_: Throwable) {
    }
    try {
      val nets = Networks.list()
      for (n in nets) {
        collector.getLatestSnapshot(n)?.nodes?.values?.forEach { node ->
          if (node.isSelf) {
            if (node.vpnAddress.isNotEmpty()) ips.add(node.vpnAddress.lowercase(Locale.ROOT))
            node.subnets.forEach { sub ->
              val ip = sub.substringBefore('#').substringBefore('/').trim().lowercase(Locale.ROOT)
              if (ip.isNotEmpty() && ip != "0.0.0.0" && ip != "::") ips.add(ip)
            }
          }
        }
        try {
          val addr = Networks.summary(n).address?.substringBefore('/')?.trim()?.lowercase(Locale.ROOT)
          if (!addr.isNullOrEmpty() && addr != "0.0.0.0" && addr != "::") ips.add(addr)
        } catch (_: Throwable) {
        }
        try {
          val yaml = TincYaml(AppPaths.tincYamlFile(n))
          val stanza = yaml.resolveNetwork(n)
          VpnInterfaceConfiguration.fromTincYaml(yaml, stanza).addresses.forEach { cidr ->
            val ip = cidr.address.trim().removeSurrounding("[", "]").lowercase(Locale.ROOT)
            if (ip.isNotEmpty() && ip != "0.0.0.0" && ip != "::") ips.add(ip)
          }
        } catch (_: Throwable) {
        }
      }
    } catch (_: Throwable) {
    }
    return ips
  }

  internal fun isAllowedHost(hostHeader: String, extraAllowedIps: Set<String> = collectOwnVpnIps()): Boolean {
    val host = parseHostFromHostHeader(hostHeader) ?: return false
    if (host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "0:0:0:0:0:0:0:1") {
      return true
    }
    return extraAllowedIps.any { it.equals(host, ignoreCase = true) }
  }

  internal fun isAllowedOrigin(
    originHeader: String,
    hostHeader: String,
    allowMissingOrigin: Boolean,
    extraAllowedIps: Set<String> = collectOwnVpnIps(),
  ): Boolean {
    val reqHost = parseHostFromHostHeader(hostHeader) ?: return false
    if (!isAllowedHost(hostHeader, extraAllowedIps)) return false
    val cleanOrigin = originHeader.trim()
    if (cleanOrigin.isEmpty()) return allowMissingOrigin
    if (cleanOrigin.equals("null", ignoreCase = true)) return false
    val hostPort = when {
      cleanOrigin.startsWith("http://", ignoreCase = true) -> cleanOrigin.substring(7)
      cleanOrigin.startsWith("https://", ignoreCase = true) -> cleanOrigin.substring(8)
      else -> return false
    }
    if ('/' in hostPort || '?' in hostPort || '#' in hostPort || '@' in hostPort) return false
    val originHost = parseHostFromHostHeader(hostPort) ?: return false
    if (!isAllowedHost(hostPort, extraAllowedIps)) return false
    return originHost.equals(reqHost, ignoreCase = true)
  }

  private data class YamlKeyLine(
    val indent: Int,
    val rawKeyToken: String,
    val key: String,
    val rest: String,
  )

  private fun parseYamlKeyLine(line: String): YamlKeyLine? {
    val trimmedStart = line.trimStart(' ')
    if (trimmedStart.isEmpty() || trimmedStart.startsWith("#")) return null
    if (trimmedStart.startsWith("- ") || trimmedStart == "-") return null
    val indent = line.length - trimmedStart.length
    if (trimmedStart.startsWith("\"")) {
      var idx = 1
      val sb = StringBuilder()
      var closed = false
      while (idx < trimmedStart.length) {
        val c = trimmedStart[idx++]
        if (c == '"') {
          closed = true
          break
        }
        if (c == '\\' && idx < trimmedStart.length) {
          when (val esc = trimmedStart[idx++]) {
            'n' -> sb.append('\n')
            'r' -> sb.append('\r')
            't' -> sb.append('\t')
            '"', '\\', '/' -> sb.append(esc)
            else -> sb.append(esc)
          }
        } else {
          sb.append(c)
        }
      }
      if (!closed || idx >= trimmedStart.length || trimmedStart[idx] != ':') return null
      val afterColon = trimmedStart.substring(idx + 1)
      if (afterColon.isNotEmpty() && afterColon[0] != ' ' && afterColon[0] != '\t') return null
      return YamlKeyLine(indent, trimmedStart.substring(0, idx), sb.toString(), afterColon.trim())
    }
    if (trimmedStart.startsWith("'")) {
      var idx = 1
      val sb = StringBuilder()
      var closed = false
      while (idx < trimmedStart.length) {
        val c = trimmedStart[idx++]
        if (c == '\'') {
          if (idx < trimmedStart.length && trimmedStart[idx] == '\'') {
            sb.append('\'')
            idx++
          } else {
            closed = true
            break
          }
        } else {
          sb.append(c)
        }
      }
      if (!closed || idx >= trimmedStart.length || trimmedStart[idx] != ':') return null
      val afterColon = trimmedStart.substring(idx + 1)
      if (afterColon.isNotEmpty() && afterColon[0] != ' ' && afterColon[0] != '\t') return null
      return YamlKeyLine(indent, trimmedStart.substring(0, idx), sb.toString(), afterColon.trim())
    }
    var colonIdx = -1
    for (k in trimmedStart.indices) {
      if (trimmedStart[k] == ':' && (k + 1 == trimmedStart.length || trimmedStart[k + 1] == ' ' || trimmedStart[k + 1] == '\t')) {
        colonIdx = k
        break
      }
    }
    if (colonIdx <= 0) return null
    val rawKey = trimmedStart.substring(0, colonIdx).trim()
    if (rawKey.isEmpty() || '=' in rawKey) return null
    return YamlKeyLine(indent, rawKey, rawKey, trimmedStart.substring(colonIdx + 1).trim())
  }

  private fun isBlockScalarRest(rest: String): Boolean {
    val clean = if (" #" in rest) rest.substringBefore(" #").trim() else rest
    return clean.startsWith("|") || clean.startsWith(">")
  }

  private fun findYamlEntryEndLine(lines: List<String>, startIdx: Int, keyIndent: Int): Int {
    var endIdx = startIdx
    var j = startIdx + 1
    while (j < lines.size) {
      val l = lines[j]
      val trimmed = l.trimStart(' ')
      if (trimmed.isEmpty()) {
        j++
        continue
      }
      val ind = l.length - trimmed.length
      val isSameIndentSeq = ind == keyIndent && (trimmed.startsWith("- ") || trimmed == "-")
      if (ind > keyIndent || isSameIndentSeq) {
        endIdx = j
        j++
      } else {
        break
      }
    }
    return endIdx
  }

  /**
   * Redacts ALL private keys under `keys:` (`ed25519_priv`, `rsa_priv`, `tls_key`,
   * `acme_account`, etc. — everything except public `tls_cert`) and secret options
   * (`Ed25519PrivateKey`, `PrivateKey`, `CloudflareToken`, `AcmeAccountKey`, `ObfsPassword`),
   * handling block scalars (`|`, `|-`, `>`), multi-line values, sequences, and flow maps.
   */
  @Suppress("UNCHECKED_CAST")
  internal fun redactYamlSecrets(rawYaml: String): String {
    if (rawYaml.isBlank()) return rawYaml
    val hasTrailingNewline = rawYaml.endsWith("\n")
    val srcLines = rawYaml.replace("\r\n", "\n").let {
      if (it.endsWith("\n")) it.dropLast(1).split('\n') else it.split('\n')
    }
    val outLines = ArrayList<String>(srcLines.size)

    var networksIndent = -1
    var netIndent = -1
    var sectionIndent = -1
    var currentSection = ""

    var i = 0
    while (i < srcLines.size) {
      val line = srcLines[i]
      val kl = parseYamlKeyLine(line)
      if (kl == null) {
        // Also redact legacy `PrivateKey = ...` lines if any exist outside YAML mappings
        outLines.add(
          line.replace(
            Regex("""(?i)^(\s*(?:Ed25519PrivateKey|PrivateKey|CloudflareToken|AcmeAccountKey|ObfsPassword)\s*=\s*).*$"""),
            "$1$REDACTED_MARKER",
          )
        )
        i++
        continue
      }

      if (sectionIndent >= 0 && kl.indent <= sectionIndent) {
        sectionIndent = -1
        currentSection = ""
      }
      if (netIndent >= 0 && kl.indent <= netIndent) {
        netIndent = -1
        sectionIndent = -1
        currentSection = ""
      }
      if (networksIndent >= 0 && kl.indent <= networksIndent && !kl.key.equals("networks", ignoreCase = true)) {
        networksIndent = -1
        netIndent = -1
        sectionIndent = -1
        currentSection = ""
      }

      if (networksIndent < 0 && kl.key == "networks") {
        networksIndent = kl.indent
        outLines.add(line)
        i++
        continue
      }
      if (networksIndent >= 0 && netIndent < 0 && kl.indent > networksIndent) {
        netIndent = kl.indent
        outLines.add(line)
        i++
        continue
      }
      if (netIndent >= 0 && sectionIndent < 0 && kl.indent > netIndent) {
        sectionIndent = kl.indent
        currentSection = kl.key.lowercase(Locale.ROOT)
        // Guard against flow-style `keys: { ed25519_priv: ... }` on the section line itself
        if (currentSection == "keys" && kl.rest.startsWith("{")) {
          val endIdx = findYamlEntryEndLine(srcLines, i, kl.indent)
          outLines.add("${" ".repeat(kl.indent)}${kl.rawKeyToken}:")
          try {
            val parsedRoot = TincYaml.newYaml().load<Any?>(rawYaml) as? Map<*, *>
            val nets = parsedRoot?.get("networks") as? Map<*, *>
            nets?.values?.firstOrNull()?.let { nObj ->
              val kMap = (nObj as? Map<*, *>)?.get("keys") as? Map<*, *>
              kMap?.forEach { (kName, kVal) ->
                val ks = kName?.toString() ?: return@forEach
                if (ks.equals("tls_cert", ignoreCase = true)) {
                  val vs = kVal?.toString().orEmpty()
                  emitRestoredScalarLines(outLines, kl.indent + 2, TincYaml.formatYamlKey(ks), vs)
                } else {
                  outLines.add("${" ".repeat(kl.indent + 2)}${TincYaml.formatYamlKey(ks)}: \"$REDACTED_MARKER\"")
                }
              }
            }
          } catch (_: Exception) {
          }
          i = endIdx + 1
          continue
        }
        outLines.add(line)
        i++
        continue
      }

      if (sectionIndent >= 0 && kl.indent > sectionIndent) {
        if (currentSection == "keys") {
          val endIdx = findYamlEntryEndLine(srcLines, i, kl.indent)
          if (kl.key.equals("tls_cert", ignoreCase = true)) {
            for (k in i..endIdx) outLines.add(srcLines[k])
          } else {
            outLines.add("${" ".repeat(kl.indent)}${kl.rawKeyToken}: \"$REDACTED_MARKER\"")
          }
          i = endIdx + 1
          continue
        }
        if (currentSection == "options" && kl.key.lowercase(Locale.ROOT) in SECRET_OPTION_KEYS) {
          val endIdx = findYamlEntryEndLine(srcLines, i, kl.indent)
          outLines.add("${" ".repeat(kl.indent)}${kl.rawKeyToken}: \"$REDACTED_MARKER\"")
          i = endIdx + 1
          continue
        }
        if (isBlockScalarRest(kl.rest)) {
          val endIdx = findYamlEntryEndLine(srcLines, i, kl.indent)
          for (k in i..endIdx) outLines.add(srcLines[k])
          i = endIdx + 1
          continue
        }
      } else if (kl.key.lowercase(Locale.ROOT) in SECRET_OPTION_KEYS) {
        val endIdx = findYamlEntryEndLine(srcLines, i, kl.indent)
        outLines.add("${" ".repeat(kl.indent)}${kl.rawKeyToken}: \"$REDACTED_MARKER\"")
        i = endIdx + 1
        continue
      }

      outLines.add(line)
      i++
    }

    val joined = outLines.joinToString("\n") + if (hasTrailingNewline) "\n" else ""
    // Defense-in-depth verification: ensure parsed YAML contains no unredacted secret keys.
    try {
      val root = TincYaml.newYaml().load<Any?>(joined) as? Map<*, *>
      val nets = root?.get("networks") as? Map<*, *>
      if (nets != null) {
        for ((_, netVal) in nets) {
          val nMap = netVal as? Map<*, *> ?: continue
          val kMap = nMap["keys"] as? Map<*, *>
          if (kMap != null) {
            for ((k, v) in kMap) {
              val ks = k?.toString() ?: continue
              if (!ks.equals("tls_cert", ignoreCase = true) && v?.toString() != REDACTED_MARKER) {
                return "# YAML contains unsupported flow/anchor secrets; raw view suppressed\n"
              }
            }
          }
          val oMap = nMap["options"] as? Map<*, *>
          if (oMap != null) {
            for ((k, v) in oMap) {
              val ks = k?.toString() ?: continue
              if (ks.lowercase(Locale.ROOT) in SECRET_OPTION_KEYS) {
                val vals = TincYaml.valuesOf(v)
                if (vals.any { it != REDACTED_MARKER }) {
                  return "# YAML contains unsupported flow/anchor secrets; raw view suppressed\n"
                }
              }
            }
          }
        }
      }
    } catch (_: Exception) {
    }
    return joined
  }

  private fun emitRestoredScalarLines(outLines: MutableList<String>, indent: Int, rawKeyToken: String, value: String) {
    val pad = " ".repeat(indent)
    if (value.contains('\n')) {
      val hasTrailingNl = value.endsWith('\n')
      val indicator = if (hasTrailingNl) "|" else "|-"
      outLines.add("$pad$rawKeyToken: $indicator")
      val body = if (hasTrailingNl) value.dropLast(1) else value
      val bodyPad = " ".repeat(indent + 2)
      for (bl in body.split('\n')) {
        outLines.add(if (bl.isEmpty()) "" else "$bodyPad$bl")
      }
    } else {
      outLines.add("$pad$rawKeyToken: ${TincYaml.formatYamlScalar(value)}")
    }
  }

  private fun isRedactedValueToken(rest: String): Boolean {
    val clean = rest.trim().removeSurrounding("\"").removeSurrounding("'").trim()
    return clean == REDACTED_MARKER
  }

  private fun normalizeScriptsSection(scriptsObj: Any?): Map<String, String> {
    if (scriptsObj == null) return emptyMap()
    if (scriptsObj !is Map<*, *>) throw IllegalArgumentException("Invalid 'scripts' section in tinc.yaml")
    val out = LinkedHashMap<String, String>()
    for ((k, v) in scriptsObj) {
      val ks = k?.toString()?.trim().orEmpty()
      if (ks.isNotEmpty()) out[ks] = v?.toString().orEmpty()
    }
    return out
  }

  /**
   * Restores `***REDACTED***` entries under `keys:` and `options:` from [diskYaml]
   * without clobbering, and forbids injecting or modifying `scripts:` via the Diagnostic WebUI.
   */
  @Suppress("UNCHECKED_CAST")
  internal fun restoreYamlSecretsAndValidate(submittedYaml: String, diskYaml: String): String {
    val subRootObj = try {
      TincYaml.newYaml().load<Any?>(submittedYaml)
    } catch (e: Exception) {
      throw IllegalArgumentException("Invalid YAML: ${e.message}")
    }
    if (subRootObj !is Map<*, *>) throw IllegalArgumentException("Top level of tinc.yaml must be a mapping")
    if (subRootObj.keys.any { it?.toString()?.equals("scripts", ignoreCase = true) == true }) {
      throw IllegalArgumentException("Modifying 'scripts' via Diagnostic WebUI is forbidden")
    }
    val subNetsObj = subRootObj["networks"]
      ?: throw IllegalArgumentException("Missing 'networks' mapping in tinc.yaml")
    if (subNetsObj !is Map<*, *>) throw IllegalArgumentException("'networks' must be a mapping")

    val diskNets: Map<String, Map<String, Any?>> = if (diskYaml.isNotBlank()) {
      try {
        val dRoot = TincYaml.newYaml().load<Any?>(diskYaml) as? Map<*, *>
        val dNets = dRoot?.get("networks") as? Map<*, *>
        dNets?.entries?.mapNotNull { (k, v) ->
          val m = v as? Map<*, *> ?: return@mapNotNull null
          k.toString() to m.entries.associate { it.key.toString() to it.value }
        }?.toMap().orEmpty()
      } catch (_: Exception) {
        emptyMap()
      }
    } else {
      emptyMap()
    }

    for ((nKey, nVal) in subNetsObj) {
      val netName = nKey?.toString() ?: continue
      val nMap = nVal as? Map<*, *>
        ?: throw IllegalArgumentException("Network '$netName' must be a mapping")
      val subScriptsEntry = nMap.entries.firstOrNull { it.key?.toString()?.equals("scripts", ignoreCase = true) == true }
      val diskMap = diskNets[netName]
      val diskScriptsEntry = diskMap?.entries?.firstOrNull { it.key.equals("scripts", ignoreCase = true) }
      val subScripts = normalizeScriptsSection(subScriptsEntry?.value)
      val diskScripts = normalizeScriptsSection(diskScriptsEntry?.value)
      if (subScripts != diskScripts) {
        throw IllegalArgumentException("Modifying 'scripts' via Diagnostic WebUI is forbidden")
      }
    }

    if (!submittedYaml.contains(REDACTED_MARKER) || diskNets.isEmpty()) {
      return submittedYaml
    }

    val hasTrailingNewline = submittedYaml.endsWith("\n")
    val srcLines = submittedYaml.replace("\r\n", "\n").let {
      if (it.endsWith("\n")) it.dropLast(1).split('\n') else it.split('\n')
    }
    val outLines = ArrayList<String>(srcLines.size + 16)

    var networksIndent = -1
    var netIndent = -1
    var currentNet = ""
    var sectionIndent = -1
    var currentSection = ""

    var i = 0
    while (i < srcLines.size) {
      val line = srcLines[i]
      val kl = parseYamlKeyLine(line)
      if (kl == null) {
        outLines.add(line)
        i++
        continue
      }

      if (sectionIndent >= 0 && kl.indent <= sectionIndent) {
        sectionIndent = -1
        currentSection = ""
      }
      if (netIndent >= 0 && kl.indent <= netIndent) {
        netIndent = -1
        currentNet = ""
        sectionIndent = -1
        currentSection = ""
      }
      if (networksIndent >= 0 && kl.indent <= networksIndent && !kl.key.equals("networks", ignoreCase = true)) {
        networksIndent = -1
        netIndent = -1
        currentNet = ""
        sectionIndent = -1
        currentSection = ""
      }

      if (networksIndent < 0 && kl.key == "networks") {
        networksIndent = kl.indent
        outLines.add(line)
        i++
        continue
      }
      if (networksIndent >= 0 && netIndent < 0 && kl.indent > networksIndent) {
        netIndent = kl.indent
        currentNet = kl.key
        outLines.add(line)
        i++
        continue
      }
      if (netIndent >= 0 && sectionIndent < 0 && kl.indent > netIndent) {
        sectionIndent = kl.indent
        currentSection = kl.key.lowercase(Locale.ROOT)
        outLines.add(line)
        i++
        continue
      }

      if (sectionIndent >= 0 && kl.indent > sectionIndent) {
        val diskNetMap = diskNets[currentNet] ?: diskNets.values.firstOrNull()
        if (currentSection == "keys" && !kl.key.equals("tls_cert", ignoreCase = true) && isRedactedValueToken(kl.rest)) {
          val diskKeys = diskNetMap?.get("keys") as? Map<*, *>
          val origVal = diskKeys?.entries?.firstOrNull { it.key.toString().equals(kl.key, ignoreCase = true) }?.value?.toString()
          if (origVal != null) {
            emitRestoredScalarLines(outLines, kl.indent, kl.rawKeyToken, origVal)
            i++
            continue
          }
        }
        if (currentSection == "options" && kl.key.lowercase(Locale.ROOT) in SECRET_OPTION_KEYS && isRedactedValueToken(kl.rest)) {
          val diskOpts = diskNetMap?.get("options") as? Map<*, *>
          val origOpt = diskOpts?.entries?.firstOrNull { it.key.toString().equals(kl.key, ignoreCase = true) }?.value
          if (origOpt != null) {
            val vals = TincYaml.valuesOf(origOpt)
            if (vals.size == 1) {
              emitRestoredScalarLines(outLines, kl.indent, kl.rawKeyToken, vals[0])
            } else if (vals.size > 1) {
              val pad = " ".repeat(kl.indent)
              val itemPad = " ".repeat(kl.indent + 2)
              outLines.add("$pad${kl.rawKeyToken}:")
              for (v in vals) outLines.add("$itemPad- ${TincYaml.formatYamlScalar(v)}")
            }
            i++
            continue
          }
        }
        if (isBlockScalarRest(kl.rest)) {
          val endIdx = findYamlEntryEndLine(srcLines, i, kl.indent)
          for (k in i..endIdx) outLines.add(srcLines[k])
          i = endIdx + 1
          continue
        }
      }

      outLines.add(line)
      i++
    }

    val restored = outLines.joinToString("\n") + if (hasTrailingNewline) "\n" else ""
    try {
      TincYaml.newYaml().load<Any?>(restored)
    } catch (e: Exception) {
      throw IllegalArgumentException("Restored YAML is invalid: ${e.message}")
    }
    return restored
  }

  private fun buildLoginHtml(): String = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>tincstack Diagnostic Panel — Вход</title>
<style>
  :root {
    --bg: #0f172a;
    --panel: #1e293b;
    --border: #334155;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --red: #ef4444;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 16px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
  }
  .card {
    width: 100%;
    max-width: 400px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
  }
  h1 {
    margin: 0 0 8px 0;
    font-size: 18px;
    color: var(--accent);
  }
  p {
    margin: 0 0 16px 0;
    font-size: 13px;
    line-height: 1.45;
    color: var(--muted);
  }
  input[type="password"] {
    width: 100%;
    padding: 10px 12px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 15px;
    margin-bottom: 12px;
  }
  button {
    width: 100%;
    padding: 10px 14px;
    border-radius: 8px;
    border: none;
    background: #0284c7;
    color: #fff;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
  }
  button:hover { background: #0369a1; }
  .err {
    margin-top: 12px;
    font-size: 13px;
    color: var(--red);
    min-height: 18px;
  }
</style>
</head>
<body>
  <div class="card">
    <h1>🔒 tincstack Diagnostic Panel</h1>
    <p>Введите пароль веб-панели. Посмотреть и скопировать пароль можно в приложении tincstack: <b>Diagnostic Panel &amp; Telemetry</b>.</p>
    <form id="login-form">
      <input type="password" id="pwd" placeholder="Пароль веб-панели" autocomplete="current-password" autofocus required>
      <button type="submit" id="btn">Войти</button>
      <div class="err" id="err"></div>
    </form>
  </div>
  <script>
    document.getElementById("login-form").addEventListener("submit", async function(ev) {
      ev.preventDefault();
      const errEl = document.getElementById("err");
      const btn = document.getElementById("btn");
      errEl.textContent = "";
      btn.disabled = true;
      try {
        const r = await fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password: document.getElementById("pwd").value })
        });
        const j = await r.json().catch(function() { return {}; });
        if (r.ok && j.ok) {
          window.location.reload();
          return;
        }
        errEl.textContent = j.error || "Неверный пароль";
      } catch (e) {
        errEl.textContent = "Ошибка соединения: " + e.message;
      } finally {
        btn.disabled = false;
      }
    });
  </script>
</body>
</html>"""

  fun isEnabled(): Boolean = synchronized(serverLock) { serverEnabled && serverSocket != null && !serverSocket!!.isClosed }

  fun getPort(): Int = synchronized(serverLock) { serverPort }

  fun loadSavedSettings(context: Context): Pair<Boolean, Int> {
    ensurePassword(context)
    val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    val en = prefs.getBoolean(PREF_ENABLED, false)
    val p = prefs.getInt(PREF_PORT, DEFAULT_DIAG_PORT).coerceIn(1024, 65535)
    synchronized(serverLock) { serverPort = p }
    return en to p
  }

  private fun saveSettings(enabled: Boolean, port: Int) {
    try {
      val prefs = App.getContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      prefs.edit().putBoolean(PREF_ENABLED, enabled).putInt(PREF_PORT, port).apply()
    } catch (_: Exception) {
    }
  }

  private fun sampleOnceNonBlocking(net: String) {
    if (!samplerBusy.compareAndSet(false, true)) return
    try {
      val snap = captureLiveSnapshot(net)
      collector.recordSnapshot(net, snap)
    } catch (_: Exception) {
    } finally {
      samplerBusy.set(false)
    }
  }

  fun ensureSamplerRunning() {
    synchronized(serverLock) {
      if (!serverEnabled) return
      if (samplerTask != null && !samplerTask!!.isDone) return
      samplerTask = samplerExec.scheduleWithFixedDelay({
        try {
          if (!isEnabled()) return@scheduleWithFixedDelay
          val net = TincVpnService.getCurrentNetName()
          if (!net.isNullOrEmpty() && TincVpnService.isDaemonRunning()) {
            sampleOnceNonBlocking(net)
          }
        } catch (_: Exception) {
        }
      }, 2500L, 2500L, TimeUnit.MILLISECONDS)
    }
  }

  private fun stopSampler() {
    synchronized(serverLock) {
      samplerTask?.cancel(false)
      samplerTask = null
    }
  }

  fun onDaemonStarted(netName: String) {
    try {
      val (savedEnabled, savedPort) = loadSavedSettings(App.getContext())
      if (savedEnabled && !isEnabled()) {
        startServer(savedPort)
      } else {
        if (isEnabled()) ensureSamplerRunning()
        syncTincdBridge(netName)
      }
    } catch (_: Exception) {
      syncTincdBridge(netName)
    }
  }

  fun syncTincdBridge(specificNet: String? = null) {
    val activePort = if (isEnabled()) getPort() else 0
    val net = specificNet ?: try { TincVpnService.getCurrentNetName() } catch (_: Exception) { null } ?: return
    httpPool.execute {
      try {
        if (TincVpnService.isDaemonRunning()) {
          runTincCli(net, 2500L, "diag-port", activePort.toString())
        }
      } catch (_: Exception) {
      }
    }
  }

  fun startServer(port: Int = DEFAULT_DIAG_PORT): Pair<Boolean, String> {
    val cleanPort = port.coerceIn(1024, 65535)
    ensurePassword()
    synchronized(serverLock) {
      if (serverEnabled && serverSocket != null && !serverSocket!!.isClosed && serverPort == cleanPort) {
        syncTincdBridge()
        return true to "Diagnostic server already running on port $cleanPort"
      }
    }
    stopServer(persist = false)
    val ss = try {
      ServerSocket().apply {
        reuseAddress = true
        bind(InetSocketAddress("127.0.0.1", cleanPort), 50)
      }
    } catch (e: Exception) {
      return false to "Could not bind port $cleanPort: ${e.message}"
    }

    synchronized(serverLock) {
      serverSocket = ss
      serverPort = cleanPort
      serverEnabled = true
    }
    saveSettings(true, cleanPort)
    ensureSamplerRunning()
    syncTincdBridge()

    Thread({
      while (!ss.isClosed) {
        val client = try {
          ss.accept()
        } catch (_: Exception) {
          break
        }
        httpPool.execute {
          try {
            handleHttpClient(client)
          } catch (_: Throwable) {
          } finally {
            try {
              client.close()
            } catch (_: Throwable) {
            }
          }
        }
      }
    }, "tinc-diag-accept-$cleanPort").apply { isDaemon = true }.start()

    log.info("Diagnostic Web Server listening on port {}", cleanPort)
    return true to "Diagnostic Web Server listening on port $cleanPort"
  }

  fun stopServer(persist: Boolean = true): Pair<Boolean, String> {
    val ss = synchronized(serverLock) {
      val old = serverSocket
      serverSocket = null
      serverEnabled = false
      old
    }
    stopSampler()
    if (persist) saveSettings(false, getPort())
    syncTincdBridge()
    try {
      ss?.close()
    } catch (_: Exception) {
    }
    return true to "Diagnostic Web Server stopped"
  }

  fun getVpnUrls(selectedNet: String? = null): List<String> {
    val p = getPort()
    val urls = mutableListOf<String>()
    val net = selectedNet ?: try { TincVpnService.getCurrentNetName() } catch (_: Exception) { null }
    if (!net.isNullOrEmpty() && isSafeNetSyntax(net)) {
      val snap = collector.getLatestSnapshot(net)
      if (snap != null && snap.error.isEmpty()) {
        for (n in snap.nodes.values) {
          if (n.isSelf && n.vpnAddress.isNotEmpty()) {
            val u = "http://${n.vpnAddress}:$p/"
            if (u !in urls) urls.add(u)
          }
        }
      }
      try {
        val s = Networks.summary(net)
        val ip = s.address?.substringBefore('/')?.trim().orEmpty()
        if (ip.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) {
          val u = "http://$ip:$p/"
          if (u !in urls) urls.add(u)
        }
      } catch (_: Exception) {
      }
    }
    urls.add("http://127.0.0.1:$p/")
    return urls
  }

  private fun loadWebUiHtml(): String {
    try {
      App.getContext().assets.open("diag_webui.html").use {
        return it.bufferedReader(StandardCharsets.UTF_8).readText()
      }
    } catch (_: Exception) {
    }
    for (candidate in listOf(
      File("src/main/assets/diag_webui.html"),
      File("app/src/main/assets/diag_webui.html"),
      File("platforms/android/app/src/main/assets/diag_webui.html"),
    )) {
      if (candidate.isFile) return candidate.readText(StandardCharsets.UTF_8)
    }
    return "<html><body><h1>tincstack Diagnostic WebUI</h1></body></html>"
  }

  private fun defaultNet(): String {
    val candidate = try {
      TincVpnService.getCurrentNetName() ?: Networks.list().firstOrNull().orEmpty()
    } catch (_: Exception) {
      ""
    }
    return if (isSafeNetSyntax(candidate)) candidate else ""
  }

  @Suppress("UNCHECKED_CAST")
  fun buildOverview(requestedNet: String = ""): Map<String, Any?> {
    if (requestedNet.isNotEmpty() && !isKnownValidNet(requestedNet)) {
      return mapOf("ok" to false, "error" to "Invalid or unknown network name")
    }
    val nets = try { Networks.list() } catch (_: Exception) { emptyList() }
    val targetNet = when {
      requestedNet.isNotEmpty() -> requestedNet
      else -> (try { TincVpnService.getCurrentNetName() } catch (_: Exception) { null })
        ?.takeIf { isSafeNetSyntax(it) }
        ?: nets.firstOrNull { isSafeNetSyntax(it) }.orEmpty()
    }

    var snap: DiagSnapshot? = null
    if (targetNet.isNotEmpty()) {
      val isDaemonActive = try { TincVpnService.isDaemonRunning() && TincVpnService.getCurrentNetName() == targetNet } catch (_: Exception) { false }
      val (cachedSnap, ageSec) = collector.getLatestSnapshotWithAge(targetNet)
      snap = when {
        cachedSnap != null && ageSec < 2.0 -> cachedSnap
        isDaemonActive && cachedSnap == null -> {
          // Initial snapshot for this network
          captureLiveSnapshot(targetNet).also { collector.recordSnapshot(targetNet, it) }
        }
        isDaemonActive && cachedSnap != null -> {
          // Serve cached snapshot immediately (0 ms) and refresh asynchronously on samplerExec
          samplerExec.execute { sampleOnceNonBlocking(targetNet) }
          cachedSnap
        }
        else -> cachedSnap ?: DiagSnapshot(targetNet, error = "VPN disconnected")
      }
    }

    val peerConfigs = LinkedHashMap<String, Map<String, Any?>>()
    val configNoDirectPeers = HashSet<String>()
    var selfNode = ""
    var myVpnIp = ""
    if (targetNet.isNotEmpty()) {
      try {
        val f = AppPaths.tincYamlFile(targetNet)
        if (f.isFile) {
          val yaml = TincYaml(f)
          val stanza = yaml.resolveNetwork(targetNet)
          selfNode = yaml.optionValue(stanza, "Name").orEmpty()
          val hostsMap = (yaml.networkMapPublic(stanza)["hosts"] as? Map<*, *>).orEmpty()
          for ((k, v) in hostsMap) {
            val hName = k.toString()
            peerConfigs[hName] = parseHostEndpoints(v?.toString())
            if (yaml.isPeerNoDirect(stanza, hName)) {
              configNoDirectPeers.add(hName.lowercase(Locale.ROOT))
            }
          }
          for (nd in yaml.optionValues(stanza, "NoDirectNodes").flatMap { it.split(Regex("[\\s,;]+")) }) {
            val clean = nd.trim().lowercase(Locale.ROOT)
            if (clean.isNotEmpty()) configNoDirectPeers.add(clean)
          }
          val summary = Networks.summary(targetNet)
          myVpnIp = summary.address?.substringBefore('/').orEmpty()
        }
      } catch (_: Exception) {
      }
    }

    val nodesList = mutableListOf<Map<String, Any?>>()
    var totalRx = 0L
    var totalTx = 0L
    if (snap != null && snap.error.isEmpty()) {
      val sorted = snap.nodes.values.sortedWith(compareBy({ !it.isSelf }, { it.name }))
      for (n in sorted) {
        if (n.isSelf) {
          selfNode = n.name
          if (n.vpnAddress.isNotEmpty()) myVpnIp = n.vpnAddress
        } else {
          totalRx += n.rxBytes
          totalTx += n.txBytes
        }
        val pcfg = peerConfigs[n.name].orEmpty()
        val isNoDirect = !n.isSelf && (n.status["no_direct"] == true || n.name.lowercase(Locale.ROOT) in configNoDirectPeers)
        nodesList.add(
          mapOf(
            "name" to n.name,
            "is_self" to n.isSelf,
            "reachable" to n.reachable,
            "no_direct" to isNoDirect,
            "link" to n.link,
            "transport" to n.transport,
            "preferred_transport" to (pcfg["preferred_transport"] ?: "auto"),
            "supported_transports" to n.supportedTransports,
            "nexthop" to n.nexthop,
            "via" to n.via,
            "distance" to n.distance,
            "rtt" to ((n.rtt * 10.0).roundToLong() / 10.0),
            "pmtu" to n.pmtu,
            "pmtu_min" to n.pmtuMin,
            "pmtu_max" to n.pmtuMax,
            "rx_bytes" to n.rxBytes,
            "tx_bytes" to n.txBytes,
            "rx_packets" to n.rxPackets,
            "tx_packets" to n.txPackets,
            "address" to n.address,
            "configured_address" to (pcfg["configured_address"] ?: ""),
            "port" to n.port,
            "vpn_address" to n.vpnAddress,
            "subnets" to n.subnets,
            "routable_subnets" to emptyList<String>(),
            "default_subnets" to emptyList<String>(),
            "status_hex" to "0x${n.statusHex}",
            "status" to n.status,
            "options_hex" to "0x${n.options}",
            "has_host_block" to (n.name in peerConfigs),
            "web_diag_url" to if (n.vpnAddress.isNotEmpty()) "http://${n.vpnAddress}:${getPort()}/" else "",
          )
        )
      }
    }

    val series = if (targetNet.isNotEmpty()) collector.getSeries(targetNet, maxPoints = 600) else emptyList()
    val lastPt = series.lastOrNull() ?: mapOf("rx_bps" to 0.0, "tx_bps" to 0.0)
    val running = snap != null && snap.error.isEmpty()

    return mapOf(
      "ok" to true,
      "platform" to "android",
      "version" to BuildConfig.VERSION_NAME,
      "hostname" to (Build.MODEL ?: "android"),
      "diag_port" to getPort(),
      "networks" to nets,
      "net" to targetNet,
      "current_net" to targetNet,
      "running" to running,
      "error" to (snap?.error ?: "No network selected"),
      "self_node" to selfNode,
      "self_vpn_ip" to myVpnIp,
      "my_vpn_ip" to myVpnIp,
      "current_bw" to mapOf(
        "rx_bps" to (lastPt["rx_bps"] ?: 0.0),
        "tx_bps" to (lastPt["tx_bps"] ?: 0.0),
        "total_rx" to totalRx,
        "total_tx" to totalTx,
      ),
      "full_tunnel" to "",
      "full_tunnel_info" to mapOf("exit_node" to "", "state" to ""),
      "os_summary" to "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) · ${Build.MANUFACTURER} ${Build.MODEL}",
      "system_info" to mapOf(
        "OS" to "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
        "Device" to "${Build.MANUFACTURER} ${Build.MODEL}",
        "Version" to BuildConfig.VERSION_NAME,
        "Network" to targetNet,
        "Diag Bridge Port" to getPort().toString(),
      ),
      "active_routes" to emptyList<String>(),
      "nodes" to nodesList,
      "edges" to (snap?.edges?.map { it.toMap() } ?: emptyList<Any>()),
      "connections" to (snap?.connections ?: emptyMap<String, String>()),
      "history" to series,
      "series" to series,
      "incidents" to if (targetNet.isNotEmpty()) collector.getIncidents(targetNet, limit = 150) else emptyList<Any>(),
    )
  }

  private fun tailFile(f: File?, maxLines: Int = 250): String {
    if (f == null || !f.isFile) return ""
    return try {
      f.readLines().takeLast(maxLines).joinToString("\n")
    } catch (_: Exception) {
      ""
    }
  }

  fun buildLogs(net: String = "", source: String = "tincd", lines: Int = 250): Map<String, Any?> {
    if (net.isNotEmpty() && !isKnownValidNet(net)) {
      return mapOf("ok" to false, "error" to "Invalid or unknown network name")
    }
    val safeLines = lines.coerceIn(1, 5000)
    val targetNet = net.ifEmpty { defaultNet() }
    val tincdLog = try { if (targetNet.isNotEmpty()) AppPaths.logFile(targetNet) else null } catch (_: Exception) { null }
    val appLog = try { AppPaths.appLogFile() } catch (_: Exception) { null }
    val evLog = if (targetNet.isNotEmpty()) collector.eventsFile(targetNet) else null
    val tText = tailFile(tincdLog, safeLines)
    val aText = tailFile(appLog, safeLines)
    val eText = tailFile(evLog, safeLines)
    val cText = aText.lines().filter {
      it.contains("ERROR") || it.contains("Exception") || it.contains("Fatal") || it.trimStart().startsWith("at ") || it.trimStart().startsWith("Caused by:")
    }.takeLast(safeLines).joinToString("\n")
    val selected = when (source) {
      "tincd" -> tText
      "crash" -> cText.ifEmpty { "(Сбоев и стектрейсов не зафиксировано)" }
      "events" -> eText
      else -> aText
    }
    return mapOf(
      "ok" to true,
      "net" to targetNet,
      "source" to source,
      "text" to selected,
      "tincd_log" to tText,
      "tincmgr_log" to aText,
      "crash_log" to cText,
      "has_crashes" to cText.isNotEmpty(),
    )
  }

  @Suppress("UNCHECKED_CAST")
  fun buildConfig(net: String = ""): Map<String, Any?> {
    if (net.isNotEmpty() && !isKnownValidNet(net)) {
      return mapOf("ok" to false, "error" to "Invalid or unknown network name")
    }
    val targetNet = net.ifEmpty { defaultNet() }
    var rawYaml = ""
    var optionsMap = emptyMap<String, Any?>()
    var hostsMap = emptyMap<String, String>()
    var prefVal = ""
    var trVal = ""
    var reconnectOnNet = true
    var disconnectScreenOff = false
    var lowPower = false
    if (targetNet.isNotEmpty()) {
      try {
        val f = AppPaths.tincYamlFile(targetNet)
        if (f.isFile) {
          rawYaml = redactYamlSecrets(f.readText())
          val yaml = TincYaml(f)
          val stanza = yaml.resolveNetwork(targetNet)
          val rawOpts = LinkedHashMap<String, Any?>()
          for ((k, v) in yaml.options(stanza)) {
            if (k.lowercase(Locale.ROOT) in SECRET_OPTION_KEYS) {
              rawOpts[k] = listOf(REDACTED_MARKER)
            } else {
              rawOpts[k] = v
            }
          }
          optionsMap = rawOpts
          val rawHosts = (yaml.networkMapPublic(stanza)["hosts"] as? Map<*, *>).orEmpty()
          hostsMap = rawHosts.entries.associate { it.key.toString() to it.value?.toString().orEmpty() }
          prefVal = yaml.optionValues(stanza, "PreferredTransports").joinToString(", ")
          trVal = yaml.optionValues(stanza, "Transports").joinToString(", ")
          reconnectOnNet = TincYaml.asTincBoolean(yaml.optionValue(stanza, "ReconnectOnNetworkChange"), true)
          disconnectScreenOff = TincYaml.asTincBoolean(yaml.optionValue(stanza, "DisconnectOnScreenOff"), false)
          lowPower = TincYaml.asTincBoolean(yaml.optionValue(stanza, "LowPowerMode"), false)
        }
      } catch (_: Exception) {
      }
    }
    return mapOf(
      "ok" to true,
      "net" to targetNet,
      "transports" to trVal,
      "preferred_transports" to prefVal,
      "reconnect_on_net_change" to reconnectOnNet,
      "disconnect_on_screen_off" to disconnectScreenOff,
      "low_power_mode" to lowPower,
      "options" to optionsMap,
      "hosts" to hostsMap,
      "raw_yaml" to rawYaml,
    )
  }

  fun buildExportBundle(net: String = ""): Map<String, Any?> {
    if (net.isNotEmpty() && !isKnownValidNet(net)) {
      return mapOf("ok" to false, "error" to "Invalid or unknown network name")
    }
    val targetNet = net.ifEmpty { defaultNet() }
    val cfg = LinkedHashMap(buildConfig(targetNet))
    cfg.remove("raw_yaml")
    val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
      timeZone = TimeZone.getTimeZone("UTC")
    }
    return mapOf(
      "exported_at" to sdf.format(Date()),
      "overview" to buildOverview(targetNet),
      "logs" to buildLogs(targetNet, lines = 500),
      "config" to cfg,
      "dns_cache" to runProbe(targetNet, "dns", emptyMap()),
      "os_routes" to runProbe(targetNet, "routes", emptyMap()),
    )
  }

  fun handleAction(net: String, rawAction: String, payload: Map<String, Any?>): Pair<Boolean, Map<String, Any?>> {
    if (net.isNotEmpty() && !isKnownValidNet(net)) {
      return false to mapOf("ok" to false, "message" to "Invalid or unknown network name")
    }
    val targetNet = net.ifEmpty { defaultNet() }
    val action = if (rawAction == "daemon") (payload["op"]?.toString() ?: "").trim() else rawAction.trim()

    return try {
      when (action) {
        "start" -> {
          if (targetNet.isEmpty() || !isKnownValidNet(targetNet)) {
            return false to mapOf("ok" to false, "message" to "No valid network selected")
          }
          TincVpnService.connect(targetNet)
          true to mapOf("ok" to true, "message" to "Connecting $targetNet")
        }
        "stop" -> {
          TincVpnService.disconnect()
          true to mapOf("ok" to true, "message" to "Disconnecting VPN")
        }
        "restart" -> {
          if (targetNet.isEmpty() || !isKnownValidNet(targetNet)) {
            return false to mapOf("ok" to false, "message" to "No valid network selected")
          }
          TincVpnService.connect(targetNet)
          true to mapOf("ok" to true, "message" to "Restarting $targetNet")
        }
        "reload" -> {
          val (rc, lines) = runTincCli(targetNet, 4000L, "reload")
          (rc == 0) to mapOf("ok" to (rc == 0), "message" to lines.joinToString("\n").trim().ifEmpty { "Reloaded $targetNet" })
        }
        "retry" -> {
          val (rc, lines) = runTincCli(targetNet, 4000L, "retry")
          (rc == 0) to mapOf("ok" to (rc == 0), "message" to lines.joinToString("\n").trim().ifEmpty { "Retry triggered" })
        }
        "purge" -> {
          val (rc, lines) = runTincCli(targetNet, 4000L, "purge")
          (rc == 0) to mapOf("ok" to (rc == 0), "message" to lines.joinToString("\n").trim().ifEmpty { "Purged unreachable nodes" })
        }
        "debug" -> {
          val level = ((payload["level"] as? Number)?.toInt() ?: payload["level"]?.toString()?.toIntOrNull() ?: 0).coerceIn(0, 5)
          val (rc, lines) = runTincCli(targetNet, 4000L, "debug", level.toString())
          val msg = lines.joinToString("\n").trim()
          (rc == 0) to mapOf("ok" to (rc == 0), "message" to msg.ifEmpty { "Debug level set to $level" })
        }
        "clear_incidents" -> {
          if (targetNet.isEmpty() || !isKnownValidNet(targetNet)) {
            return false to mapOf("ok" to false, "message" to "No valid network selected")
          }
          collector.clearIncidents(targetNet)
          true to mapOf("ok" to true, "message" to "Журнал инцидентов очищен")
        }
        "clear_crash_log" -> {
          try { AppPaths.crashFlagFile().delete() } catch (_: Exception) {}
          true to mapOf("ok" to true, "message" to "Флаг сбоя очищен")
        }
        "peer_info" -> {
          val peer = (payload["peer"]?.toString() ?: "").trim()
          if (!isSafeNodeName(peer)) return false to mapOf("ok" to false, "message" to "Invalid peer name")
          val (rc, lines) = runTincCli(targetNet, 5000L, "info", peer)
          val out = lines.joinToString("\n").trim()
          (rc == 0) to mapOf("ok" to (rc == 0), "message" to out, "output" to out)
        }
        "reconnect_peer", "peer_reconnect" -> {
          val peer = (payload["peer"]?.toString() ?: "").trim()
          if (!isSafeNodeName(peer)) return false to mapOf("ok" to false, "message" to "Invalid peer name")
          runTincCli(targetNet, 3500L, "reload")
          runTincCli(targetNet, 3500L, "disconnect", peer)
          runTincCli(targetNet, 3500L, "retry")
          true to mapOf("ok" to true, "message" to "Reconnected $peer")
        }
        "switch_transport", "peer_transport" -> {
          val peer = (payload["peer"]?.toString() ?: "").trim()
          val carrier = (payload["carrier"] ?: payload["transport"] ?: "auto").toString().trim().lowercase()
          if (targetNet.isEmpty() || !isKnownValidNet(targetNet) || !isSafeNodeName(peer)) {
            return false to mapOf("ok" to false, "message" to "Invalid network or peer")
          }
          val yaml = TincYaml(AppPaths.tincYamlFile(targetNet))
          val stanza = yaml.resolveNetwork(targetNet)
          val valToSet = if (carrier == "auto") null else listOf(carrier)
          yaml.editBatch {
            setHostMultiVars(
              stanza,
              peer,
              mapOf("PreferredTransports" to valToSet, "PreferredTransport" to null),
              createIfMissing = true,
            )
            if (carrier != "auto") {
              ensureConnectToIfDialable(stanza, peer)
            }
          }
          runTincCli(targetNet, 3500L, "reload")
          runTincCli(targetNet, 3500L, "disconnect", peer)
          runTincCli(targetNet, 3500L, "retry")
          collector.addIncident(
            net = targetNet,
            kind = "USER_ACTION",
            severity = "info",
            peer = peer,
            summary = "Switched preferred transport for '$peer' to '$carrier' via Diagnostic WebUI",
          )
          true to mapOf("ok" to true, "message" to "Switched $peer transport to $carrier")
        }
        "set_peer_direct", "toggle_no_direct" -> {
          val peer = (payload["peer"]?.toString() ?: "").trim()
          if (targetNet.isEmpty() || !isKnownValidNet(targetNet) || !isSafeNodeName(peer)) {
            return false to mapOf("ok" to false, "message" to "Invalid network or peer")
          }
          val yaml = TincYaml(AppPaths.tincYamlFile(targetNet))
          val stanza = yaml.resolveNetwork(targetNet)
          var resolvedNoDirect = false
          yaml.editBatch {
            val noDirect = when {
              payload.containsKey("no_direct") -> payload["no_direct"] as? Boolean ?: payload["no_direct"]?.toString().toBoolean()
              payload.containsKey("direct") -> !(payload["direct"] as? Boolean ?: payload["direct"]?.toString().toBoolean())
              else -> !isPeerNoDirect(stanza, peer)
            }
            resolvedNoDirect = noDirect
            setPeerNoDirect(stanza, peer, noDirect)
          }
          runTincCli(targetNet, 3500L, "reload")
          val modeStr = if (resolvedNoDirect) "Relay only (no direct connect)" else "Direct connect allowed"
          collector.addIncident(
            net = targetNet,
            kind = "USER_ACTION",
            severity = "info",
            peer = peer,
            summary = "Set '$peer' direct connect policy to '$modeStr' via Diagnostic WebUI",
          )
          true to mapOf("ok" to true, "message" to "$peer: $modeStr", "no_direct" to resolvedNoDirect)
        }
        "save_host", "peer_save_host" -> {
          val host = (payload["host"] ?: payload["peer"] ?: "").toString().trim()
          val content = (payload["content"] ?: payload["text"] ?: "").toString().trimEnd('\n')
          if (targetNet.isEmpty() || !isKnownValidNet(targetNet) || !isSafeNodeName(host)) {
            return false to mapOf("ok" to false, "message" to "Invalid network or host name")
          }
          val yaml = TincYaml(AppPaths.tincYamlFile(targetNet))
          val stanza = yaml.resolveNetwork(targetNet)
          yaml.editBatch {
            setHostText(stanza, host, content)
            val blocked = optionValues(stanza, "BlockedNodes").flatMap { it.split(Regex("[\\s,;]+")) }.map { it.trim() }.filter { it.isNotEmpty() && it != host }
            setOptions(stanza, mapOf("BlockedNodes" to blocked.ifEmpty { null }))
          }
          runTincCli(targetNet, 3500L, "reload")
          true to mapOf("ok" to true, "message" to "Saved host '$host'")
        }
        "delete_host" -> {
          val host = (payload["host"] ?: payload["peer"] ?: "").toString().trim()
          if (targetNet.isEmpty() || !isKnownValidNet(targetNet) || !isSafeNodeName(host)) {
            return false to mapOf("ok" to false, "message" to "Invalid network or host name")
          }
          val yaml = TincYaml(AppPaths.tincYamlFile(targetNet))
          val stanza = yaml.resolveNetwork(targetNet)
          yaml.editBatch {
            removeHost(stanza, host)
            val blocked = optionValues(stanza, "BlockedNodes").flatMap { it.split(Regex("[\\s,;]+")) }.map { it.trim() }.filter { it.isNotEmpty() }.toMutableList()
            if (host !in blocked) blocked.add(host)
            val ct = optionValues(stanza, "ConnectTo").flatMap { it.split(Regex("[\\s,;]+")) }.map { it.trim() }.filter { it.isNotEmpty() && it != host }
            setOptions(stanza, mapOf("BlockedNodes" to blocked, "ConnectTo" to ct.ifEmpty { null }))
          }
          runTincCli(targetNet, 3500L, "reload")
          true to mapOf("ok" to true, "message" to "Deleted and blocked host '$host'")
        }
        "save_settings" -> {
          if (targetNet.isEmpty() || !isKnownValidNet(targetNet)) {
            return false to mapOf("ok" to false, "message" to "Invalid network")
          }
          val yaml = TincYaml(AppPaths.tincYamlFile(targetNet))
          val stanza = yaml.resolveNetwork(targetNet)
          val trStr = (payload["transports"]?.toString() ?: "").trim()
          val prefStr = (payload["preferred_transports"]?.toString() ?: "").trim()
          val trList = trStr.split(Regex("[\\s,;]+")).map { it.trim() }.filter { it.isNotEmpty() }.ifEmpty { null }
          val prefList = prefStr.split(Regex("[\\s,;]+")).map { it.trim() }.filter { it.isNotEmpty() }.ifEmpty { null }
          val updates = mutableMapOf<String, List<String>?>(
            "Transports" to trList,
            "PreferredTransports" to prefList,
          )
          if (payload.containsKey("reconnect_on_net_change")) {
            val reconn = payload["reconnect_on_net_change"]?.toString()?.toBooleanStrictOrNull() ?: true
            updates["ReconnectOnNetworkChange"] = if (reconn) null else listOf("no")
          }
          if (payload.containsKey("disconnect_on_screen_off")) {
            val pauseLock = payload["disconnect_on_screen_off"]?.toString()?.toBooleanStrictOrNull() ?: false
            updates["DisconnectOnScreenOff"] = if (pauseLock) listOf("yes") else null
          }
          if (payload.containsKey("low_power_mode")) {
            val lowPwr = payload["low_power_mode"]?.toString()?.toBooleanStrictOrNull() ?: false
            updates["LowPowerMode"] = if (lowPwr) listOf("yes") else null
          }
          yaml.setOptions(stanza, updates)
          runTincCli(targetNet, 3500L, "reload")
          true to mapOf("ok" to true, "message" to "Saved network settings")
        }
        "save_raw_yaml" -> {
          if (targetNet.isEmpty() || !isKnownValidNet(targetNet)) {
            return false to mapOf("ok" to false, "message" to "Invalid network")
          }
          val rawText = payload["raw_yaml"]?.toString().orEmpty()
          if (rawText.isBlank()) return false to mapOf("ok" to false, "message" to "Empty YAML")
          val f = AppPaths.tincYamlFile(targetNet)
          val origYaml = if (f.isFile) f.readText() else ""
          val validatedYaml = restoreYamlSecretsAndValidate(rawText, origYaml)
          TincYaml(f).writeRawText(validatedYaml)
          runTincCli(targetNet, 3500L, "reload")
          true to mapOf("ok" to true, "message" to "Saved tinc.yaml")
        }
        "invite" -> {
          val peer = (payload["peer"]?.toString() ?: "").trim()
          if (!isSafeNodeName(peer)) return false to mapOf("ok" to false, "message" to "Valid invitee name required")
          val (rc, lines) = runTincCli(targetNet, 10000L, "invite", peer)
          val url = lines.joinToString("\n").trim()
          if (rc != 0) return false to mapOf("ok" to false, "message" to url.ifEmpty { "Invite failed" })
          true to mapOf("ok" to true, "message" to "Invitation created for $peer", "invite_url" to url, "output" to url)
        }
        else -> false to mapOf("ok" to false, "message" to "Unsupported action: $action")
      }
    } catch (e: Exception) {
      false to mapOf("ok" to false, "message" to ((e.cause ?: e).message ?: "Action failed"))
    }
  }

  private fun readAsciiLine(ins: InputStream): String? {
    val sb = StringBuilder()
    while (true) {
      val b = ins.read()
      if (b < 0) return if (sb.isEmpty()) null else sb.toString()
      if (b == '\n'.code) break
      if (b != '\r'.code) sb.append((b and 0xFF).toChar())
      if (sb.length > MAX_HEADER_LINE_LEN) {
        throw IllegalArgumentException("HTTP header line exceeds $MAX_HEADER_LINE_LEN bytes")
      }
    }
    return sb.toString()
  }

  internal fun safeUrlDecode(raw: String): String {
    return try {
      URLDecoder.decode(raw, "UTF-8")
    } catch (_: Exception) {
      raw
    }
  }

  internal fun parseQuery(query: String): Map<String, String> {
    if (query.isEmpty()) return emptyMap()
    val out = LinkedHashMap<String, String>()
    for (part in query.split('&')) {
      if (part.isEmpty()) continue
      val eq = part.indexOf('=')
      if (eq >= 0) {
        val k = safeUrlDecode(part.substring(0, eq))
        val v = safeUrlDecode(part.substring(eq + 1))
        out[k] = v
      } else {
        out[safeUrlDecode(part)] = ""
      }
    }
    return out
  }

  @Suppress("UNCHECKED_CAST")
  private fun handleHttpClient(socket: Socket) {
    socket.use { s ->
      s.soTimeout = 30_000
      val ins = BufferedInputStream(s.getInputStream())
      val out = BufferedOutputStream(s.getOutputStream())

      fun sendResponse(status: Int, contentType: String, body: ByteArray, extraHeaders: Map<String, String> = emptyMap()) {
        val statusText = when (status) {
          200 -> "OK"
          400 -> "Bad Request"
          401 -> "Unauthorized"
          403 -> "Forbidden"
          404 -> "Not Found"
          405 -> "Method Not Allowed"
          413 -> "Payload Too Large"
          429 -> "Too Many Requests"
          else -> "Server Error"
        }
        val hdr = StringBuilder()
        hdr.append("HTTP/1.1 $status $statusText\r\n")
        hdr.append("Content-Type: $contentType\r\n")
        hdr.append("Cache-Control: no-store\r\n")
        hdr.append("Connection: close\r\n")
        hdr.append("Content-Length: ${body.size}\r\n")
        for ((k, v) in extraHeaders) {
          val safeKey = k.replace("\r", "").replace("\n", "")
          val safeVal = v.replace("\r", "").replace("\n", "")
          hdr.append("$safeKey: $safeVal\r\n")
        }
        hdr.append("\r\n")
        out.write(hdr.toString().toByteArray(StandardCharsets.UTF_8))
        out.write(body)
        out.flush()
      }

      fun sendJson(obj: Any?, status: Int = 200, extraHeaders: Map<String, String> = emptyMap()) {
        val bytes = JsonCodec.stringify(obj).toByteArray(StandardCharsets.UTF_8)
        sendResponse(status, "application/json; charset=utf-8", bytes, extraHeaders)
      }

      val reqLine = try {
        readAsciiLine(ins)
      } catch (_: IllegalArgumentException) {
        sendJson(mapOf("ok" to false, "error" to "Request line too long"), status = 400)
        return
      } ?: return

      val parts = reqLine.split(' ')
      if (parts.size < 2) return
      val method = parts[0].uppercase(Locale.ROOT)
      val fullPath = parts[1]
      val path = fullPath.substringBefore('?')
      val query = if ('?' in fullPath) fullPath.substringAfter('?') else ""
      val qs = parseQuery(query)

      var contentLength = 0
      var invalidContentLength = false
      var bodyTooLarge = false
      var originHeader = ""
      var hostHeader = ""
      var authHeader = ""
      var diagPwdHeader = ""
      var cookieHeader = ""
      var headerCount = 0

      while (true) {
        val h = try {
          readAsciiLine(ins)
        } catch (_: IllegalArgumentException) {
          sendJson(mapOf("ok" to false, "error" to "Header line too long"), status = 400)
          return
        } ?: break
        if (h.isEmpty()) break
        headerCount++
        if (headerCount > MAX_HTTP_HEADERS) {
          sendJson(mapOf("ok" to false, "error" to "Too many HTTP headers"), status = 400)
          return
        }
        val colon = h.indexOf(':')
        if (colon <= 0) continue
        val hName = h.substring(0, colon).trim().lowercase(Locale.ROOT)
        val hVal = h.substring(colon + 1).trim()
        when (hName) {
          "content-length" -> {
            val parsed = hVal.toLongOrNull()
            when {
              parsed == null || parsed < 0L -> invalidContentLength = true
              parsed > MAX_HTTP_BODY_BYTES -> bodyTooLarge = true
              else -> contentLength = parsed.toInt()
            }
          }
          "origin" -> originHeader = hVal
          "host" -> hostHeader = hVal
          "authorization" -> authHeader = hVal
          "x-diag-password" -> diagPwdHeader = hVal
          "cookie" -> cookieHeader = if (cookieHeader.isEmpty()) hVal else "$cookieHeader; $hVal"
        }
      }

      // 1. Strict Host whitelist check on ALL methods (mitigates DNS rebinding)
      val allowedIps = collectOwnVpnIps()
      if (!isAllowedHost(hostHeader, allowedIps)) {
        sendJson(mapOf("ok" to false, "error" to "Forbidden Host header"), status = 403)
        return
      }

      if (invalidContentLength) {
        sendJson(mapOf("ok" to false, "error" to "Invalid Content-Length"), status = 400)
        return
      }
      if (bodyTooLarge) {
        sendJson(mapOf("ok" to false, "error" to "Payload too large"), status = 413)
        return
      }

      val bodyBytes = if (contentLength > 0) {
        val buf = ByteArray(contentLength)
        var off = 0
        while (off < contentLength) {
          val n = ins.read(buf, off, contentLength - off)
          if (n < 0) break
          off += n
        }
        if (off < contentLength) {
          sendJson(mapOf("ok" to false, "error" to "Truncated request body"), status = 400)
          return
        }
        buf
      } else {
        ByteArray(0)
      }

      val (authKind, sessionSid) = authenticateRequest(authHeader, diagPwdHeader, cookieHeader)
      val net = qs["net"]?.trim().orEmpty()

      if (method == "GET") {
        if (path == "/" || path == "/index.html") {
          if (authKind == AuthKind.NONE) {
            val loginHtml = buildLoginHtml().toByteArray(StandardCharsets.UTF_8)
            sendResponse(200, "text/html; charset=utf-8", loginHtml)
          } else {
            val html = loadWebUiHtml().toByteArray(StandardCharsets.UTF_8)
            sendResponse(200, "text/html; charset=utf-8", html)
          }
          return
        }

        if (authKind == AuthKind.NONE) {
          sendJson(
            mapOf("ok" to false, "auth_required" to true, "error" to "Authentication required"),
            status = 401,
          )
          return
        }

        if (net.isNotEmpty() && !isKnownValidNet(net)) {
          sendJson(mapOf("ok" to false, "error" to "Invalid or unknown network name"), status = 400)
          return
        }

        when (path) {
          "/api/overview" -> sendJson(buildOverview(net))
          "/api/logs" -> {
            val lines = qs["lines"]?.toIntOrNull() ?: 250
            val source = qs["source"]?.trim()?.ifEmpty { "tincd" } ?: "tincd"
            sendJson(buildLogs(net, source, lines))
          }
          "/api/config" -> sendJson(buildConfig(net))
          "/api/export" -> {
            val bundle = buildExportBundle(net)
            val safeLabel = if (net.isEmpty()) "all" else net.replace(Regex("[^A-Za-z0-9_.-]"), "_")
            val fname = "tincstack-android-diag-$safeLabel-${System.currentTimeMillis() / 1000}.json"
            sendJson(bundle, extraHeaders = mapOf("Content-Disposition" to "attachment; filename=\"$fname\""))
          }
          else -> sendJson(mapOf("ok" to false, "error" to "Not found"), status = 404)
        }
        return
      }

      if (method == "POST") {
        // 2. Strict Origin check on POST (mitigates CSRF & login CSRF)
        val allowMissingOrigin = (authKind == AuthKind.HEADER)
        if (!isAllowedOrigin(originHeader, hostHeader, allowMissingOrigin, allowedIps)) {
          sendJson(mapOf("ok" to false, "error" to "Cross-origin POST rejected"), status = 403)
          return
        }

        val payload: Map<String, Any?> = if (bodyBytes.isNotEmpty()) {
          val str = String(bodyBytes, StandardCharsets.UTF_8)
          val parsed = try {
            JsonCodec.parse(str)
          } catch (_: Exception) {
            sendJson(mapOf("ok" to false, "error" to "Invalid JSON body"), status = 400)
            return
          }
          if (parsed !is Map<*, *>) {
            sendJson(mapOf("ok" to false, "error" to "JSON body must be an object"), status = 400)
            return
          }
          parsed as Map<String, Any?>
        } else {
          emptyMap()
        }

        if (path == "/api/login") {
          val submittedPwd = payload["password"]?.toString().orEmpty()
          val expectedPwd = ensurePassword()
          if (submittedPwd.isNotEmpty() && constantTimeEquals(submittedPwd, expectedPwd)) {
            val sid = issueSession()
            sendJson(
              mapOf("ok" to true),
              status = 200,
              extraHeaders = mapOf(
                "Set-Cookie" to "$SESSION_COOKIE_NAME=$sid; HttpOnly; SameSite=Strict; Path=/",
              ),
            )
          } else {
            try {
              Thread.sleep(50)
            } catch (_: InterruptedException) {
            }
            sendJson(
              mapOf("ok" to false, "auth_required" to true, "error" to "Invalid password"),
              status = 401,
            )
          }
          return
        }

        if (path == "/api/logout") {
          revokeSession(sessionSid)
          sendJson(
            mapOf("ok" to true),
            status = 200,
            extraHeaders = mapOf(
              "Set-Cookie" to "$SESSION_COOKIE_NAME=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/",
            ),
          )
          return
        }

        if (authKind == AuthKind.NONE) {
          sendJson(
            mapOf("ok" to false, "auth_required" to true, "error" to "Authentication required"),
            status = 401,
          )
          return
        }

        val postNet = (payload["net"]?.toString() ?: net).trim()
        if (postNet.isNotEmpty() && !isKnownValidNet(postNet)) {
          sendJson(mapOf("ok" to false, "error" to "Invalid or unknown network name"), status = 400)
          return
        }

        when (path) {
          "/api/mark" -> {
            val targetNet = postNet.ifEmpty { defaultNet() }
            if (targetNet.isEmpty() || !isKnownValidNet(targetNet)) {
              sendJson(mapOf("ok" to false, "error" to "No network configured"), status = 400)
              return
            }
            val note = payload["note"]?.toString().orEmpty()
            val ev = collector.recordUserMark(targetNet, note)
            sendJson(mapOf("ok" to true, "message" to "Метка затупа сохранена", "event" to ev.toMap()))
          }
          "/api/probe" -> {
            val targetNet = postNet.ifEmpty { defaultNet() }
            val tool = (payload["tool"] ?: payload["kind"] ?: "").toString().trim()
            sendJson(runProbe(targetNet, tool, payload))
          }
          "/api/action" -> {
            val targetNet = postNet.ifEmpty { defaultNet() }
            val act = (payload["action"] ?: "").toString().trim()
            val (ok, resp) = handleAction(targetNet, act, payload)
            sendJson(resp, status = if (ok) 200 else 400)
          }
          else -> sendJson(mapOf("ok" to false, "error" to "Not found"), status = 404)
        }
        return
      }

      sendJson(mapOf("ok" to false, "error" to "Method not allowed"), status = 405)
    }
  }

  // ---- Pure Kotlin JSON Codec (zero Android SDK dependency for unit tests) --

  object JsonCodec {
    fun stringify(value: Any?): String {
      val sb = StringBuilder()
      writeValue(sb, value)
      return sb.toString()
    }

    private fun writeValue(sb: StringBuilder, value: Any?) {
      when (value) {
        null -> sb.append("null")
        is Boolean -> sb.append(if (value) "true" else "false")
        is Number -> {
          val d = value.toDouble()
          if (d.isNaN() || d.isInfinite()) sb.append("null") else sb.append(value.toString())
        }
        is String -> writeString(sb, value)
        is Map<*, *> -> {
          sb.append('{')
          var first = true
          for ((k, v) in value) {
            if (k == null) continue
            if (!first) sb.append(',')
            first = false
            writeString(sb, k.toString())
            sb.append(':')
            writeValue(sb, v)
          }
          sb.append('}')
        }
        is Iterable<*> -> {
          sb.append('[')
          var first = true
          for (item in value) {
            if (!first) sb.append(',')
            first = false
            writeValue(sb, item)
          }
          sb.append(']')
        }
        is Array<*> -> {
          sb.append('[')
          var first = true
          for (item in value) {
            if (!first) sb.append(',')
            first = false
            writeValue(sb, item)
          }
          sb.append(']')
        }
        is Pair<*, *> -> {
          sb.append('[')
          writeValue(sb, value.first)
          sb.append(',')
          writeValue(sb, value.second)
          sb.append(']')
        }
        else -> writeString(sb, value.toString())
      }
    }

    private fun writeString(sb: StringBuilder, s: String) {
      sb.append('"')
      for (c in s) {
        when (c) {
          '"' -> sb.append("\\\"")
          '\\' -> sb.append("\\\\")
          '\b' -> sb.append("\\b")
          '\u000C' -> sb.append("\\f")
          '\n' -> sb.append("\\n")
          '\r' -> sb.append("\\r")
          '\t' -> sb.append("\\t")
          else -> {
            if (c.code < 0x20) {
              sb.append(String.format(Locale.US, "\\u%04x", c.code))
            } else {
              sb.append(c)
            }
          }
        }
      }
      sb.append('"')
    }

    fun parse(json: String): Any? = Parser(json).parseValue()

    private class Parser(private val s: String) {
      private var i = 0

      fun parseValue(): Any? {
        skipWs()
        if (i >= s.length) throw IllegalArgumentException("Unexpected EOF")
        return when (val c = s[i]) {
          '{' -> parseObject()
          '[' -> parseArray()
          '"' -> parseString()
          't' -> { expect("true"); true }
          'f' -> { expect("false"); false }
          'n' -> { expect("null"); null }
          '-', in '0'..'9' -> parseNumber()
          else -> throw IllegalArgumentException("Unexpected char '$c' at $i")
        }
      }

      private fun skipWs() {
        while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
      }

      private fun expect(lit: String) {
        if (!s.startsWith(lit, i)) throw IllegalArgumentException("Expected '$lit' at $i")
        i += lit.length
      }

      private fun parseObject(): Map<String, Any?> {
        i++
        skipWs()
        val map = LinkedHashMap<String, Any?>()
        if (i < s.length && s[i] == '}') {
          i++
          return map
        }
        while (true) {
          skipWs()
          val k = parseString()
          skipWs()
          if (i >= s.length || s[i] != ':') throw IllegalArgumentException("Expected ':' at $i")
          i++
          map[k] = parseValue()
          skipWs()
          if (i < s.length && s[i] == ',') {
            i++
            continue
          }
          if (i < s.length && s[i] == '}') {
            i++
            return map
          }
          throw IllegalArgumentException("Expected ',' or '}' at $i")
        }
      }

      private fun parseArray(): List<Any?> {
        i++
        skipWs()
        val list = ArrayList<Any?>()
        if (i < s.length && s[i] == ']') {
          i++
          return list
        }
        while (true) {
          list.add(parseValue())
          skipWs()
          if (i < s.length && s[i] == ',') {
            i++
            continue
          }
          if (i < s.length && s[i] == ']') {
            i++
            return list
          }
          throw IllegalArgumentException("Expected ',' or ']' at $i")
        }
      }

      private fun parseString(): String {
        if (i >= s.length || s[i] != '"') throw IllegalArgumentException("Expected '\"' at $i")
        i++
        val sb = StringBuilder()
        while (i < s.length) {
          val c = s[i++]
          if (c == '"') return sb.toString()
          if (c == '\\') {
            if (i >= s.length) throw IllegalArgumentException("Unterminated escape")
            when (val esc = s[i++]) {
              '"', '\\', '/' -> sb.append(esc)
              'b' -> sb.append('\b')
              'f' -> sb.append('\u000C')
              'n' -> sb.append('\n')
              'r' -> sb.append('\r')
              't' -> sb.append('\t')
              'u' -> {
                if (i + 4 > s.length) throw IllegalArgumentException("Bad unicode escape")
                sb.append(s.substring(i, i + 4).toInt(16).toChar())
                i += 4
              }
              else -> sb.append(esc)
            }
          } else {
            sb.append(c)
          }
        }
        throw IllegalArgumentException("Unterminated string")
      }

      private fun parseNumber(): Number {
        val start = i
        if (s[i] == '-') i++
        while (i < s.length && s[i] in '0'..'9') i++
        var isFloat = false
        if (i < s.length && s[i] == '.') {
          isFloat = true
          i++
          while (i < s.length && s[i] in '0'..'9') i++
        }
        if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
          isFloat = true
          i++
          if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
          while (i < s.length && s[i] in '0'..'9') i++
        }
        val raw = s.substring(start, i)
        return if (isFloat) raw.toDouble() else raw.toLong()
      }
    }
  }
}
