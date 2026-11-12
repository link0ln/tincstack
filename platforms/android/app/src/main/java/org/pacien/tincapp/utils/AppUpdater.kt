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

package org.pacien.tincapp.utils

import java8.util.concurrent.CompletableFuture
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Checks GitHub Releases (`releases/latest`) for a newer signed Android APK,
 * verifies its SHA-256 against `SHA256SUMS` (and optional release-notes digest,
 * or the GitHub asset SHA-256 digest), and stages it under the app cache for
 * installation via `FileProvider`.
 */
object AppUpdater {
  const val API = "https://api.github.com/repos/link0ln/tincstack/releases/latest"
  const val CHECK_MIN_MS = 3L * 60 * 60 * 1000
  const val USER_AGENT = "tincstack-android-update-check"
  const val MAX_METADATA_BYTES = 2 * 1024 * 1024

  private val downloadLocks = ConcurrentHashMap<String, ReentrantLock>()
  private val inFlightLock = Any()
  private var inFlightFuture: CompletableFuture<File>? = null
  @Volatile var activeDownloadRelease: Release? = null
    private set
  @Volatile var lastDownloadProgress: Pair<Long, Long>? = null
    private set
  private val progressListeners = CopyOnWriteArrayList<(Long, Long) -> Unit>()

  fun isDownloading(): Boolean = synchronized(inFlightLock) {
    inFlightFuture?.isDone == false
  }

  fun attachProgressListener(listener: (Long, Long) -> Unit): () -> Unit {
    progressListeners.add(listener)
    lastDownloadProgress?.let { (read, total) -> listener(read, total) }
    return { progressListeners.remove(listener) }
  }

  fun currentInFlightDownload(): CompletableFuture<File>? = synchronized(inFlightLock) {
    inFlightFuture?.takeIf { !it.isDone }
  }

  fun startOrJoinDownload(
    rel: Release,
    destDir: File,
    asyncRunner: (Runnable) -> Unit,
  ): CompletableFuture<File> = synchronized(inFlightLock) {
    val existing = inFlightFuture
    if (existing != null && !existing.isDone) {
      return existing
    }
    val future = CompletableFuture<File>()
    inFlightFuture = future
    activeDownloadRelease = rel
    lastDownloadProgress = null
    asyncRunner(Runnable {
      try {
        val apk = fetchApk(rel, destDir) { read, total ->
          lastDownloadProgress = read to total
          for (l in progressListeners) {
            runCatching { l(read, total) }
          }
        }
        future.complete(apk)
      } catch (t: Throwable) {
        future.completeExceptionally(t)
      } finally {
        synchronized(inFlightLock) {
          if (inFlightFuture === future) {
            inFlightFuture = null
            activeDownloadRelease = null
            lastDownloadProgress = null
          }
        }
      }
    })
    future
  }

  private fun lockForTarget(targetFile: File): ReentrantLock {
    val key = try { targetFile.canonicalPath } catch (_: IOException) { targetFile.absolutePath }
    downloadLocks[key]?.let { return it }
    val created = ReentrantLock()
    return downloadLocks.putIfAbsent(key, created) ?: created
  }

  private val VERSION_RE = Regex("""^v?(\d+)\.(\d+)\.(\d+)$""")
  private val APK_NAME_RE = Regex("""^tincstack-v[\d.]+(?:-[a-zA-Z0-9_]+)?\.apk$""")
  private val HEX64_RE = Regex("""^[0-9a-fA-F]{64}$""")
  private val NOTES_SUMS_RE = Regex(
    """([0-9a-fA-F]{64})\s+\*?SHA256SUMS\b|SHA256SUMS[^0-9a-fA-F\r\n]*([0-9a-fA-F]{64})"""
  )

  data class Release(
    val tag: String,
    val version: String,
    val apkName: String,
    val apkUrl: String,
    val sumsUrl: String,
    val apkDigest: String = "",
    val notes: String = "",
  )

  sealed class CheckResult {
    data class UpdateAvailable(val release: Release) : CheckResult()
    data class UpToDate(val version: String) : CheckResult()
    data class Error(val message: String) : CheckResult()
  }

  fun parseVersion(v: String?): Triple<Int, Int, Int>? {
    val m = VERSION_RE.matchEntire((v ?: "").trim()) ?: return null
    val (maj, min, pat) = m.destructured
    return Triple(maj.toInt(), min.toInt(), pat.toInt())
  }

  fun isNewer(installedVersion: String?, releaseVersion: String): Boolean {
    val theirs = parseVersion(releaseVersion) ?: return false
    val ours = parseVersion(installedVersion) ?: return true
    return compareValuesBy(theirs, ours, { it.first }, { it.second }, { it.third }) > 0
  }

  @Suppress("UNCHECKED_CAST")
  fun findAssets(releaseJson: String): Release? {
    val root = try {
      JsonParser(releaseJson).parseValue() as? Map<String, Any?>
    } catch (_: Exception) {
      null
    } ?: return null

    if (root["draft"] == true || root["prerelease"] == true) return null
    val tag = (root["tag_name"] as? String)?.trim().orEmpty()
    if (parseVersion(tag) == null) return null
    val body = (root["body"] as? String).orEmpty()
    val rawAssets = (root["assets"] as? List<*>) ?: emptyList<Any?>()

    var apkName = ""
    var apkUrl = ""
    var apkDigest = ""
    var sumsUrl = ""

    for (entry in rawAssets) {
      val a = entry as? Map<String, Any?> ?: continue
      val name = (a["name"] as? String).orEmpty()
      val url = (a["browser_download_url"] as? String).orEmpty()
      val digest = (a["digest"] as? String).orEmpty()
      if (name.isEmpty() || !isHttpsUrl(url)) continue
      if (name == "SHA256SUMS") {
        sumsUrl = url
      } else if (apkName.isEmpty() && !name.contains("UNSIGNED", ignoreCase = true) && APK_NAME_RE.matches(name)) {
        apkName = name
        apkUrl = url
        apkDigest = digest
      }
    }
    if (apkName.isEmpty() || apkUrl.isEmpty()) return null
    return Release(
      tag = tag,
      version = tag,
      apkName = apkName,
      apkUrl = apkUrl,
      sumsUrl = sumsUrl,
      apkDigest = apkDigest,
      notes = body,
    )
  }

  fun checkDetailed(
    installedVersion: String?,
    fetcher: (String) -> String = { httpGetBytes(it, 20_000).toString(Charsets.UTF_8) },
  ): CheckResult {
    val body = try {
      fetcher(API)
    } catch (e: Exception) {
      return CheckResult.Error(e.message ?: e.javaClass.simpleName)
    }
    val rel = findAssets(body)
      ?: return CheckResult.Error("No signed Android APK in the latest release")
    return if (isNewer(installedVersion, rel.version)) {
      CheckResult.UpdateAvailable(rel)
    } else {
      CheckResult.UpToDate(rel.version)
    }
  }

  fun checkIfDue(
    installedVersion: String?,
    nowMs: Long,
    lastCheckMs: Long,
    force: Boolean = false,
    fetcher: (String) -> String = { httpGetBytes(it, 20_000).toString(Charsets.UTF_8) },
  ): Release? {
    if (!force && lastCheckMs > 0L && (nowMs - lastCheckMs) < CHECK_MIN_MS) {
      return null
    }
    return (checkDetailed(installedVersion, fetcher) as? CheckResult.UpdateAvailable)?.release
  }

  fun parseSums(text: String): Map<String, String> {
    val out = mutableMapOf<String, String>()
    for (line in text.lineSequence()) {
      val parts = line.trim().split(Regex("""\s+"""), limit = 2)
      if (parts.size == 2 && HEX64_RE.matches(parts[0])) {
        val name = File(parts[1].trimStart('*')).name
        out[name] = parts[0].lowercase()
      }
    }
    return out
  }

  fun extractNotesSumsSha256(notes: String): String? {
    val m = NOTES_SUMS_RE.find(notes) ?: return null
    val hex = m.groupValues[1].ifEmpty { m.groupValues[2] }
    return hex.lowercase().takeIf { it.length == 64 }
  }

  private fun isHttpsUrl(url: String): Boolean =
    url.trim().lowercase().startsWith("https://")

  private fun requireHttpsUrl(url: String, label: String): String {
    val trimmed = url.trim()
    if (!isHttpsUrl(trimmed)) {
      throw IOException("Refusing non-HTTPS $label URL: $trimmed")
    }
    return trimmed
  }

  private fun parseMetadataSha256(rawDigest: String): String? {
    val trimmed = rawDigest.trim()
    if (trimmed.isEmpty()) return null
    if (!trimmed.lowercase().startsWith("sha256:")) {
      throw IOException("Unsupported APK digest format in release metadata: $trimmed")
    }
    val digestHex = trimmed.substringAfter(':').trim().lowercase()
    if (!HEX64_RE.matches(digestHex)) {
      throw IOException("Malformed APK SHA-256 digest in release metadata")
    }
    return digestHex
  }

  fun expectedApkSha256(
    rel: Release,
    sumsFetcher: (String) -> ByteArray = { httpGetBytes(it, 60_000) },
  ): String {
    requireHttpsUrl(rel.apkUrl, "APK")
    val safeName = File(rel.apkName).name
    if (!APK_NAME_RE.matches(safeName)) {
      throw IOException("Refusing invalid APK asset name: ${rel.apkName}")
    }
    val metadataSha = parseMetadataSha256(rel.apkDigest)
    if (rel.sumsUrl.isNotEmpty()) {
      val sumsUrl = requireHttpsUrl(rel.sumsUrl, "SHA256SUMS")
      val sumsBytes = sumsFetcher(sumsUrl)
      val expectedSumsSha = extractNotesSumsSha256(rel.notes)
      if (expectedSumsSha != null) {
        val gotSumsSha = sha256Bytes(sumsBytes)
        if (!MessageDigest.isEqual(gotSumsSha.toByteArray(Charsets.US_ASCII), expectedSumsSha.toByteArray(Charsets.US_ASCII))) {
          throw IOException("SHA256SUMS does not match the digest in release notes")
        }
      }
      val sums = parseSums(sumsBytes.toString(Charsets.UTF_8))
      val want = sums[safeName]
        ?: throw IOException("$safeName is not listed in SHA256SUMS")
      if (metadataSha != null && !MessageDigest.isEqual(want.toByteArray(Charsets.US_ASCII), metadataSha.toByteArray(Charsets.US_ASCII))) {
        throw IOException("SHA256SUMS digest for $safeName disagrees with release asset digest")
      }
      return want
    }
    if (metadataSha != null) {
      return metadataSha
    }
    throw IOException("Release ${rel.version} provides no SHA-256 checksum for $safeName")
  }

  fun fetchApk(
    rel: Release,
    destDir: File,
    onProgress: ((Long, Long) -> Unit)? = null,
  ): File {
    if (!destDir.exists() && !destDir.mkdirs() && !destDir.isDirectory) {
      throw IOException("Could not create update directory ${destDir.absolutePath}")
    }
    val safeName = File(rel.apkName).name
    if (!APK_NAME_RE.matches(safeName)) {
      throw IOException("Refusing invalid APK asset name: ${rel.apkName}")
    }
    val targetFile = File(destDir, safeName)
    return lockForTarget(targetFile).withLock {
      val expectedSha = expectedApkSha256(rel)

      if (targetFile.isFile && sha256File(targetFile) == expectedSha) {
        return@withLock targetFile
      }

      val partFile = File(destDir, "$safeName.part")
      val conn = openConnection(requireHttpsUrl(rel.apkUrl, "APK"), 600_000)
      try {
        val total = conn.contentLengthLong
        val md = MessageDigest.getInstance("SHA-256")
        var readSoFar = 0L
        conn.inputStream.use { input ->
          FileOutputStream(partFile).use { output ->
            val buf = ByteArray(64 * 1024)
            while (true) {
              val n = input.read(buf)
              if (n < 0) break
              if (n == 0) continue
              output.write(buf, 0, n)
              md.update(buf, 0, n)
              readSoFar += n
              onProgress?.invoke(readSoFar, total)
            }
            output.fd.sync()
          }
        }
        if (total > 0L && readSoFar != total) {
          partFile.delete()
          throw IOException("Truncated APK download ($readSoFar of $total bytes)")
        }
        val gotSha = md.digest().joinToString("") { "%02x".format(it) }
        if (!MessageDigest.isEqual(gotSha.toByteArray(Charsets.US_ASCII), expectedSha.toByteArray(Charsets.US_ASCII))) {
          partFile.delete()
          throw IOException("Downloaded APK SHA-256 mismatch (expected ${expectedSha.take(12)}…, got ${gotSha.take(12)}…)")
        }
      } catch (e: Exception) {
        partFile.delete()
        throw e
      } finally {
        conn.disconnect()
      }

      destDir.listFiles()?.forEach { f ->
        if (f != partFile && f.name.endsWith(".apk")) f.delete()
      }
      if (targetFile.exists()) targetFile.delete()
      if (!partFile.renameTo(targetFile)) {
        throw IOException("Could not move verified APK into place")
      }
      targetFile
    }
  }

  fun sha256Bytes(bytes: ByteArray): String {
    val md = MessageDigest.getInstance("SHA-256")
    return md.digest(bytes).joinToString("") { "%02x".format(it) }
  }

  fun sha256File(file: File): String {
    val md = MessageDigest.getInstance("SHA-256")
    FileInputStream(file).use { input ->
      val buf = ByteArray(64 * 1024)
      while (true) {
        val n = input.read(buf)
        if (n <= 0) break
        md.update(buf, 0, n)
      }
    }
    return md.digest().joinToString("") { "%02x".format(it) }
  }

  private fun openConnection(url: String, timeoutMs: Int): HttpURLConnection {
    var currentUrl = requireHttpsUrl(url, "update")
    repeat(5) {
      val parsed = URL(currentUrl)
      if (!parsed.protocol.equals("https", ignoreCase = true)) {
        throw IOException("Refusing non-HTTPS redirect target: $currentUrl")
      }
      val conn = (parsed.openConnection() as HttpURLConnection).apply {
        instanceFollowRedirects = false
        connectTimeout = 20_000
        readTimeout = timeoutMs
        setRequestProperty("User-Agent", USER_AGENT)
        setRequestProperty("Accept", "*/*")
      }
      val code = conn.responseCode
      if (code in 300..399) {
        val loc = conn.getHeaderField("Location")
        conn.disconnect()
        if (loc.isNullOrEmpty()) throw IOException("HTTP redirect ($code) without Location header")
        currentUrl = requireHttpsUrl(URL(parsed, loc).toString(), "redirect")
      } else if (code in 200..299) {
        return conn
      } else {
        conn.disconnect()
        throw IOException("HTTP $code from $currentUrl")
      }
    }
    throw IOException("Too many redirects fetching $url")
  }

  internal fun readBoundedBytes(
    input: InputStream,
    maxBytes: Int = MAX_METADATA_BYTES,
    label: String = "response",
  ): ByteArray {
    val out = ByteArrayOutputStream()
    val buf = ByteArray(16 * 1024)
    var total = 0
    while (true) {
      val n = input.read(buf)
      if (n < 0) break
      if (n == 0) continue
      total += n
      if (total > maxBytes) {
        throw IOException("Response from $label exceeds $maxBytes bytes")
      }
      out.write(buf, 0, n)
    }
    return out.toByteArray()
  }

  private fun httpGetBytes(url: String, timeoutMs: Int, maxBytes: Int = MAX_METADATA_BYTES): ByteArray {
    val conn = openConnection(url, timeoutMs)
    return try {
      val declared = conn.contentLengthLong
      if (declared > maxBytes) {
        throw IOException("Response from $url exceeds $maxBytes bytes ($declared)")
      }
      conn.inputStream.use { readBoundedBytes(it, maxBytes, url) }
    } finally {
      conn.disconnect()
    }
  }

  internal fun parseJson(json: String): Any? = JsonParser(json).parseValue()

  /**
   * Minimal RFC 8259 JSON parser so `findAssets` works identically on Android
   * and in local JUnit tests (where `android.jar`'s `org.json` classes are
   * unmocked stubs).
   */
  private class JsonParser(private val s: String) {
    private var i = 0

    fun parseValue(): Any? {
      skipWs()
      if (i >= s.length) throw IllegalArgumentException("Unexpected end of JSON")
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
      i++ // '{'
      skipWs()
      val map = LinkedHashMap<String, Any?>()
      if (i < s.length && s[i] == '}') {
        i++
        return map
      }
      while (true) {
        skipWs()
        val key = parseString()
        skipWs()
        if (i >= s.length || s[i] != ':') throw IllegalArgumentException("Expected ':' at $i")
        i++
        val value = parseValue()
        map[key] = value
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
      i++ // '['
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
          if (i >= s.length) throw IllegalArgumentException("Unterminated escape at $i")
          when (val esc = s[i++]) {
            '"', '\\', '/' -> sb.append(esc)
            'b' -> sb.append('\b')
            'f' -> sb.append('\u000C')
            'n' -> sb.append('\n')
            'r' -> sb.append('\r')
            't' -> sb.append('\t')
            'u' -> {
              if (i + 4 > s.length) throw IllegalArgumentException("Bad unicode escape at $i")
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
      return if (isFloat) {
        raw.toDoubleOrNull() ?: throw IllegalArgumentException("Invalid JSON number: $raw")
      } else {
        raw.toLongOrNull() ?: raw.toDoubleOrNull() ?: throw IllegalArgumentException("Invalid JSON number: $raw")
      }
    }
  }
}
