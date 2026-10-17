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

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

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
      if (name.isEmpty() || url.isEmpty()) continue
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

  fun expectedApkSha256(
    rel: Release,
    sumsFetcher: (String) -> ByteArray = { httpGetBytes(it, 60_000) },
  ): String {
    if (rel.sumsUrl.isNotEmpty()) {
      val sumsBytes = sumsFetcher(rel.sumsUrl)
      val expectedSumsSha = extractNotesSumsSha256(rel.notes)
      if (expectedSumsSha != null) {
        val gotSumsSha = sha256Bytes(sumsBytes)
        if (gotSumsSha != expectedSumsSha) {
          throw IOException("SHA256SUMS does not match the digest in release notes")
        }
      }
      val sums = parseSums(sumsBytes.toString(Charsets.UTF_8))
      val want = sums[rel.apkName]
        ?: throw IOException("${rel.apkName} is not listed in SHA256SUMS")
      return want
    }
    if (rel.apkDigest.lowercase().startsWith("sha256:")) {
      val digestHex = rel.apkDigest.substringAfter(':').trim().lowercase()
      if (HEX64_RE.matches(digestHex)) return digestHex
    }
    throw IOException("Release ${rel.version} provides no SHA-256 checksum for ${rel.apkName}")
  }

  fun fetchApk(
    rel: Release,
    destDir: File,
    onProgress: ((Long, Long) -> Unit)? = null,
  ): File {
    if (!destDir.exists() && !destDir.mkdirs()) {
      throw IOException("Could not create update directory ${destDir.absolutePath}")
    }
    val safeName = File(rel.apkName).name
    val targetFile = File(destDir, safeName)
    val expectedSha = expectedApkSha256(rel)

    if (targetFile.isFile && sha256File(targetFile) == expectedSha) {
      return targetFile
    }

    val partFile = File(destDir, "$safeName.part")
    val conn = openConnection(rel.apkUrl, 600_000)
    try {
      val total = conn.contentLengthLong
      val md = MessageDigest.getInstance("SHA-256")
      conn.inputStream.use { input ->
        FileOutputStream(partFile).use { output ->
          val buf = ByteArray(64 * 1024)
          var readSoFar = 0L
          while (true) {
            val n = input.read(buf)
            if (n <= 0) break
            output.write(buf, 0, n)
            md.update(buf, 0, n)
            readSoFar += n
            onProgress?.invoke(readSoFar, total)
          }
          output.fd.sync()
        }
      }
      val gotSha = md.digest().joinToString("") { "%02x".format(it) }
      if (gotSha != expectedSha) {
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
    return targetFile
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
    var currentUrl = url
    repeat(5) {
      val conn = (URL(currentUrl).openConnection() as HttpURLConnection).apply {
        instanceFollowRedirects = true
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
        currentUrl = URL(URL(currentUrl), loc).toString()
      } else if (code in 200..299) {
        return conn
      } else {
        conn.disconnect()
        throw IOException("HTTP $code from $currentUrl")
      }
    }
    throw IOException("Too many redirects fetching $url")
  }

  private fun httpGetBytes(url: String, timeoutMs: Int): ByteArray {
    val conn = openConnection(url, timeoutMs)
    return try {
      conn.inputStream.use { it.readBytes() }
    } finally {
      conn.disconnect()
    }
  }

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
      return if (isFloat) raw.toDouble() else raw.toLong()
    }
  }
}
