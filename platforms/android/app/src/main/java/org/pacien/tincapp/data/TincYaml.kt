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

import org.yaml.snakeyaml.DumperOptions
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor
import org.yaml.snakeyaml.nodes.Tag
import org.yaml.snakeyaml.representer.Representer
import org.yaml.snakeyaml.resolver.Resolver
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.RandomAccessFile
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * The one tincstack configuration file of a network (`tinc.yaml`, see
 * docs/config-schema.md). The daemon owns and rewrites this file (it embeds the
 * private keys and persists learned peer keys into it), so the app treats it as
 * a document it may only *edit*, never regenerate:
 *
 *  - reads go through a full YAML parser (SnakeYAML);
 *  - writes touch only the `networks.<net>.options.<key>` entries the app
 *    manages, as a textual splice of the existing document, and replace the
 *    file atomically (temp file + rename), exactly like the daemon's own
 *    write-back. Everything else in the file (keys, hosts, comments, unrelated
 *    options) is preserved byte for byte.
 *
 * The daemon's parser (core/tincd/src/yamlconf.c) understands block mappings,
 * block sequences, flow sequences, literal block scalars and plain scalars.
 * This writer emits only that subset: `Key: value` for single values and a
 * block sequence (`Key:` + `- item` lines) for lists.
 */
class TincYaml(val file: File) {
  class InvalidConfigurationException(msg: String) : RuntimeException(msg)

  /** Parsed `networks:` map, or an empty map for an absent/empty file. */
  fun networks(): Map<String, Any?> = MEM_LOCK.withLock {
    if (!file.exists()) return@withLock emptyMap()
    parseNetworksFromText(file.readText(), file.name)
  }

  private fun parseNetworksFromText(rawText: String, sourceName: String = file.name): Map<String, Any?> {
    if (rawText.isBlank()) return emptyMap()
    val root = try {
      newYaml().load<Any?>(rawText)
    } catch (e: Exception) {
      throw InvalidConfigurationException("$sourceName: ${e.message}")
    }
    if (root == null) return emptyMap()
    if (root !is Map<*, *>) throw InvalidConfigurationException("$sourceName: top level is not a mapping")
    val networks = root["networks"] ?: return emptyMap()
    if (networks !is Map<*, *>) throw InvalidConfigurationException("$sourceName: 'networks' is not a mapping")
    return networks.entries.associate { it.key.toString() to it.value }
  }

  fun networkNames(): List<String> = networks().keys.toList()

  /**
   * The stanza the app should operate on for a network directory named
   * [preferred]: that stanza if present, else the first one in the file (the
   * daemon's own rule when no `-n` is given), else [preferred] (a file the
   * daemon has yet to materialise).
   */
  fun resolveNetwork(preferred: String): String {
    val names = networkNames()
    return if (preferred in names) preferred else names.firstOrNull() ?: preferred
  }

  private fun networkMap(net: String): Map<String, Any?> {
    val n = networks()[net] ?: return emptyMap()
    if (n !is Map<*, *>) throw InvalidConfigurationException("${file.name}: network '$net' is not a mapping")
    return n.entries.associate { it.key.toString() to it.value }
  }

  /** The parsed network stanza, for readers that need a section this class has no accessor for. */
  fun networkMapPublic(net: String): Map<String, Any?> = networkMap(net)

  private fun sectionMap(net: String, section: String): Map<String, Any?> {
    val s = networkMap(net)[section] ?: return emptyMap()
    if (s !is Map<*, *>) throw InvalidConfigurationException("${file.name}: '$section' of network '$net' is not a mapping")
    return s.entries.associate { it.key.toString() to it.value }
  }

  /** `networks.<net>.options`, values as parsed by YAML (String, Int, Boolean, List, ...). */
  fun options(net: String): Map<String, Any?> = sectionMap(net, "options")

  /**
   * An option as the list of its values: a scalar is a one-element list, a
   * sequence its items, an absent key an empty list. Booleans are rendered as
   * tinc's `yes`/`no`.
   */
  fun optionValues(net: String, key: String): List<String> =
    valuesOf(options(net)[key])

  fun optionValue(net: String, key: String): String? =
    optionValues(net, key).firstOrNull()

  /** Host-file text of `networks.<net>.hosts.<name>`, or null. */
  fun hostText(net: String, name: String): String? =
    sectionMap(net, "hosts")[name]?.toString()

  /** All host names in `networks.<net>.hosts`, with the own node (`Name`) first if present. */
  fun hostNames(net: String): List<String> {
    val own = optionValue(net, "Name")
    val names = sectionMap(net, "hosts").keys.toList()
    return listOfNotNull(own?.takeIf { it in names }) + names.filter { it != own }
  }

  /** True if direct connections to [peerName] are forbidden via `NoDirectNodes` or `DirectConnect = no`. */
  fun isPeerNoDirect(net: String, peerName: String): Boolean {
    val peer = peerName.trim()
    if (peer.isEmpty()) return false
    val ndList = optionValues(net, "NoDirectNodes")
      .flatMap { it.split(Regex("[\\s,;]+")) }
      .map { it.trim() }
      .filter { it.isNotEmpty() }
    if (ndList.any { it.equals(peer, ignoreCase = true) }) return true
    val hText = hostText(net, peer) ?: return false
    return PeerConfig(peer, hText).noDirect
  }

  /**
   * Transactional in-memory editor for `tinc.yaml` so multi-step updates
   * (`options:` + `hosts:` changes, peer deletion + option cleanup, etc.)
   * execute under one file lock and replace `tinc.yaml` in a single atomic rename.
   */
  inner class BatchEditor internal constructor(private var docText: String) {
    internal fun resultText(): String = docText

    private fun netMap(net: String): Map<String, Any?> {
      val n = parseNetworksFromText(docText)[net] ?: return emptyMap()
      if (n !is Map<*, *>) throw InvalidConfigurationException("${file.name}: network '$net' is not a mapping")
      return n.entries.associate { it.key.toString() to it.value }
    }

    private fun secMap(net: String, section: String): Map<String, Any?> {
      val s = netMap(net)[section] ?: return emptyMap()
      if (s !is Map<*, *>) throw InvalidConfigurationException("${file.name}: '$section' of network '$net' is not a mapping")
      return s.entries.associate { it.key.toString() to it.value }
    }

    fun optionValues(net: String, key: String): List<String> =
      valuesOf(secMap(net, "options")[key])

    fun optionValue(net: String, key: String): String? =
      optionValues(net, key).firstOrNull()

    fun hostText(net: String, name: String): String? =
      secMap(net, "hosts")[name]?.toString()

    fun hostNames(net: String): List<String> {
      val own = optionValue(net, "Name")
      val names = secMap(net, "hosts").keys.toList()
      return listOfNotNull(own?.takeIf { it in names }) + names.filter { it != own }
    }

    fun isPeerNoDirect(net: String, peerName: String): Boolean {
      val peer = peerName.trim()
      if (peer.isEmpty()) return false
      val ndList = optionValues(net, "NoDirectNodes")
        .flatMap { it.split(Regex("[\\s,;]+")) }
        .map { it.trim() }
        .filter { it.isNotEmpty() }
      if (ndList.any { it.equals(peer, ignoreCase = true) }) return true
      val hText = hostText(net, peer) ?: return false
      return PeerConfig(peer, hText).noDirect
    }

    fun setOptions(net: String, changes: Map<String, List<String>?>) {
      if (changes.isEmpty()) return
      docText = splice(docText, net, changes)
    }

    fun setHostVars(net: String, name: String, changes: Map<String, String?>) {
      if (changes.isEmpty()) return
      val original = hostText(net, name)
        ?: throw InvalidConfigurationException("no host record for '$name' in ${file.name}")
      val edited = spliceHostVars(original, changes)
      if (edited != original) {
        docText = replaceHostBlockInText(docText, net, name, edited, file.name)
      }
    }

    fun setHostMultiVars(net: String, name: String, changes: Map<String, List<String>?>, createIfMissing: Boolean = true) {
      val current = hostText(net, name)
      if (changes.isEmpty() && current != null) return
      val original = current
        ?: if (createIfMissing) "" else throw InvalidConfigurationException("no host record for '$name' in ${file.name}")
      val edited = spliceHostMultiVars(original, changes)
      if (edited != original || current == null) {
        docText = replaceHostBlockInText(docText, net, name, edited, file.name)
      }
    }

    fun setHostText(net: String, name: String, newText: String) {
      val original = hostText(net, name)
      val merged = mergeLearnedTofuKeys(newText, original).trimEnd()
      val origTrimmed = original?.trimEnd()
      if (merged != origTrimmed) {
        docText = replaceHostBlockInText(docText, net, name, if (merged.isEmpty()) "" else "$merged\n", file.name)
      }
    }

    fun removeHost(net: String, name: String) {
      if (docText.isEmpty()) return
      docText = removeHostBlockInText(docText, net, name)
    }

    fun setPeerNoDirect(net: String, peerName: String, noDirect: Boolean) {
      val peer = peerName.trim()
      if (peer.isEmpty()) return
      val ndList = optionValues(net, "NoDirectNodes")
        .flatMap { it.split(Regex("[\\s,;]+")) }
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .toMutableList()
      if (noDirect) {
        if (ndList.none { it.equals(peer, ignoreCase = true) }) ndList.add(peer)
      } else {
        ndList.removeAll { it.equals(peer, ignoreCase = true) }
      }
      setOptions(net, mapOf("NoDirectNodes" to ndList.ifEmpty { null }))
      if (hostText(net, peer) != null) {
        val hostChanges = if (noDirect) mapOf("DirectConnect" to "no") else mapOf("DirectConnect" to null)
        setHostVars(net, peer, hostChanges)
      }
    }

    fun ensureConnectToIfDialable(net: String, peerName: String) {
      val peer = peerName.trim()
      if (peer.isEmpty() || isPeerNoDirect(net, peer)) return
      val hText = hostText(net, peer) ?: return
      if (PeerConfig(peer, hText).address.isNullOrBlank()) return
      val ct = optionValues(net, "ConnectTo")
        .flatMap { it.split(Regex("[\\s,;]+")) }
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .toMutableList()
      if (ct.none { it.equals(peer, ignoreCase = true) }) {
        ct.add(peer)
        setOptions(net, mapOf("ConnectTo" to ct))
      }
    }
  }

  /** Apply multiple mutations in memory under one lock and commit with a single atomic write. */
  fun editBatch(block: BatchEditor.() -> Unit) = withFileLock {
    val original = if (file.exists()) file.readText() else ""
    val editor = BatchEditor(original)
    editor.block()
    val updated = editor.resultText()
    if (updated != original) {
      writeAtomically(updated)
    }
  }

  /** Enable or disable relay-only mode (`NoDirectNodes` / `DirectConnect = no`) for [peerName].
   *  Preserves `ConnectTo` and `IndirectData` as lower-level topology declarations. */
  fun setPeerNoDirect(net: String, peerName: String, noDirect: Boolean) = editBatch {
    setPeerNoDirect(net, peerName, noDirect)
  }

  /** Replace or create the full host record `networks.<net>.hosts.<name>` with [newText]. */
  fun setHostText(net: String, name: String, newText: String) = editBatch {
    setHostText(net, name, newText)
  }

  /**
   * Ensure [peerName] is listed in `ConnectTo` when direct connections to it
   * are allowed (`!isPeerNoDirect`) and its host record declares an `Address`.
   */
  fun ensureConnectToIfDialable(net: String, peerName: String) = editBatch {
    ensureConnectToIfDialable(net, peerName)
  }

  /** Raw text of `tinc.yaml`, or empty string if absent. */
  fun readRawText(): String = MEM_LOCK.withLock { if (file.exists()) file.readText() else "" }

  /** Validate that [newText] is a valid `tinc.yaml` mapping and write it atomically, preserving daemon-learned TOFU keys. */
  fun writeRawText(newText: String) = withFileLock {
    val root = try {
      newYaml().load<Any?>(newText)
    } catch (e: Exception) {
      throw InvalidConfigurationException("${file.name}: ${e.message}")
    }
    if (root !is Map<*, *>) throw InvalidConfigurationException("${file.name}: top level is not a mapping")
    val networks = root["networks"]
    if (networks != null && networks !is Map<*, *>) {
      throw InvalidConfigurationException("${file.name}: 'networks' is not a mapping")
    }
    val original = if (file.exists()) file.readText() else ""
    var normalized = newText.trimEnd() + "\n"
    if (original.isNotBlank() && networks is Map<*, *>) {
      val diskNets = try {
        parseNetworksFromText(original)
      } catch (_: Exception) {
        emptyMap()
      }
      for ((rawNetKey, rawNetVal) in networks.entries) {
        val netName = rawNetKey?.toString() ?: continue
        val diskNet = diskNets[netName] as? Map<*, *> ?: continue
        val diskHosts = diskNet["hosts"] as? Map<*, *> ?: continue
        val newHosts = (rawNetVal as? Map<*, *>)?.get("hosts") as? Map<*, *> ?: continue
        for ((rawHostKey, rawHostVal) in newHosts.entries) {
          val hostName = rawHostKey?.toString() ?: continue
          val diskHostBody = diskHosts[hostName]?.toString() ?: continue
          val newHostBody = rawHostVal?.toString() ?: continue
          val mergedBody = mergeLearnedTofuKeys(newHostBody, diskHostBody).trimEnd()
          if (mergedBody != newHostBody.trimEnd()) {
            normalized = replaceHostBlockInText(normalized, netName, hostName, "$mergedBody\n", file.name)
          }
        }
      }
    }
    if (normalized != original) writeAtomically(normalized)
  }

  /**
   * Host-file variable `key` of this network's own node (`hosts.<Name>`), all
   * occurrences, in file order.
   */
  fun ownHostValues(net: String, key: String): List<String> {
    val name = optionValue(net, "Name") ?: return emptyList()
    val text = hostText(net, name) ?: return emptyList()
    return parseHostKeyValues(text)
      .filter { it.first.equals(key, ignoreCase = true) }
      .map { it.second }
  }

  /**
   * Set (or, with a null/empty list, remove) option keys of `networks.<net>`
   * and write the file back atomically. Only the named keys are touched; the
   * rest of the document is preserved verbatim. Missing `networks:` / `<net>:`
   * / `options:` scaffolding is created.
   */
  fun setOptions(net: String, changes: Map<String, List<String>?>) = withFileLock {
    if (changes.isEmpty()) return@withFileLock
    val original = if (file.exists()) file.readText() else ""
    val edited = splice(original, net, changes)
    if (edited != original) writeAtomically(edited)
  }

  /** Create the file with a minimal stanza (`Name` only); the daemon fills in the rest at first start. */
  fun createNetwork(net: String, nodeName: String) = withFileLock {
    if (file.exists()) throw IOException("${file.absolutePath} already exists")
    file.parentFile?.mkdirs()
    writeAtomically(splice("", net, mapOf("Name" to listOf(nodeName))))
  }

  /**
   * Rewrite `Key = value` lines inside the host record `networks.<net>.hosts.<name>`
   * and write the file back atomically. Only the named keys are touched; every
   * other line (PEM, comments, unknown keys) is preserved byte for byte, in
   * place. A value of null removes all lines of that key; a value with no
   * existing line is appended to the end of the record's `Key = value` lines.
   */
  fun setHostVars(net: String, name: String, changes: Map<String, String?>) = withFileLock {
    if (changes.isEmpty()) return@withFileLock
    val original = hostText(net, name)
      ?: throw InvalidConfigurationException("no host record for '$name' in ${file.name}")
    val edited = spliceHostVars(original, changes)
    if (edited != original) replaceHostBlock(net, name, edited)
  }

  /**
   * Rewrite single- or multi-value `Key = value` lines inside `networks.<net>.hosts.<name>`,
   * creating the host record if it does not yet exist.
   */
  fun setHostMultiVars(net: String, name: String, changes: Map<String, List<String>?>, createIfMissing: Boolean = true) = withFileLock {
    if (changes.isEmpty() && hostText(net, name) != null) return@withFileLock
    val original = hostText(net, name)
      ?: if (createIfMissing) "" else throw InvalidConfigurationException("no host record for '$name' in ${file.name}")
    val edited = spliceHostMultiVars(original, changes)
    if (edited != original || hostText(net, name) == null) replaceHostBlock(net, name, edited)
  }

  /** Pure function: the record text with `Key = value` lines replaced/removed/appended. */
  fun spliceHostVars(text: String, changes: Map<String, String?>): String =
    spliceHostMultiVars(text, changes.mapValues { (_, v) ->
      v?.trim()?.takeIf { it.isNotEmpty() }?.let(::listOf)
    })

  /**
   * Pure function: the record text with single- or multi-value `Key = value` lines
   * replaced/removed/appended in place.
   */
  fun spliceHostMultiVars(text: String, changes: Map<String, List<String>?>): String {
    val lines = if (text.isEmpty()) mutableListOf() else text.split('\n').toMutableList()
    val changesLeft = changes.toMutableMap()
    val touchedKeys = changes.keys.map { it.lowercase() }.toSet()

    // replace/remove in place, case-insensitive on the key, first occurrence wins;
    // subsequent occurrences of a touched key are dropped so deletions/replacements are complete.
    var i = 0
    var inPem = false
    while (i < lines.size) {
      val trimmed = lines[i].trim()
      if (trimmed.startsWith("-----BEGIN ")) inPem = true
      if (inPem || !isHostKeyValueLine(trimmed)) {
        if (trimmed.startsWith("-----END ")) inPem = false
        i++
        continue
      }
      val key = trimmed.substringBefore('=').trim()
      if (key.lowercase() !in touchedKeys) {
        i++
        continue
      }
      val match = changesLeft.keys.firstOrNull { it.equals(key, ignoreCase = true) }
      if (match != null) {
        val values = changesLeft.remove(match)?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()
        if (values.isEmpty()) {
          lines.removeAt(i)
          continue
        } else {
          lines.removeAt(i)
          val replacement = values.map { "$key = $it" }
          lines.addAll(i, replacement)
          i += replacement.size
          continue
        }
      } else {
        lines.removeAt(i)
        continue
      }
    }

    // append the keys that had no line, after the last Key = value line (outside PEM blocks)
    if (changesLeft.isNotEmpty()) {
      var last = -1
      var pem = false
      for (idx in lines.indices) {
        val trimmed = lines[idx].trim()
        if (trimmed.startsWith("-----BEGIN ")) pem = true
        if (!pem && isHostKeyValueLine(trimmed)) last = idx
        if (trimmed.startsWith("-----END ")) pem = false
      }
      val added = changesLeft.entries.flatMap { (k, vals) ->
        vals?.map { it.trim() }?.filter { it.isNotEmpty() }?.map { "$k = $it" }.orEmpty()
      }
      if (added.isNotEmpty()) {
        lines.addAll(last + 1, added)
      }
    }

    // collapse runs of blank lines a removal may have produced; drop trailing ones
    val joined = lines.joinToString("\n").replace("\n{3,}".toRegex(), "\n\n").trimEnd()
    return if (joined.isEmpty()) "" else "$joined\n"
  }

  /** Replace or create the body of `networks.<net>.hosts.<name>` with [newText], preserving indentation. */
  private fun replaceHostBlock(net: String, name: String, newText: String) {
    val updated = replaceHostBlockInText(file.readText(), net, name, newText, file.name)
    writeAtomically(updated)
  }

  /** Remove the host block `networks.<net>.hosts.<name>` if present. */
  fun removeHost(net: String, name: String) = withFileLock {
    if (!file.exists()) return@withFileLock
    val original = file.readText()
    val updated = removeHostBlockInText(original, net, name)
    if (updated != original) writeAtomically(updated)
  }

  private fun <T> withFileLock(block: () -> T): T = MEM_LOCK.withLock {
    if (MEM_LOCK.holdCount > 1) return@withLock block()
    val dir = file.absoluteFile.parentFile
    if (dir != null && !dir.exists()) dir.mkdirs()
    val lockFile = File("${file.absolutePath}.lock")
    try {
      RandomAccessFile(lockFile, "rw").use { raf ->
        raf.channel.lock().use {
          return@withLock block()
        }
      }
    } catch (_: Exception) {
      // Fallback to in-process lock if filesystem lock cannot be opened
      return@withLock block()
    }
  }

  private fun writeAtomically(text: String) {
    val dir = file.absoluteFile.parentFile ?: throw FileNotFoundException(file.absolutePath)
    if (!dir.isDirectory && !dir.mkdirs()) throw IOException("Could not create ${dir.absolutePath}")
    val tmp = File(dir, "${file.name}.kt.${System.nanoTime()}.tmp")
    try {
      tmp.writeText(text)
      // the file holds private keys: owner-only, like the daemon's 0600
      tmp.setReadable(false, false); tmp.setReadable(true, true)
      tmp.setWritable(false, false); tmp.setWritable(true, true)
      tmp.setExecutable(false, false)
      if (!tmp.renameTo(file)) throw IOException("Could not replace ${file.absolutePath}")
    } finally {
      tmp.delete()
    }
  }

  companion object {
    const val FILE_NAME = "tinc.yaml"
    private val HOST_KEY_RE = Regex("^[A-Za-z][A-Za-z0-9_]*$")
    private val MEM_LOCK = ReentrantLock()
    private val EMPTY_FLOW_MAP_RE = Regex("^(\\s*(?:\"[^\"]*\"|'[^']*'|[^:#]+):)\\s*\\{\\s*\\}(\\s*(?:#.*)?)$")
    private val YAML_RESERVED_WORDS = setOf(
      "y", "n", "yes", "no", "true", "false", "on", "off", "null", "~"
    )

    private fun stripEmptyFlowMap(rawLines: MutableList<String>, idx: Int): Boolean {
      val m = EMPTY_FLOW_MAP_RE.matchEntire(rawLines[idx]) ?: return false
      rawLines[idx] = "${m.groupValues[1]}${m.groupValues[2]}"
      return true
    }

    private fun stripEmptyFlowMapLine(lines: MutableList<Line>, idx: Int) {
      val m = EMPTY_FLOW_MAP_RE.matchEntire(lines[idx].text) ?: return
      lines[idx] = Line("${m.groupValues[1]}${m.groupValues[2]}")
    }

    /**
     * Custom SnakeYAML resolver that keeps all non-empty scalars as verbatim Strings
     * (never mangling YAML 1.1 boolean node/network names like `no`, `yes`, `on`, `off`
     * into `Boolean`, nor turning `01:02` sexagesimals into integers), while still
     * resolving empty mapping bodies (`hosts:`) to `null`.
     */
    private class RawStringResolver : Resolver() {
      override fun addImplicitResolvers() {
        addImplicitResolver(Tag.NULL, EMPTY, null)
      }
    }

    internal fun newYaml(): Yaml {
      val loaderOpts = LoaderOptions().apply { isAllowDuplicateKeys = true }
      val dumperOpts = DumperOptions()
      return Yaml(
        SafeConstructor(loaderOpts),
        Representer(dumperOpts),
        dumperOpts,
        loaderOpts,
        RawStringResolver(),
      )
    }

    private fun isPlainScalarSafe(s: String): Boolean {
      if (s.isEmpty()) return false
      if (s.first().isWhitespace() || s.last().isWhitespace()) return false
      if (s.first() in "[]{}\"'|>#&*!%@`,?:-") {
        if (!(s.length >= 2 && s[0] == '-' && s[1].isDigit())) return false
      }
      for (c in s) {
        if (c.code < 0x20 || c.code == 0x7f || c == '"' || c == '\\') return false
      }
      if (s.contains(": ") || s.endsWith(":") || s.contains('#')) return false
      if (s.lowercase() in YAML_RESERVED_WORDS) return false
      return true
    }

    private fun isPlainKeySafe(k: String): Boolean =
      isPlainScalarSafe(k) && !k.contains(':')

    internal fun quoteDqScalar(s: String): String = buildString(s.length + 4) {
      append('"')
      for (c in s) {
        when (c) {
          '"' -> append("\\\"")
          '\\' -> append("\\\\")
          '\n' -> append("\\n")
          '\r' -> append("\\r")
          '\t' -> append("\\t")
          else -> if (c.code < 0x20 || c.code == 0x7f) {
            append(String.format("\\x%02x", c.code))
          } else {
            append(c)
          }
        }
      }
      append('"')
    }

    internal fun formatYamlScalar(s: String): String =
      if (isPlainScalarSafe(s)) s else quoteDqScalar(s)

    internal fun formatYamlKey(k: String): String =
      if (isPlainKeySafe(k)) k else quoteDqScalar(k)

    /**
     * Preserve daemon-learned TOFU keys (`Ed25519PublicKey`, `TlsFingerprint`) from
     * [diskHostText] when [newHostText] omits them because the daemon persisted them
     * concurrently while the user was editing.
     */
    internal fun mergeLearnedTofuKeys(newHostText: String, diskHostText: String?): String {
      if (diskHostText.isNullOrBlank() || newHostText.isBlank()) return newHostText
      val newKvs = parseHostKeyValues(newHostText)
      val diskKvs = parseHostKeyValues(diskHostText)
      val missing = LinkedHashMap<String, List<String>?>()
      for (tofuKey in listOf("Ed25519PublicKey", "TlsFingerprint")) {
        val hasInNew = newKvs.any { it.first.equals(tofuKey, ignoreCase = true) && it.second.isNotBlank() }
        if (!hasInNew) {
          val diskVals = diskKvs
            .filter { it.first.equals(tofuKey, ignoreCase = true) && it.second.isNotBlank() }
            .map { it.second }
          if (diskVals.isNotEmpty()) {
            missing[tofuKey] = diskVals
          }
        }
      }
      if (missing.isEmpty()) return newHostText
      val dummy = TincYaml(File("tinc.yaml"))
      return dummy.spliceHostMultiVars(newHostText, missing)
    }

    /** True if [trimmed] is a `Key = value` line (and not a base64 line with `=` padding). */
    fun isHostKeyValueLine(trimmed: String): Boolean {
      if (trimmed.startsWith("#") || trimmed.startsWith("-----") || !trimmed.contains('=')) return false
      val key = trimmed.substringBefore('=').trim()
      return HOST_KEY_RE.matches(key)
    }

    /** Parse `Key = value` pairs from a host record, ignoring comments and PEM blocks. */
    fun parseHostKeyValues(text: String): List<Pair<String, String>> {
      val out = mutableListOf<Pair<String, String>>()
      var inPem = false
      for (line in text.lineSequence()) {
        val trimmed = line.trim()
        if (trimmed.startsWith("-----BEGIN ")) inPem = true
        if (!inPem && isHostKeyValueLine(trimmed)) {
          out.add(trimmed.substringBefore('=').trim() to trimmed.substringAfter('=').trim())
        }
        if (trimmed.startsWith("-----END ")) inPem = false
      }
      return out
    }

    /**
     * Group `Key = value` lines from a host record by key (case-insensitive,
     * preserving the casing and file order of the first occurrence of each key).
     */
    fun parseHostMultiKeyValues(text: String): List<Pair<String, List<String>>> {
      val canonicalName = LinkedHashMap<String, String>()
      val grouped = LinkedHashMap<String, MutableList<String>>()
      for ((k, v) in parseHostKeyValues(text)) {
        val lower = k.lowercase()
        if (!canonicalName.containsKey(lower)) canonicalName[lower] = k
        grouped.getOrPut(lower) { mutableListOf() }.add(v)
      }
      return grouped.entries.map { (lower, vals) -> canonicalName[lower]!! to vals.toList() }
    }

    fun valuesOf(v: Any?): List<String> = when (v) {
      null -> emptyList()
      is List<*> -> v.mapNotNull { it?.let(::scalarToString) }
      else -> listOf(scalarToString(v))
    }

    private fun scalarToString(v: Any): String = when (v) {
      is Boolean -> if (v) "yes" else "no"
      else -> v.toString()
    }

    fun asTincBoolean(s: String?, default: Boolean): Boolean = when (s?.trim()?.lowercase()) {
      null, "" -> default
      "yes", "true", "on", "1" -> true
      "no", "false", "off", "0" -> false
      else -> throw InvalidConfigurationException("not a boolean: '$s'")
    }

    // ---- textual splice --------------------------------------------------

    private class Line(val text: String) {
      val indent = text.length - text.trimStart(' ').length
      val content = text.trimStart(' ')
      val skip = content.isEmpty() || content.startsWith("#") || content.isBlank()
      fun keyOrNull(): String? {
        if (skip || content.startsWith("-")) return null
        if (content.startsWith("\"")) {
          var i = 1
          val sb = StringBuilder()
          while (i < content.length) {
            val c = content[i]
            if (c == '\\' && i + 1 < content.length) {
              i++
              when (val esc = content[i]) {
                'n' -> sb.append('\n')
                't' -> sb.append('\t')
                'r' -> sb.append('\r')
                '"' -> sb.append('"')
                '\\' -> sb.append('\\')
                'x' -> if (i + 2 < content.length) {
                  val hex = content.substring(i + 1, i + 3).toIntOrNull(16)
                  if (hex != null) {
                    sb.append(hex.toChar())
                    i += 2
                  } else sb.append('x')
                } else sb.append('x')
                else -> sb.append(esc)
              }
              i++
            } else if (c == '"') {
              val rest = content.substring(i + 1).trimStart(' ', '\t')
              if (!rest.startsWith(":")) return null
              val after = rest.substring(1)
              if (after.isNotEmpty() && !after[0].isWhitespace()) return null
              return sb.toString()
            } else {
              sb.append(c)
              i++
            }
          }
          return null
        }
        if (content.startsWith("'")) {
          var i = 1
          val sb = StringBuilder()
          while (i < content.length) {
            val c = content[i]
            if (c == '\'' && i + 1 < content.length && content[i + 1] == '\'') {
              sb.append('\'')
              i += 2
            } else if (c == '\'') {
              val rest = content.substring(i + 1).trimStart(' ', '\t')
              if (!rest.startsWith(":")) return null
              val after = rest.substring(1)
              if (after.isNotEmpty() && !after[0].isWhitespace()) return null
              return sb.toString()
            } else {
              sb.append(c)
              i++
            }
          }
          return null
        }
        val colon = content.indexOf(':')
        if (colon <= 0) return null
        val after = content.substring(colon + 1)
        if (after.isNotEmpty() && !after[0].isWhitespace()) return null // e.g. "10.0.0.1:655" is not a key
        return content.substring(0, colon).trim()
      }
    }

    /** [start, end) of the block owned by the mapping entry at [keyIndex]: following lines more indented than it (or sequence items at the same indent). */
    private fun blockEnd(lines: List<Line>, keyIndex: Int): Int {
      val indent = lines[keyIndex].indent
      var i = keyIndex + 1
      while (i < lines.size && (lines[i].skip || lines[i].indent > indent ||
          (lines[i].indent == indent && (lines[i].content == "-" || lines[i].content.startsWith("- "))))) {
        i++
      }
      // give trailing blank/comment lines back to the parent
      while (i > keyIndex + 1 && lines[i - 1].skip) i--
      return i
    }

    /** Index of the child entry `key` inside the block (start, end) whose children sit at [childIndent], or -1. */
    private fun findChild(lines: List<Line>, start: Int, end: Int, childIndent: Int, key: String): Int {
      for (i in start until end) {
        val l = lines[i]
        if (l.skip || l.indent != childIndent) continue
        if (l.keyOrNull() == key) return i
      }
      return -1
    }

    private fun firstChildIndent(lines: List<Line>, start: Int, end: Int, default: Int): Int {
      for (i in start until end) if (!lines[i].skip) return lines[i].indent
      return default
    }

    private fun render(key: String, values: List<String>, indent: Int): List<String> {
      val pad = " ".repeat(indent)
      val formattedKey = formatYamlKey(key)
      val formattedVals = values.map { v ->
        val trimmed = v.trim()
        require(trimmed.isNotEmpty() && v.none { it == '\n' || it == '\r' || it == '\u0000' }) {
          "unrepresentable value for $key: '$v'"
        }
        formatYamlScalar(trimmed)
      }
      return if (formattedVals.size == 1) listOf("$pad$formattedKey: ${formattedVals[0]}")
      else listOf("$pad$formattedKey:") + formattedVals.map { "$pad  - $it" }
    }

    internal fun replaceHostBlockInText(docText: String, net: String, name: String, newText: String, sourceName: String = FILE_NAME): String {
      val rawLines = docText.split('\n').let { if (it.last().isEmpty()) it.dropLast(1) else it }.toMutableList()
      var parsed = rawLines.map(::Line)
      val netsIdx = findChild(parsed, 0, parsed.size, 0, "networks")
      require(netsIdx >= 0) { "no networks: section in $sourceName" }
      if (stripEmptyFlowMap(rawLines, netsIdx)) parsed = rawLines.map(::Line)
      val netsEnd = blockEnd(parsed, netsIdx)
      val netIndent = firstChildIndent(parsed, netsIdx + 1, netsEnd, 2)
      val netIdx = findChild(parsed, netsIdx + 1, netsEnd, netIndent, net)
      require(netIdx >= 0) { "no network '$net' in $sourceName" }
      if (stripEmptyFlowMap(rawLines, netIdx)) parsed = rawLines.map(::Line)
      var netEnd = blockEnd(parsed, netIdx)
      val sectionIndent = firstChildIndent(parsed, netIdx + 1, netEnd, netIndent + 2)
      var hostsIdx = findChild(parsed, netIdx + 1, netEnd, sectionIndent, "hosts")
      if (hostsIdx < 0) {
        val keysIdx = findChild(parsed, netIdx + 1, netEnd, sectionIndent, "keys")
        val insertHostsAt = if (keysIdx >= 0) keysIdx else netEnd
        rawLines.add(insertHostsAt, "${" ".repeat(sectionIndent)}hosts:")
        parsed = rawLines.map(::Line)
        netEnd = blockEnd(parsed, netIdx)
        hostsIdx = findChild(parsed, netIdx + 1, netEnd, sectionIndent, "hosts")
      } else if (stripEmptyFlowMap(rawLines, hostsIdx)) {
        parsed = rawLines.map(::Line)
      }
      val hostsEnd = blockEnd(parsed, hostsIdx)
      val hostIndent = firstChildIndent(parsed, hostsIdx + 1, hostsEnd, sectionIndent + 2)
      val hostIdx = findChild(parsed, hostsIdx + 1, hostsEnd, hostIndent, name)
      val formattedName = formatYamlKey(name)
      val safeCommentName = name.replace("\n", " ").replace("\r", " ")
      if (hostIdx >= 0) {
        val hostEnd = blockEnd(parsed, hostIdx)
        val blockIndent = parsed[hostIdx].indent
        val headerLine = "${" ".repeat(blockIndent)}$formattedName: |"
        val indentedBody = if (newText.trimEnd().isEmpty()) {
          listOf("${" ".repeat(blockIndent + 2)}# $safeCommentName")
        } else {
          newText.trimEnd().split('\n').map { if (it.isEmpty()) "" else " ".repeat(blockIndent + 2) + it }
        }
        val result = rawLines.subList(0, hostIdx) + listOf(headerLine) + indentedBody + rawLines.subList(hostEnd, rawLines.size)
        return result.joinToString("\n") + "\n"
      } else {
        val headerLine = "${" ".repeat(hostIndent)}$formattedName: |"
        val bodyLines = if (newText.trimEnd().isEmpty()) {
          listOf("${" ".repeat(hostIndent + 2)}# $safeCommentName")
        } else {
          newText.trimEnd().split('\n').map { if (it.isEmpty()) "" else " ".repeat(hostIndent + 2) + it }
        }
        val result = rawLines.subList(0, hostsEnd) + listOf(headerLine) + bodyLines + rawLines.subList(hostsEnd, rawLines.size)
        return result.joinToString("\n") + "\n"
      }
    }

    internal fun removeHostBlockInText(docText: String, net: String, name: String): String {
      if (docText.isEmpty()) return docText
      val rawLines = docText.split('\n').let { if (it.last().isEmpty()) it.dropLast(1) else it }
      val parsed = rawLines.map(::Line)
      val netsIdx = findChild(parsed, 0, parsed.size, 0, "networks")
      if (netsIdx < 0) return docText
      val netsEnd = blockEnd(parsed, netsIdx)
      val netIndent = firstChildIndent(parsed, netsIdx + 1, netsEnd, 2)
      val netIdx = findChild(parsed, netsIdx + 1, netsEnd, netIndent, net)
      if (netIdx < 0) return docText
      val netEnd = blockEnd(parsed, netIdx)
      val sectionIndent = firstChildIndent(parsed, netIdx + 1, netEnd, netIndent + 2)
      val hostsIdx = findChild(parsed, netIdx + 1, netEnd, sectionIndent, "hosts")
      if (hostsIdx < 0) return docText
      val hostsEnd = blockEnd(parsed, hostsIdx)
      val hostIndent = firstChildIndent(parsed, hostsIdx + 1, hostsEnd, sectionIndent + 2)
      val hostIdx = findChild(parsed, hostsIdx + 1, hostsEnd, hostIndent, name)
      if (hostIdx < 0) return docText
      val hostEnd = blockEnd(parsed, hostIdx)
      val result = rawLines.subList(0, hostIdx) + rawLines.subList(hostEnd, rawLines.size)
      return result.joinToString("\n") + "\n"
    }

    /** Pure function: the document text with `networks.<net>.options.<key>` entries replaced/removed/added. */
    internal fun splice(text: String, net: String, changes: Map<String, List<String>?>): String {
      val lines = text.split('\n').let { if (it.last().isEmpty()) it.dropLast(1) else it }.map(::Line).toMutableList()

      fun insert(at: Int, newLines: List<String>) {
        lines.addAll(at, newLines.map(::Line))
      }

      // networks:
      var netsIdx = findChild(lines, 0, lines.size, 0, "networks")
      if (netsIdx < 0) {
        insert(lines.size, listOf("networks:"))
        netsIdx = lines.size - 1
      } else {
        stripEmptyFlowMapLine(lines, netsIdx)
      }
      val netsEnd = blockEnd(lines, netsIdx)
      val netIndent = firstChildIndent(lines, netsIdx + 1, netsEnd, 2)

      // <net>:
      var netIdx = findChild(lines, netsIdx + 1, netsEnd, netIndent, net)
      if (netIdx < 0) {
        insert(netsEnd, listOf("${" ".repeat(netIndent)}${formatYamlKey(net)}:"))
        netIdx = netsEnd
      } else {
        stripEmptyFlowMapLine(lines, netIdx)
      }
      val netEnd = blockEnd(lines, netIdx)
      val sectionIndent = firstChildIndent(lines, netIdx + 1, netEnd, netIndent + 2)

      // options:
      var optIdx = findChild(lines, netIdx + 1, netEnd, sectionIndent, "options")
      if (optIdx < 0) {
        insert(netIdx + 1, listOf("${" ".repeat(sectionIndent)}options:"))
        optIdx = netIdx + 1
      } else {
        stripEmptyFlowMapLine(lines, optIdx)
      }
      var optEnd = blockEnd(lines, optIdx)
      val keyIndent = firstChildIndent(lines, optIdx + 1, optEnd, sectionIndent + 2)

      // remove every managed key (all occurrences), remembering where the first one stood
      var insertAt = -1
      for (key in changes.keys) {
        while (true) {
          val k = findChild(lines, optIdx + 1, optEnd, keyIndent, key)
          if (k < 0) break
          val end = blockEnd(lines, k)
          repeat(end - k) { lines.removeAt(k) }
          // a removal before the remembered spot moves it there; one after it leaves it untouched
          if (insertAt < 0 || k < insertAt) insertAt = k
          optEnd = blockEnd(lines, optIdx)
        }
      }
      if (insertAt < 0) insertAt = optEnd

      // (re)add the ones with values, in a stable order
      val added = changes.entries
        .filter { !it.value.isNullOrEmpty() }
        .flatMap { render(it.key, it.value!!, keyIndent) }
      insert(insertAt, added)

      return lines.joinToString("\n") { it.text } + "\n"
    }
  }
}
