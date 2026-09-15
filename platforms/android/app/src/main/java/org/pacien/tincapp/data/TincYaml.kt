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

import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException

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
  fun networks(): Map<String, Any?> {
    if (!file.exists()) return emptyMap()
    val root = try {
      newYaml().load<Any?>(file.readText())
    } catch (e: Exception) {
      throw InvalidConfigurationException("${file.name}: ${e.message}")
    }
    if (root == null) return emptyMap()
    if (root !is Map<*, *>) throw InvalidConfigurationException("${file.name}: top level is not a mapping")
    val networks = root["networks"] ?: return emptyMap()
    if (networks !is Map<*, *>) throw InvalidConfigurationException("${file.name}: 'networks' is not a mapping")
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

  /**
   * Host-file variable `key` of this network's own node (`hosts.<Name>`), all
   * occurrences, in file order.
   */
  fun ownHostValues(net: String, key: String): List<String> {
    val name = optionValue(net, "Name") ?: return emptyList()
    val text = hostText(net, name) ?: return emptyList()
    return text.lineSequence()
      .map { it.trim() }
      .filter { !it.startsWith("#") && it.contains('=') }
      .map { it.substringBefore('=').trim() to it.substringAfter('=').trim() }
      .filter { it.first.equals(key, ignoreCase = true) }
      .map { it.second }
      .toList()
  }

  /**
   * Set (or, with a null/empty list, remove) option keys of `networks.<net>`
   * and write the file back atomically. Only the named keys are touched; the
   * rest of the document is preserved verbatim. Missing `networks:` / `<net>:`
   * / `options:` scaffolding is created.
   */
  fun setOptions(net: String, changes: Map<String, List<String>?>) {
    if (changes.isEmpty()) return
    val original = if (file.exists()) file.readText() else ""
    val edited = splice(original, net, changes)
    if (edited != original) writeAtomically(edited)
  }

  /** Create the file with a minimal stanza (`Name` only); the daemon fills in the rest at first start. */
  fun createNetwork(net: String, nodeName: String) {
    if (file.exists()) throw IOException("${file.absolutePath} already exists")
    file.parentFile?.mkdirs()
    writeAtomically(splice("", net, mapOf("Name" to listOf(nodeName))))
  }

  private fun writeAtomically(text: String) {
    val dir = file.absoluteFile.parentFile ?: throw FileNotFoundException(file.absolutePath)
    if (!dir.isDirectory && !dir.mkdirs()) throw IOException("Could not create ${dir.absolutePath}")
    val tmp = File(dir, "${file.name}.${System.nanoTime()}.tmp")
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

    private fun newYaml() = Yaml(LoaderOptions().apply { isAllowDuplicateKeys = true })

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
        val colon = content.indexOf(':')
        if (colon <= 0) return null
        val after = content.substring(colon + 1)
        if (after.isNotEmpty() && !after[0].isWhitespace()) return null // e.g. "10.0.0.1:655" is not a key
        return content.substring(0, colon).trim().removeSurrounding("\"").removeSurrounding("'")
      }
    }

    /** [start, end) of the block owned by the mapping entry at [keyIndex]: following lines more indented than it. */
    private fun blockEnd(lines: List<Line>, keyIndex: Int): Int {
      val indent = lines[keyIndex].indent
      var i = keyIndex + 1
      while (i < lines.size && (lines[i].skip || lines[i].indent > indent)) i++
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
      values.forEach { v ->
        require(v.isNotBlank() && v.none { it == '\n' || it == '\r' } && !v.trim().startsWith("#")) { "unrepresentable value for $key: '$v'" }
      }
      return if (values.size == 1) listOf("$pad$key: ${values[0].trim()}")
      else listOf("$pad$key:") + values.map { "$pad  - ${it.trim()}" }
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
      }
      val netsEnd = blockEnd(lines, netsIdx)
      val netIndent = firstChildIndent(lines, netsIdx + 1, netsEnd, 2)

      // <net>:
      var netIdx = findChild(lines, netsIdx + 1, netsEnd, netIndent, net)
      if (netIdx < 0) {
        insert(netsEnd, listOf("${" ".repeat(netIndent)}$net:"))
        netIdx = netsEnd
      }
      val netEnd = blockEnd(lines, netIdx)
      val sectionIndent = firstChildIndent(lines, netIdx + 1, netEnd, netIndent + 2)

      // options:
      var optIdx = findChild(lines, netIdx + 1, netEnd, sectionIndent, "options")
      if (optIdx < 0) {
        insert(netIdx + 1, listOf("${" ".repeat(sectionIndent)}options:"))
        optIdx = netIdx + 1
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
